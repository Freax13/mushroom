use core::{
    cell::RefCell,
    marker::PhantomData,
    ops::Index,
    sync::atomic::{AtomicU64, Ordering},
};

use bit_field::BitField;
use snp_types::{ghcb::msr_protocol::PageOperation, VmplPermissions};
use x86_64::{
    structures::paging::{
        page::NotGiantPageSize, Page, PageSize, PageTableIndex, PhysFrame, Size1GiB, Size2MiB,
        Size4KiB,
    },
    PhysAddr, VirtAddr,
};

use crate::{
    cpuid::c_bit_location,
    dynamic::{pvalidate, pvalidate_2mib, rmpadjust, rmpadjust_2mib},
    ghcb, FakeSync,
};

/// A macro to get the physical address of a static variable.
#[macro_export]
macro_rules! pa_of {
    ($static:ident) => {{
        // Make sure that $static is indeed a static variable.
        // Make sure that it's a reference.
        const fn to_pointer<T>(r: &T) -> *const ::core::ffi::c_void {
            r as *const T as *const ::core::ffi::c_void
        }
        // Make sure that it's a static.
        static REFERENCE: $crate::FakeSync<*const ::core::ffi::c_void> =
            $crate::FakeSync::new(to_pointer(&$static));

        // Lookup the value once and cache it.
        static PA: $crate::FakeSync<::core::cell::LazyCell<::x86_64::PhysAddr>> =
            $crate::FakeSync::new(::core::cell::LazyCell::new(|| unsafe {
                $crate::pagetable::ptr_to_pa(*REFERENCE).unwrap()
            }));

        **PA
    }};
}

pub fn ref_to_pa<T>(value: &T) -> Result<PhysAddr, TranslationError>
where
    T: ?Sized,
{
    unsafe { ptr_to_pa(value) }
}

pub unsafe fn ptr_to_pa<T>(value: *const T) -> Result<PhysAddr, TranslationError>
where
    T: ?Sized,
{
    let size = core::mem::size_of_val_raw(value);
    let sizem1 = size.checked_sub(1).ok_or(TranslationError::ZeroSized)?;

    let start_addr = VirtAddr::from_ptr(value as *const T as *const u8);
    let end_addr = start_addr + sizem1;

    let start_page = Page::containing_address(start_addr);
    let end_page = Page::containing_address(end_addr);

    let frame = unsafe { page_to_frame(start_page) };

    for (page, i) in Page::range_inclusive(start_page, end_page).zip(0..).skip(1) {
        let f = unsafe { page_to_frame(page) };
        if f != frame + i {
            return Err(TranslationError::NotContigous);
        }
    }

    let offset_in_start_page = start_addr - start_page.start_address();
    Ok(frame.start_address() + offset_in_start_page)
}

/// # Safety
///
/// The page has to be mapped.
pub unsafe fn page_to_frame(page: Page) -> PhysFrame {
    let pml4 = PageTable::get();
    let pml4e = &pml4[page.p4_index()];
    let pdp = pml4e.table().unwrap_unchecked();
    let pdpe = &pdp[page.p3_index()];
    let pd = match pdpe.content().unwrap_unchecked() {
        PageTableEntryContent::Frame(frame) => {
            let offset_in_page = page.start_address()
                - Page::from_page_table_indices(
                    page.p4_index(),
                    page.p3_index(),
                    PageTableIndex::new(0),
                    PageTableIndex::new(0),
                )
                .start_address();
            let addr = frame.start_address() + offset_in_page;
            return PhysFrame::containing_address(addr);
        }
        PageTableEntryContent::PageTable(pd) => pd,
    };
    let pde = &pd[page.p2_index()];
    let pt = match pde.content().unwrap_unchecked() {
        PageTableEntryContent::Frame(frame) => {
            let offset_in_page = page.start_address()
                - Page::from_page_table_indices(
                    page.p4_index(),
                    page.p3_index(),
                    page.p2_index(),
                    PageTableIndex::new(0),
                )
                .start_address();
            let addr = frame.start_address() + offset_in_page;
            return PhysFrame::containing_address(addr);
        }
        PageTableEntryContent::PageTable(pt) => pt,
    };
    let pte = &pt[page.p1_index()];
    pte.frame().unwrap_unchecked()
}

#[derive(Debug)]
pub enum TranslationError {
    NotContigous,
    ZeroSized,
}

struct Level4;

struct Level3;

struct Level2;

struct Level1;

trait HugePageLevel {
    type NextLevel;
    type PageSize: PageSize;
}

impl HugePageLevel for Level3 {
    type NextLevel = Level2;
    type PageSize = Size1GiB;
}

impl HugePageLevel for Level2 {
    type NextLevel = Level1;
    type PageSize = Size2MiB;
}

#[repr(transparent)]
struct PageTable<L> {
    entries: [PageTableEntry<L>; 512],
}

impl PageTable<Level4> {
    pub fn get() -> &'static Self {
        const RECURSIVE_INDEX: PageTableIndex = PageTableIndex::new_truncate(511);

        let addr = Page::from_page_table_indices(
            RECURSIVE_INDEX,
            RECURSIVE_INDEX,
            RECURSIVE_INDEX,
            RECURSIVE_INDEX,
        );

        unsafe { &*addr.start_address().as_ptr() }
    }
}

impl<L> Index<PageTableIndex> for PageTable<L> {
    type Output = PageTableEntry<L>;

    fn index(&self, index: PageTableIndex) -> &Self::Output {
        &self.entries[usize::from(index)]
    }
}

#[repr(transparent)]
struct PageTableEntry<L> {
    value: AtomicU64,
    _level: PhantomData<L>,
}

impl<L> PageTableEntry<L> {
    pub fn present(&self) -> bool {
        self.value.load(Ordering::SeqCst).get_bit(0)
    }
}

impl<L> PageTableEntry<L>
where
    L: HugePageLevel,
{
    pub fn is_huge_page(&self) -> bool {
        self.value.load(Ordering::SeqCst).get_bit(7)
    }
}

impl PageTableEntry<Level4> {
    pub fn table(&self) -> Option<&PageTable<Level3>> {
        if !self.present() {
            return None;
        }

        let addr = VirtAddr::from_ptr(self);
        let addr = addr.as_u64();
        let table_addr = addr.wrapping_shl(9);
        let table_addr = VirtAddr::new_truncate(table_addr);
        let table = unsafe { &*table_addr.as_ptr() };
        Some(table)
    }
}

impl<L> PageTableEntry<L>
where
    L: HugePageLevel,
{
    pub fn content(&self) -> Option<PageTableEntryContent<L>> {
        if !self.present() {
            return None;
        }

        if self.is_huge_page() {
            let frame = PhysFrame::containing_address(PhysAddr::new_truncate(
                self.value.load(Ordering::SeqCst),
            ));
            Some(PageTableEntryContent::Frame(frame))
        } else {
            let addr = VirtAddr::from_ptr(self);
            let addr = addr.as_u64();
            let table_addr = addr.wrapping_shl(9);
            let table_addr = VirtAddr::new_truncate(table_addr);
            let table = unsafe { &*table_addr.as_ptr() };
            Some(PageTableEntryContent::PageTable(table))
        }
    }
}

impl PageTableEntry<Level1> {
    pub fn frame(&self) -> Option<PhysFrame> {
        if !self.present() {
            return None;
        }

        let frame = PhysFrame::containing_address(PhysAddr::new_truncate(
            self.value.load(Ordering::SeqCst),
        ));
        Some(frame)
    }
}

impl PageTableEntry<Level2> {
    pub unsafe fn create_temporary_mapping(&self, addr: PhysFrame<Size2MiB>) {
        self.value.store(
            addr.start_address().as_u64() | 1 | (1 << 7) | (1 << c_bit_location()),
            Ordering::SeqCst,
        );
    }
}

impl PageTableEntry<Level1> {
    pub unsafe fn create_temporary_mapping(&self, addr: PhysFrame<Size4KiB>, private: bool) {
        self.value.store(
            addr.start_address().as_u64() | 1 | (1 << 7) | (u64::from(private) << c_bit_location()),
            Ordering::SeqCst,
        );
    }
}

enum PageTableEntryContent<'a, L>
where
    L: HugePageLevel,
{
    Frame(PhysFrame<L::PageSize>),
    PageTable(&'a PageTable<L::NextLevel>),
}

pub static TEMPORARY_MAPPER: FakeSync<RefCell<TemporaryMapper>> =
    FakeSync::new(RefCell::new(TemporaryMapper(())));

pub struct TemporaryMapper(());

impl TemporaryMapper {
    pub fn create_temporary_mapping_4kib(
        &mut self,
        frame: PhysFrame<Size4KiB>,
        private: bool,
    ) -> TemporaryMapping<Size4KiB> {
        let page = Page::from_start_address(VirtAddr::new(0x400000000000)).unwrap();

        let pml4 = PageTable::get();
        let pml4e = &pml4[page.p4_index()];
        let pdp = pml4e.table().unwrap();
        let pdpe = &pdp[page.p3_index()];
        let pd = match pdpe.content().unwrap() {
            PageTableEntryContent::Frame(_) => unreachable!(),
            PageTableEntryContent::PageTable(pd) => pd,
        };
        let pde = &pd[page.p2_index()];
        let pt = match pde.content().unwrap() {
            PageTableEntryContent::Frame(_) => unreachable!(),
            PageTableEntryContent::PageTable(pt) => pt,
        };
        let pte = &pt[page.p1_index()];
        unsafe {
            pte.create_temporary_mapping(frame, private);
        }

        x86_64::instructions::tlb::flush_all();

        TemporaryMapping {
            mapper: self,
            frame,
            page,
        }
    }

    pub fn create_temporary_mapping_2mib(
        &mut self,
        frame: PhysFrame<Size2MiB>,
    ) -> TemporaryMapping<Size2MiB> {
        let page = Page::from_start_address(VirtAddr::new(0x400000200000)).unwrap();

        let pml4 = PageTable::get();
        let pml4e = &pml4[page.p4_index()];
        let pdp = pml4e.table().unwrap();
        let pdpe = &pdp[page.p3_index()];
        let pd = match pdpe.content().unwrap() {
            PageTableEntryContent::Frame(_) => unreachable!(),
            PageTableEntryContent::PageTable(pd) => pd,
        };
        let pde = &pd[page.p2_index()];
        unsafe {
            pde.create_temporary_mapping(frame);
        }

        x86_64::instructions::tlb::flush_all();

        TemporaryMapping {
            mapper: self,
            frame,
            page,
        }
    }
}

pub struct TemporaryMapping<'a, S>
where
    S: NotGiantPageSize,
{
    mapper: &'a mut TemporaryMapper,
    frame: PhysFrame<S>,
    page: Page<S>,
}

impl TemporaryMapping<'_, Size4KiB> {
    pub unsafe fn convert_to_private_in_place(&mut self) -> &[u8; 4096] {
        // Copy to content out of the page.
        let mut content = [0u8; 0x1000];
        unsafe {
            core::intrinsics::volatile_copy_nonoverlapping_memory(
                &mut content,
                self.page.start_address().as_ptr(),
                1,
            );
        }

        // Tell the Hypervisor that we want to change the page to private.
        ghcb::page_state_change(self.frame, PageOperation::PageAssignmentPrivate);

        self.mapper.create_temporary_mapping_4kib(self.frame, true);

        // Convert the page to private.
        pvalidate(self.page, true).unwrap();

        // Adjust the permissions for VMPL 1.
        rmpadjust(self.page, 1, VmplPermissions::READ, true).unwrap();

        // Copy the content back in.
        unsafe {
            core::intrinsics::volatile_copy_nonoverlapping_memory(
                self.page.start_address().as_mut_ptr(),
                &content,
                1,
            );
        }

        unsafe { &*self.page.start_address().as_ptr() }
    }

    /// Copy memory from the mapping into a buffer.
    pub fn read(&self, out: &mut [u8]) {
        assert!(out.len() <= 4096);
        unsafe {
            core::intrinsics::volatile_copy_nonoverlapping_memory(
                out.as_mut_ptr(),
                self.page.start_address().as_ptr(),
                out.len(),
            );
        }
    }
}

impl TemporaryMapping<'_, Size2MiB> {
    pub unsafe fn rmpadjust(&self, target_vmpl: u8, target_perm_mask: VmplPermissions, vmsa: bool) {
        rmpadjust_2mib(self.page, target_vmpl, target_perm_mask, vmsa);
    }

    pub unsafe fn pvalidate(&self, valid: bool) {
        pvalidate_2mib(self.page, valid);

        if valid {
            // Zero out the memory.
            core::ptr::write_bytes(
                self.page.start_address().as_mut_ptr::<u8>(),
                0,
                512 * 0x1000,
            );
        }
    }
}
