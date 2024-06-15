use core::{
    marker::PhantomData,
    ops::Index,
    sync::atomic::{AtomicU64, Ordering},
};

use bit_field::BitField;
use constants::new_physical_address::{supervisor::*, DYNAMIC, INPUT_FILE, OUTPUT};
use static_page_tables::{flags, StaticPageTable, StaticPd, StaticPdp, StaticPml4, StaticPt};
use x86_64::{
    structures::paging::{Page, PageSize, PageTableIndex, PhysFrame, Size1GiB, Size2MiB},
    PhysAddr, VirtAddr,
};

#[link_section = ".pagetables"]
#[export_name = "pml4"]
static PML4: StaticPml4 = {
    let mut page_table = StaticPageTable::new();
    page_table.set_table(0, &PDP_0, flags!(C | WRITE));
    page_table.set_table(64, &PDP_64, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table.set_table(128, &PDP_128, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table.set_recursive_table(511, &PML4, flags!(C));
    page_table
};

#[link_section = ".pagetables"]
static PDP_0: StaticPdp = {
    let mut page_table = StaticPageTable::new();
    page_table.set_table(1, &PD_0_1, flags!(C | WRITE));
    page_table.set_table(3, &PD_0_3, flags!(C | WRITE));
    page_table.set_page_range(64, INPUT_FILE, flags!(EXECUTE_DISABLE));
    page_table.set_page_range(128, INPUT_FILE, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table
};

#[link_section = ".pagetables"]
static PD_0_1: StaticPd = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page_range(0, TEXT, flags!(C));
    page_table.set_page_range(8, RODATA, flags!(C | EXECUTE_DISABLE));
    page_table.set_page_range(16, DATA, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table.set_page(25, STACK, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table.set_page(27, SECRETS, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table.set_page(29, SHADOW_STACK, flags!(C | EXECUTE_DISABLE | DIRTY));
    page_table.set_page(32, SHARED, flags!(WRITE | EXECUTE_DISABLE));
    page_table.set_table(34, &PT_0_1_34, flags!(EXECUTE_DISABLE));
    page_table
};

#[link_section = ".pagetables"]
static PT_0_1_34: StaticPt = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page(0, OUTPUT, flags!(C | EXECUTE_DISABLE));
    page_table
};

#[link_section = ".pagetables"]
static PD_0_3: StaticPd = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page(509, CPUID_PAGE, flags!(C | EXECUTE_DISABLE));
    page_table.set_page(510, PAGETABLES, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table.set_page(511, RESET_VECTOR, flags!(C));
    page_table
};

#[link_section = ".pagetables"]
static PDP_64: StaticPdp = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page_range(0, DYNAMIC, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table
};

#[link_section = ".pagetables"]
static PDP_128: StaticPdp = {
    let mut page_table = StaticPageTable::new();
    page_table.set_table(0, &PD_128_0, flags!(C | WRITE));
    page_table
};

#[link_section = ".pagetables"]
static PD_128_0: StaticPd = {
    let mut page_table = StaticPageTable::new();
    page_table.set_table(0, &PT_128_0_0, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table
};

#[link_section = ".pagetables"]
static PT_128_0_0: StaticPt = StaticPageTable::new();

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

/// Translate a reference to a physical address.
///
/// Returns an error if the memory is not contiguous or if the reference is zero sized.
pub fn ref_to_pa<T>(value: &T) -> Result<PhysAddr, TranslationError>
where
    T: ?Sized,
{
    unsafe { ptr_to_pa(value) }
}

/// Translate a pointer to a physical address.
///
/// Returns an error if the memory is not contiguous or if the reference is zero sized.
///
/// # Safety
///
/// The caller must ensure that the pointer points to mapped memory.
pub unsafe fn ptr_to_pa<T>(value: *const T) -> Result<PhysAddr, TranslationError>
where
    T: ?Sized,
{
    let size = core::mem::size_of_val_raw(value);
    let sizem1 = size.checked_sub(1).ok_or(TranslationError::ZeroSized)? as u64;

    let start_addr = VirtAddr::from_ptr(value);
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

/// Translate a page to a frame.
///
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
        const RECURSIVE_INDEX: PageTableIndex = PageTableIndex::new(511);

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
    fn table(&self) -> Option<&PageTable<Level3>> {
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

enum PageTableEntryContent<'a, L>
where
    L: HugePageLevel,
{
    Frame(PhysFrame<L::PageSize>),
    PageTable(&'a PageTable<L::NextLevel>),
}
