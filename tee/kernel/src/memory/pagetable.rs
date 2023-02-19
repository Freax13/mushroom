//! Concurrent page tables.

global_asm!(include_str!("pagetable.s"));

use crate::{
    error::{Error, Result},
    per_cpu::PerCpu,
};

use core::{
    arch::global_asm,
    iter::Step,
    marker::{PhantomData, PhantomPinned},
    ops::{Deref, Index, Range},
    sync::atomic::{AtomicU64, Ordering},
};

use bit_field::BitField;
use bitflags::bitflags;
use log::trace;
use spin::Lazy;
use x86_64::{
    instructions::tlb::Invlpgb,
    structures::paging::{FrameAllocator, Page, PageTableIndex, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};

const RECURSIVE_INDEX: PageTableIndex = PageTableIndex::new_truncate(511);

pub unsafe fn map_page(
    page: Page,
    frame: PhysFrame,
    flags: PageTableFlags,
    allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<()> {
    trace!("mapping page {page:?}->{frame:?} flags={flags:?}");

    let level4 = ActivePageTable::get();
    let level4_entry = &level4[page.p4_index()];

    let level3_guard = level4_entry.acquire(flags, allocator)?;
    let level3 = &*level3_guard;
    let level3_entry = &level3[page.p3_index()];

    let level2_guard = level3_entry.acquire(flags, allocator)?;
    let level2 = &*level2_guard;
    let level2_entry = &level2[page.p2_index()];

    let level1_guard = level2_entry.acquire(flags, allocator)?;
    let level1 = &*level1_guard;
    let level1_entry = &level1[page.p1_index()];

    unsafe {
        level1_entry.map(frame, flags);
    }

    Ok(())
}

pub unsafe fn unmap_page(page: Page, flags: PageTableFlags) -> PhysFrame {
    trace!("unmapping page {page:?}");

    let level4 = ActivePageTable::get();
    let level4_entry = &level4[page.p4_index()];

    let level3_guard = level4_entry.acquire_existing(flags).unwrap();
    let level3 = &*level3_guard;
    let level3_entry = &level3[page.p3_index()];

    let level2_guard = level3_entry.acquire_existing(flags).unwrap();
    let level2 = &*level2_guard;
    let level2_entry = &level2[page.p2_index()];

    let level1_guard = level2_entry.acquire_existing(flags).unwrap();
    let level1 = &*level1_guard;
    let level1_entry = &level1[page.p1_index()];

    unsafe { level1_entry.unmap() }
}

pub unsafe fn add_flags(page: Page, flags: PageTableFlags) -> Result<()> {
    let level4 = ActivePageTable::get();
    let level4_entry = &level4[page.p4_index()];

    let level3_guard = level4_entry.acquire_existing(flags).unwrap();
    let level3 = &*level3_guard;
    let level3_entry = &level3[page.p3_index()];

    let level2_guard = level3_entry.acquire_existing(flags).unwrap();
    let level2 = &*level2_guard;
    let level2_entry = &level2[page.p2_index()];

    let level1_guard = level2_entry.acquire_existing(flags).unwrap();
    let level1 = &*level1_guard;
    let level1_entry = &level1[page.p1_index()];

    unsafe {
        level1_entry.add_flags(flags);
    }

    Ok(())
}

/// # Panics
///
/// The page has to be mapped.
pub fn page_to_frame(page: Page, flags: PageTableFlags) -> Option<(PhysFrame, PageTableFlags)> {
    let pml4 = ActivePageTable::get();
    let pml4e = &pml4[page.p4_index()];
    let pdp = pml4e.acquire_existing(flags)?;
    let pdpe = &pdp[page.p3_index()];
    let pd = pdpe.acquire_existing(flags)?;
    let pde = &pd[page.p2_index()];
    let pt = pde.acquire_existing(flags)?;
    let pte = &pt[page.p1_index()];
    pte.frame()
}

struct Level4;

struct Level3;

struct Level2;

struct Level1;

/// A level that maps tables.
unsafe trait TableLevel {
    /// The next lower down level.
    type Next;

    const CAN_SET_GLOBAL: bool;
}

unsafe impl TableLevel for Level4 {
    type Next = Level3;

    const CAN_SET_GLOBAL: bool = false;
}

unsafe impl TableLevel for Level3 {
    type Next = Level2;

    const CAN_SET_GLOBAL: bool = true;
}

unsafe impl TableLevel for Level2 {
    type Next = Level1;

    const CAN_SET_GLOBAL: bool = true;
}

unsafe trait HasParentLevel {
    /// The previous upper level.
    type Prev: TableLevel;
}

unsafe impl HasParentLevel for Level3 {
    type Prev = Level4;
}

unsafe impl HasParentLevel for Level2 {
    type Prev = Level3;
}

unsafe impl HasParentLevel for Level1 {
    type Prev = Level2;
}

/// A page table.
///
/// This struct should never exist as an owned object, but always references
/// a currently active page table through the recursive page table index.
#[repr(C)]
struct ActivePageTable<L> {
    pub entries: [ActivePageTableEntry<L>; 512],
}

impl ActivePageTable<Level4> {
    fn get() -> &'static Self {
        let ptr = Page::from_page_table_indices(
            RECURSIVE_INDEX,
            RECURSIVE_INDEX,
            RECURSIVE_INDEX,
            RECURSIVE_INDEX,
        )
        .start_address()
        .as_ptr();
        unsafe {
            // SAFETY: We never construct a mutable reference.
            &*ptr
        }
    }
}

impl<L> Index<PageTableIndex> for ActivePageTable<L> {
    type Output = ActivePageTableEntry<L>;

    fn index(&self, index: PageTableIndex) -> &Self::Output {
        unsafe {
            // SAFETY: `PageTableIndex` guarantees that the values is less than 512.
            self.entries.get_unchecked(usize::from(index))
        }
    }
}

#[repr(transparent)]
struct ActivePageTableEntry<L> {
    entry: AtomicU64,
    _level: PhantomData<L>,
    _pin: PhantomPinned,
    /// A field to make sure that the entry is neither `Send` nor `Sync`.
    _not_send_sync: PhantomData<*const ()>,
}

impl<L> ActivePageTableEntry<L>
where
    L: HasParentLevel,
{
    pub fn parent_table_entry(&self) -> &ActivePageTableEntry<L::Prev> {
        let addr = VirtAddr::from_ptr(self);
        let p4_index = RECURSIVE_INDEX;
        let p3_index = addr.p4_index();
        let p2_index = addr.p3_index();
        let p1_index = addr.p2_index();
        let offset = u64::from(addr.p1_index()) << 3;
        let page = Page::from_page_table_indices(p4_index, p3_index, p2_index, p1_index);
        let addr = page.start_address() + offset;
        unsafe { &*addr.as_ptr() }
    }
}
impl ActivePageTableEntry<Level4> {
    pub fn acquire(
        &self,
        flags: PageTableFlags,
        allocator: &mut impl FrameAllocator<Size4KiB>,
    ) -> Result<ActivePageTableEntryGuard<'_, Level4>> {
        let mut storage = PerCpu::get().reserved_frame_storage.borrow_mut();
        let reserved_allocation = storage.allocate(allocator)?;
        self.acquire_reference_count(Some(reserved_allocation), flags)
            .unwrap();

        Ok(ActivePageTableEntryGuard { entry: self })
    }

    pub fn acquire_existing(
        &self,
        flags: PageTableFlags,
    ) -> Option<ActivePageTableEntryGuard<'_, Level4>> {
        self.acquire_reference_count(None, flags)?;
        Some(ActivePageTableEntryGuard { entry: self })
    }
}

impl<L> ActivePageTableEntry<L>
where
    L: HasParentLevel + TableLevel,
{
    pub fn acquire(
        &self,
        flags: PageTableFlags,
        allocator: &mut impl FrameAllocator<Size4KiB>,
    ) -> Result<ActivePageTableEntryGuard<'_, L>> {
        let mut storage = PerCpu::get().reserved_frame_storage.borrow_mut();
        let reserved_allocation = storage.allocate(allocator)?;
        let initialized = self
            .acquire_reference_count(Some(reserved_allocation), flags)
            .unwrap();

        if initialized {
            let parent_entry = self.parent_table_entry();
            parent_entry.acquire_reference_count(None, flags);
        }

        Ok(ActivePageTableEntryGuard { entry: self })
    }

    pub fn acquire_existing(
        &self,
        flags: PageTableFlags,
    ) -> Option<ActivePageTableEntryGuard<'_, L>> {
        self.acquire_reference_count(None, flags)?;
        Some(ActivePageTableEntryGuard { entry: self })
    }
}

impl<L> ActivePageTableEntry<L>
where
    L: TableLevel,
{
    /// Acquire a page table entry. This allocates a frame if the entry doesn't
    /// already contain one. Increases the reference count.
    ///
    /// Returns true if the entry was just initialized.
    fn acquire_reference_count(
        &self,
        reserved_allocation: Option<ReservedFrameAllocation>,
        flags: PageTableFlags,
    ) -> Option<bool> {
        let user = flags.contains(PageTableFlags::USER);
        let global = flags.contains(PageTableFlags::GLOBAL) & L::CAN_SET_GLOBAL;

        let mut current_entry = self.entry.load(Ordering::SeqCst);
        loop {
            // Check if the entry was already initialized.
            if current_entry.get_bit(PRESENT_BIT) {
                // Sanity check.
                // assert_eq!(user, current_entry.get_bit(USER_BIT));
                // assert_eq!(global, current_entry.get_bit(GLOBAL_BIT));

                // Increase the reference count.
                let current_reference_count = current_entry.get_bits(REFERENCE_COUNT_BITS);
                let new_reference_count = current_reference_count + 1;
                let mut new_entry = current_entry;
                new_entry.set_bits(REFERENCE_COUNT_BITS, new_reference_count);
                let res = self.entry.compare_exchange(
                    current_entry,
                    new_entry,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                match res {
                    Ok(_) => {
                        // We successfully updated the reference count.
                    }
                    Err(entry) => {
                        // Some other core modified the entry. Retry.
                        current_entry = entry;
                        continue;
                    }
                }

                // We're done.
                return Some(false);
            } else {
                // Start initializing the entry.

                // Check if we even can initialize the entry.
                if reserved_allocation.is_none() {
                    return None;
                }

                // Check if another core is already initializing the entry.
                if current_entry.get_bit(INITIALIZING_BIT) {
                    // There's nothing we can do, busy loop.
                    core::hint::spin_loop();
                    continue;
                }

                // Try to initialize the entry ourselves.

                // First, try to mark the entry as in progress of being initialized.
                let new_entry = 1 << INITIALIZING_BIT;
                let res = self.entry.compare_exchange(
                    current_entry,
                    new_entry,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                match res {
                    Ok(_) => {
                        // We've acquired to rights to initialize the entry.
                    }
                    Err(entry) => {
                        // Some other core did something to change the value. Retry.
                        current_entry = entry;
                        continue;
                    }
                }

                // Actually initialize the entry.
                let frame = reserved_allocation.unwrap().take();
                let mut new_entry = frame.start_address().as_u64();
                new_entry.set_bit(PRESENT_BIT, true);
                new_entry.set_bit(WRITE_BIT, true);
                new_entry.set_bit(USER_BIT, user);
                new_entry.set_bit(GLOBAL_BIT, global);
                new_entry.set_bit(INITIALIZING_BIT, true);
                new_entry.set_bits(REFERENCE_COUNT_BITS, 0);

                // Write the entry back.
                self.entry.store(new_entry, Ordering::SeqCst);

                // Zero out the page table.
                let table_ptr = self.as_table_ptr().cast_mut();
                unsafe {
                    core::ptr::write_bytes(table_ptr, 0, 1);
                }

                // Unset INITIALIZING_BIT.
                new_entry.set_bit(INITIALIZING_BIT, false);
                self.entry.store(new_entry, Ordering::SeqCst);

                // We're done.
                return Some(true);
            }
        }
    }

    /// Decrease the reference count and release the frame if it hits zero.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the entry is that `release` is only called
    /// after the `acquire` is no longer needed.
    unsafe fn release_reference_count(&self) -> Option<PhysFrame> {
        let mut current_entry = self.entry.load(Ordering::SeqCst);
        loop {
            // Try to decrease the reference count.
            let reference_count = current_entry.get_bits(REFERENCE_COUNT_BITS);
            let new_reference_count = reference_count.checked_sub(1);
            if let Some(new_reference_count) = new_reference_count {
                // Update the reference count.
                let mut new_entry = current_entry;
                new_entry.set_bits(REFERENCE_COUNT_BITS, new_reference_count);

                let res = self.entry.compare_exchange(
                    current_entry,
                    new_entry,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                match res {
                    Ok(_) => {
                        // Success!
                    }
                    Err(entry) => {
                        // Some other core modified the entry. Try again.
                        current_entry = entry;
                        continue;
                    }
                }

                // The reference count didn't hit zero. There's no frame to free.
                return None;
            } else {
                // The reference count hit zero. Zero out the entry and free
                // the frame.

                // First try to commit the zeroing.
                let res = self.entry.compare_exchange(
                    current_entry,
                    0,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                match res {
                    Ok(_) => {
                        // Success!
                    }
                    Err(entry) => {
                        // Some other core modified the entry. Try again.
                        current_entry = entry;
                        continue;
                    }
                }

                self.flush(true);

                // Extract the freed frame and return it.
                let phys_addr = PhysAddr::new_truncate(current_entry);
                let frame = PhysFrame::containing_address(phys_addr);
                return Some(frame);
            }
        }
    }

    fn as_table_ptr(&self) -> *const ActivePageTable<<L as TableLevel>::Next> {
        let entry_ptr = self as *const ActivePageTableEntry<L>;
        let entry_addr = entry_ptr as usize;
        let table_addr = entry_addr << 9;
        let table_ptr = table_addr as *const ActivePageTable<L::Next>;
        table_ptr
    }
}

impl<L> ActivePageTableEntry<L> {
    fn flush(&self, global: bool) {
        static INVLPGB: Lazy<Invlpgb> =
            Lazy::new(|| Invlpgb::new().expect("invlpgb not supported"));

        let flush = INVLPGB.build();
        let page = self.page();
        let next_page = Step::forward(page, 1);
        let flush = flush.pages(Page::range(page, next_page));
        let flush = if global {
            flush.include_global()
        } else {
            flush
        };
        flush.flush();

        INVLPGB.tlbsync();
    }

    pub fn page(&self) -> Page<Size4KiB> {
        let ptr = self as *const Self;
        let addr = ptr as u64;
        let addr = addr << 9;
        let addr = VirtAddr::new_truncate(addr);
        Page::from_start_address(addr).unwrap()
    }
}

impl ActivePageTableEntry<Level1> {
    /// # Panics
    ///
    /// Panics if the page is already mapped.
    ///
    /// # Safety
    ///
    /// `frame` must not already be mapped.
    pub unsafe fn map(&self, frame: PhysFrame, flags: PageTableFlags) {
        let mut new_entry = frame.start_address().as_u64();
        new_entry.set_bit(PRESENT_BIT, true);
        let writable = flags.contains(PageTableFlags::WRITABLE);
        new_entry.set_bit(WRITE_BIT, writable);
        new_entry.set_bit(USER_BIT, flags.contains(PageTableFlags::USER));
        new_entry.set_bit(GLOBAL_BIT, flags.contains(PageTableFlags::GLOBAL));
        new_entry.set_bit(
            DISABLE_EXECUTE_BIT,
            !flags.contains(PageTableFlags::EXECUTABLE),
        );
        let cow = flags.contains(PageTableFlags::COW);
        new_entry.set_bit(COW_BIT, cow);

        if cow {
            assert!(!writable);
        }

        let res = self
            .entry
            .compare_exchange(0, new_entry, Ordering::SeqCst, Ordering::SeqCst);
        res.expect("the page was already mapped");

        self.parent_table_entry()
            .acquire_reference_count(None, flags);
    }

    /// # Panics
    ///
    /// Panics if the page isn't mapped.
    ///
    /// # Safety
    ///
    /// `frame` must not already be mapped.
    pub unsafe fn unmap(&self) -> PhysFrame {
        let old_entry = self.entry.swap(0, Ordering::SeqCst);
        let present = old_entry.get_bit(PRESENT_BIT);
        let global = old_entry.get_bit(GLOBAL_BIT);
        let frame = PhysFrame::containing_address(PhysAddr::new_truncate(old_entry));

        assert!(present);

        self.flush(global);

        // FIXME: Free up the frame.
        let _maybe_frame = unsafe { self.parent_table_entry().release_reference_count() };

        frame
    }

    /// Panics if the page isn't mapped.
    ///
    /// # Safety
    ///
    /// `frame` must not already be mapped.
    pub unsafe fn add_flags(&self, flags: PageTableFlags) {
        let mut add_mask = 0;
        let mut remove_mask = 0;

        let writable = flags.contains(PageTableFlags::WRITABLE);
        add_mask.set_bit(WRITE_BIT, writable);
        add_mask.set_bit(USER_BIT, flags.contains(PageTableFlags::USER));
        let global = flags.contains(PageTableFlags::GLOBAL);
        add_mask.set_bit(GLOBAL_BIT, global);
        let cow = flags.contains(PageTableFlags::COW);
        add_mask.set_bit(COW_BIT, cow);
        remove_mask.set_bit(
            DISABLE_EXECUTE_BIT,
            flags.contains(PageTableFlags::EXECUTABLE),
        );

        if cow {
            assert!(!writable);
        }

        self.entry.fetch_or(add_mask, Ordering::SeqCst);
        self.entry.fetch_and(!remove_mask, Ordering::SeqCst);

        self.flush(global);
    }

    pub fn frame(&self) -> Option<(PhysFrame<Size4KiB>, PageTableFlags)> {
        let entry = self.entry.load(Ordering::SeqCst);
        if !entry.get_bit(PRESENT_BIT) {
            return None;
        }

        let frame = PhysFrame::containing_address(PhysAddr::new_truncate(entry));
        let mut flags = PageTableFlags::empty();
        flags.set(PageTableFlags::WRITABLE, entry.get_bit(WRITE_BIT));
        flags.set(
            PageTableFlags::EXECUTABLE,
            !entry.get_bit(DISABLE_EXECUTE_BIT),
        );
        flags.set(PageTableFlags::USER, entry.get_bit(USER_BIT));
        flags.set(PageTableFlags::GLOBAL, entry.get_bit(GLOBAL_BIT));
        flags.set(PageTableFlags::COW, entry.get_bit(COW_BIT));
        Some((frame, flags))
    }
}

struct ActivePageTableEntryGuard<'a, L>
where
    L: TableLevel,
{
    entry: &'a ActivePageTableEntry<L>,
}

impl<'a, L> Deref for ActivePageTableEntryGuard<'a, L>
where
    L: TableLevel,
{
    type Target = ActivePageTable<L::Next>;

    fn deref(&self) -> &Self::Target {
        let table_ptr = self.entry.as_table_ptr();
        unsafe { &*table_ptr }
    }
}

impl<'a, L> Drop for ActivePageTableEntryGuard<'a, L>
where
    L: TableLevel,
{
    fn drop(&mut self) {
        unsafe {
            // SAFETY: We're releasing the reference count acquired in
            // ActivePageTableEntry::acquire`.
            self.entry.release_reference_count();
        }
    }
}

const PRESENT_BIT: usize = 0;
const WRITE_BIT: usize = 1;
const USER_BIT: usize = 2;
const GLOBAL_BIT: usize = 8;
const DISABLE_EXECUTE_BIT: usize = 63;

/// Indicates that the page table is currently being initialized.
const INITIALIZING_BIT: usize = 9;

/// Indicates that the page is a copy on write page.
const COW_BIT: usize = 10;

/// Bits that are used to reference count the entry.
///
/// The reference count is represented as one less than the actual count. So if
/// the bits are 0, it's really 1. This increases the amount of possible values
/// by one.
///
/// The total capacity of the reference count is 1<<10 = 1024.
const REFERENCE_COUNT_BITS: Range<usize> = 52..62;

/// A type that buffers an allocation.
///
/// Sometimes we have operations that allocate rarely, but need the allocation
/// to happen fast. For those operations we buffer the allocation in a storage
/// and take the buffered allocation out of it in case we need it. If we don't
/// need it we preserved the allocation for the next time we do the operation.
pub struct ReservedFrameStorage {
    frame: Option<PhysFrame>,
}

impl ReservedFrameStorage {
    /// Create a new storage.
    pub const fn new() -> Self {
        Self { frame: None }
    }

    /// Create an allocation by either making a fresh allocation or reusing an
    /// existing one.
    pub fn allocate(
        &mut self,
        allocator: &mut (impl FrameAllocator<Size4KiB> + ?Sized),
    ) -> Result<ReservedFrameAllocation<'_>> {
        if self.frame.is_none() {
            // TODO: Use another allocator for this.
            let frame = allocator.allocate_frame().ok_or(Error::NoMem)?;
            self.frame = Some(frame);
        }

        Ok(ReservedFrameAllocation { storage: self })
    }
}

impl Drop for ReservedFrameStorage {
    fn drop(&mut self) {
        // (&BUMP_FRAME_ALLOCATOR).dea
    }
}

pub struct ReservedFrameAllocation<'a> {
    storage: &'a mut ReservedFrameStorage,
}

impl<'a> ReservedFrameAllocation<'a> {
    #[inline]
    fn take(self) -> PhysFrame {
        unsafe {
            // SAFETY: The existance of `ReservedFrameAllocation` proves that
            // there is a frame stored.
            self.storage.frame.take().unwrap_unchecked()
        }
    }
}

bitflags! {
    pub struct PageTableFlags: u8 {
        const WRITABLE = 1 << 0;
        const EXECUTABLE = 1 << 1;
        const USER = 1 << 2;
        const GLOBAL = 1 << 3;
        const COW = 1 << 4;
    }
}
