//! Concurrent page tables.

global_asm!(include_str!("pagetable.s"));

use crate::{
    error::{Error, Result},
    per_cpu::PerCpu,
    user::process::memory::without_write_protect,
};

use core::{
    arch::{asm, global_asm},
    fmt,
    iter::Step,
    marker::{PhantomData, PhantomPinned},
    num::NonZeroU64,
    ops::{Deref, Index, Range},
    sync::atomic::{AtomicU64, Ordering},
};

use bit_field::BitField;
use bitflags::bitflags;
use log::trace;
use spin::Lazy;
use x86_64::{
    instructions::tlb::Invlpgb,
    registers::control::Cr3,
    structures::paging::{
        FrameAllocator, FrameDeallocator, Page, PageTableIndex, PhysFrame, Size4KiB,
    },
    PhysAddr, VirtAddr,
};

use super::{frame::FRAME_ALLOCATOR, temporary::copy_into_frame};

const RECURSIVE_INDEX: PageTableIndex = PageTableIndex::new_truncate(510);

static INIT_KERNEL_PML4ES: Lazy<()> = Lazy::new(|| {
    let pml4 = ActivePageTable::get();
    for pml4e in pml4.entries[256..].iter() {
        let mut storage = PerCpu::get().reserved_frame_storage.borrow_mut();
        let reserved_allocation = storage
            .allocate(&mut &FRAME_ALLOCATOR)
            .expect("failed to allocate memory for kernel pml4e");
        pml4e.acquire_reference_count(reserved_allocation, PageTableFlags::GLOBAL);
    }
});

pub fn allocate_pml4() -> Result<PhysFrame> {
    // Make sure that all pml4 kernel entries are initialized.
    Lazy::force(&INIT_KERNEL_PML4ES);

    // Allocate a frame for the new pml4.
    let frame = (&FRAME_ALLOCATOR)
        .allocate_frame()
        .ok_or(Error::no_mem(()))?;

    // Copy the kernel entries into a temporary buffer.
    let pml4 = ActivePageTable::get();
    let mut entries = [0u64; 512];
    unsafe {
        core::ptr::copy_nonoverlapping(
            pml4.entries[256..].as_ptr().cast(),
            entries[256..].as_mut_ptr(),
            256,
        );
    }
    // Fix the recursive entry.
    entries[usize::from(RECURSIVE_INDEX)] =
        PresentPageTableEntry::new(frame, PageTableFlags::WRITABLE)
            .0
            .get();

    // Copy the buffer into the pml4.
    unsafe {
        copy_into_frame(frame, bytemuck::cast_mut(&mut entries))?;
    }

    Ok(frame)
}

pub unsafe fn map_page(
    page: Page,
    entry: PresentPageTableEntry,
    allocator: &mut (impl FrameAllocator<Size4KiB> + FrameDeallocator<Size4KiB>),
) -> Result<()> {
    trace!(
        "mapping page {page:?}->{entry:?} pml4={:?}",
        Cr3::read_pcid().0
    );

    let level4 = ActivePageTable::get();
    let level4_entry = &level4[page.p4_index()];

    let level3_guard = level4_entry.acquire(entry.flags(), allocator)?;
    let level3 = &*level3_guard;
    let level3_entry = &level3[page.p3_index()];

    let level2_guard = level3_entry.acquire(entry.flags(), allocator)?;
    let level2 = &*level2_guard;
    let level2_entry = &level2[page.p2_index()];

    let level1_guard = level2_entry.acquire(entry.flags(), allocator)?;
    let level1 = &*level1_guard;
    let level1_entry = &level1[page.p1_index()];

    unsafe {
        level1_entry.map(entry);
    }

    Ok(())
}

/// Atomically switch out a page table entry for another.
///
/// # Panics
///
/// Panics if the page isn't mapped.
///
/// # Safety
///
/// It has to be safe that stale TLB entries exist for a brief time.
pub unsafe fn remap_page(
    page: Page,
    old_entry: PresentPageTableEntry,
    new_entry: PresentPageTableEntry,
) -> Result<(), PresentPageTableEntry> {
    trace!("remapping page {page:?}");

    let level4 = ActivePageTable::get();
    let level4_entry = &level4[page.p4_index()];

    let level3_guard = level4_entry.acquire_existing().unwrap();
    let level3 = &*level3_guard;
    let level3_entry = &level3[page.p3_index()];

    let level2_guard = level3_entry.acquire_existing().unwrap();
    let level2 = &*level2_guard;
    let level2_entry = &level2[page.p2_index()];

    let level1_guard = level2_entry.acquire_existing().unwrap();
    let level1 = &*level1_guard;
    let level1_entry = &level1[page.p1_index()];

    unsafe { level1_entry.remap(old_entry, new_entry) }
}

pub unsafe fn unmap_page(page: Page) -> PresentPageTableEntry {
    trace!("unmapping page {page:?}");

    let level4 = ActivePageTable::get();
    let level4_entry = &level4[page.p4_index()];

    let level3_guard = level4_entry.acquire_existing().unwrap();
    let level3 = &*level3_guard;
    let level3_entry = &level3[page.p3_index()];

    let level2_guard = level3_entry.acquire_existing().unwrap();
    let level2 = &*level2_guard;
    let level2_entry = &level2[page.p2_index()];

    let level1_guard = level2_entry.acquire_existing().unwrap();
    let level1 = &*level1_guard;
    let level1_entry = &level1[page.p1_index()];

    unsafe { level1_entry.unmap() }
}

pub unsafe fn add_flags(page: Page, flags: PageTableFlags) {
    let level4 = ActivePageTable::get();
    let level4_entry = &level4[page.p4_index()];

    let level3_guard = level4_entry.acquire_existing().unwrap();
    let level3 = &*level3_guard;
    let level3_entry = &level3[page.p3_index()];

    let level2_guard = level3_entry.acquire_existing().unwrap();
    let level2 = &*level2_guard;
    let level2_entry = &level2[page.p2_index()];

    let level1_guard = level2_entry.acquire_existing().unwrap();
    let level1 = &*level1_guard;
    let level1_entry = &level1[page.p1_index()];

    unsafe {
        level1_entry.add_flags(flags);
    }
}

pub unsafe fn remove_flags(page: Page, flags: PageTableFlags) {
    let level4 = ActivePageTable::get();
    let level4_entry = &level4[page.p4_index()];

    let Some(level3_guard) = level4_entry.acquire_existing() else {
        return;
    };
    let level3 = &*level3_guard;
    let level3_entry = &level3[page.p3_index()];

    let Some(level2_guard) = level3_entry.acquire_existing() else {
        return;
    };
    let level2 = &*level2_guard;
    let level2_entry = &level2[page.p2_index()];

    let Some(level1_guard) = level2_entry.acquire_existing() else {
        return;
    };
    let level1 = &*level1_guard;
    let level1_entry = &level1[page.p1_index()];

    unsafe {
        level1_entry.remove_flags(flags);
    }
}

pub fn entry_for_page(page: Page) -> Option<PresentPageTableEntry> {
    let pml4 = ActivePageTable::get();
    let pml4e = &pml4[page.p4_index()];
    let pdp = pml4e.acquire_existing()?;
    let pdpe = &pdp[page.p3_index()];
    let pd = pdpe.acquire_existing()?;
    let pde = &pd[page.p2_index()];
    let pt = pde.acquire_existing()?;
    let pte = &pt[page.p1_index()];
    pte.entry()
}

/// Call the closure for all dirty userspace pages.
///
/// # Safety
///
/// The caller must ensure that the closure doesn't modify the active page table.
pub unsafe fn find_dirty_userspace_pages(mut f: impl FnMut(Page) -> Result<()>) -> Result<()> {
    freeze_userspace(|| {
        let pml4 = ActivePageTable::get();

        for p4_index in (0..256).map(PageTableIndex::new) {
            let pml4e = &pml4[p4_index];
            let Some(pdp) = pml4e.acquire_existing() else {
                continue;
            };

            for p3_index in (0..512).map(PageTableIndex::new) {
                let pdpe = &pdp[p3_index];
                let Some(pd) = pdpe.acquire_existing() else {
                    continue;
                };

                for p2_index in (0..512).map(PageTableIndex::new) {
                    let pde = &pd[p2_index];
                    let Some(pt) = pde.acquire_existing() else {
                        continue;
                    };

                    for p1_index in (0..512).map(PageTableIndex::new) {
                        let pte = &pt[p1_index];
                        if !pte.is_dirty() {
                            continue;
                        }

                        let page = pte.page();

                        f(page)?;
                    }
                }
            }
        }

        Ok(())
    })
}

/// Prevent userspace from modifying memory during the runtime of the closure.
fn freeze_userspace<R>(f: impl FnOnce() -> R) -> R {
    let pml4 = ActivePageTable::get();

    for p4_index in (0..256).map(PageTableIndex::new) {
        let pml4e = &pml4[p4_index];
        pml4e.freeze(true);
    }

    flush_current_pcid();

    let res = without_write_protect(f);

    for p4_index in (0..256).map(PageTableIndex::new) {
        let pml4e = &pml4[p4_index];
        pml4e.freeze(false);
    }

    res
}

fn flush_current_pcid() {
    static INVLPGB: Lazy<Invlpgb> = Lazy::new(|| Invlpgb::new().expect("invlpgb not supported"));

    let (_, pcid) = Cr3::read_pcid();
    unsafe {
        INVLPGB.build().pcid(pcid).flush();
    }

    INVLPGB.tlbsync();
}

struct Level4;

struct Level3;

struct Level2;

struct Level1;

/// A level that maps tables.
///
/// # Safety
///
/// This trait must only be implemented for page table levels.
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

/// A level that has a parent level.
///
/// # Safety
///
/// This trait must only be implemented for page table levels.
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
        allocator: &mut (impl FrameAllocator<Size4KiB> + FrameDeallocator<Size4KiB>),
    ) -> Result<ActivePageTableEntryGuard<'_, Level4>> {
        if let Ok(mut storage) = PerCpu::get().reserved_frame_storage.try_borrow_mut() {
            let reserved_allocation = storage.allocate(allocator)?;
            self.acquire_reference_count(reserved_allocation, flags)
                .unwrap();
        } else {
            let mut storage = ReservedFrameStorage::new();
            let reserved_allocation = storage.allocate(allocator)?;
            self.acquire_reference_count(reserved_allocation, flags)
                .unwrap();
            storage.release(allocator);
        }

        Ok(ActivePageTableEntryGuard { entry: self })
    }

    pub fn acquire_existing(&self) -> Option<ActivePageTableEntryGuard<'_, Level4>> {
        self.increase_reference_count().ok()?;
        Some(ActivePageTableEntryGuard { entry: self })
    }

    pub fn freeze(&self, frozen: bool) {
        let mut entry = atomic_load(&self.entry);
        while entry.get_bit(PRESENT_BIT) {
            assert_eq!(entry.get_bit(WRITE_BIT), frozen);

            let mut new_entry = entry;
            new_entry.set_bit(WRITE_BIT, !frozen);

            let res = atomic_compare_exchange(&self.entry, entry, new_entry);
            match res {
                Ok(_) => break,
                Err(new_entry) => entry = new_entry,
            }
        }
    }
}

impl<L> ActivePageTableEntry<L>
where
    L: HasParentLevel + TableLevel,
{
    pub fn acquire(
        &self,
        flags: PageTableFlags,
        allocator: &mut (impl FrameAllocator<Size4KiB> + FrameDeallocator<Size4KiB>),
    ) -> Result<ActivePageTableEntryGuard<'_, L>> {
        let initialized =
            if let Ok(mut storage) = PerCpu::get().reserved_frame_storage.try_borrow_mut() {
                let reserved_allocation = storage.allocate(allocator)?;
                self.acquire_reference_count(reserved_allocation, flags)
                    .unwrap()
            } else {
                let mut storage = ReservedFrameStorage::new();
                let reserved_allocation = storage.allocate(allocator)?;
                let res = self
                    .acquire_reference_count(reserved_allocation, flags)
                    .unwrap();
                storage.release(allocator);
                res
            };

        if initialized {
            let parent_entry = self.parent_table_entry();
            parent_entry.increase_reference_count().unwrap();
        }

        Ok(ActivePageTableEntryGuard { entry: self })
    }

    pub fn acquire_existing(&self) -> Option<ActivePageTableEntryGuard<'_, L>> {
        self.increase_reference_count().ok()?;
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
        reserved_allocation: ReservedFrameAllocation,
        flags: PageTableFlags,
    ) -> Option<bool> {
        let user = flags.contains(PageTableFlags::USER);
        let global = flags.contains(PageTableFlags::GLOBAL) & L::CAN_SET_GLOBAL;

        let mut current_entry = atomic_load(&self.entry);
        loop {
            // If the entry is being initialized right now, spin.
            if current_entry.get_bit(INITIALIZING_BIT) {
                core::hint::spin_loop();
                current_entry = atomic_load(&self.entry);
                continue;
            }

            // Check if the entry was already initialized.
            if current_entry.get_bit(PRESENT_BIT) {
                // Sanity check.
                assert_eq!(user, current_entry.get_bit(USER_BIT));
                assert_eq!(global, current_entry.get_bit(GLOBAL_BIT));

                // Increase the reference count.
                let current_reference_count = current_entry.get_bits(REFERENCE_COUNT_BITS);
                let new_reference_count = current_reference_count + 1;
                let mut new_entry = current_entry;
                new_entry.set_bits(REFERENCE_COUNT_BITS, new_reference_count);
                let res = atomic_compare_exchange(&self.entry, current_entry, new_entry);
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

                // Try to initialize the entry ourselves.

                // First, try to mark the entry as in progress of being initialized.
                let new_entry = 1 << INITIALIZING_BIT;
                let res = atomic_compare_exchange(&self.entry, current_entry, new_entry);
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
                let frame = reserved_allocation.take();
                let mut new_entry = frame.start_address().as_u64();
                new_entry.set_bit(PRESENT_BIT, true);
                new_entry.set_bit(WRITE_BIT, true);
                new_entry.set_bit(USER_BIT, user);
                new_entry.set_bit(GLOBAL_BIT, global);
                new_entry.set_bit(INITIALIZING_BIT, true);
                new_entry.set_bits(REFERENCE_COUNT_BITS, 0);

                // Write the entry back.
                atomic_store(&self.entry, new_entry);

                // Zero out the page table.
                let table_ptr = self.as_table_ptr().cast_mut();
                unsafe {
                    core::ptr::write_bytes(table_ptr, 0, 1);
                }

                // Unset INITIALIZING_BIT.
                new_entry.set_bit(INITIALIZING_BIT, false);
                atomic_store(&self.entry, new_entry);

                // We're done.
                return Some(true);
            }
        }
    }

    /// Increases the reference count. Returns `Ok(())` if there reference count
    /// was increased, returns `Err(())` if the page table didn't exist.
    fn increase_reference_count(&self) -> Result<(), ()> {
        let mut current_entry = atomic_load(&self.entry);
        loop {
            // If the entry is being initialized right now, spin.
            if current_entry.get_bit(INITIALIZING_BIT) {
                core::hint::spin_loop();
                current_entry = atomic_load(&self.entry);
                continue;
            }

            // Verify that the entry was already initialized.
            if !current_entry.get_bit(PRESENT_BIT) {
                return Err(());
            }

            // Increase the reference count.
            let current_reference_count = current_entry.get_bits(REFERENCE_COUNT_BITS);
            let new_reference_count = current_reference_count + 1;
            let mut new_entry = current_entry;
            new_entry.set_bits(REFERENCE_COUNT_BITS, new_reference_count);
            let res = atomic_compare_exchange(&self.entry, current_entry, new_entry);
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
            return Ok(());
        }
    }

    /// Decrease the reference count and release the frame if it hits zero.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the entry is that `release` is only called
    /// after the `acquire` is no longer needed.
    unsafe fn release_reference_count(&self) -> Option<PhysFrame> {
        let mut current_entry = atomic_load(&self.entry);
        loop {
            // Sanity check that the entry is not already unmapped.
            debug_assert_ne!(current_entry, 0, "{:?} isn't mapped", self.page());

            // Try to decrease the reference count.
            let reference_count = current_entry.get_bits(REFERENCE_COUNT_BITS);
            let new_reference_count = reference_count.checked_sub(1);
            if let Some(new_reference_count) = new_reference_count {
                // Update the reference count.
                let mut new_entry = current_entry;
                new_entry.set_bits(REFERENCE_COUNT_BITS, new_reference_count);

                let res = atomic_compare_exchange(&self.entry, current_entry, new_entry);
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
                let res = atomic_compare_exchange(&self.entry, current_entry, 0);
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
        let addr = VirtAddr::from_ptr(self);
        let p4_index = addr.p3_index();
        let p3_index = addr.p2_index();
        let p2_index = addr.p1_index();
        let p1_index = PageTableIndex::new_truncate(u16::from(addr.page_offset()) >> 3);
        let page = Page::from_page_table_indices(p4_index, p3_index, p2_index, p1_index);
        let addr = page.start_address();
        unsafe { &*addr.as_ptr() }
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
        let addr = VirtAddr::from_ptr(self);
        let p4_index = addr.p3_index();
        let p3_index = addr.p2_index();
        let p2_index = addr.p1_index();
        let p1_index = PageTableIndex::new_truncate(u16::from(addr.page_offset()) >> 3);
        Page::from_page_table_indices(p4_index, p3_index, p2_index, p1_index)
    }

    pub fn is_dirty(&self) -> bool {
        atomic_load(&self.entry).get_bit(DIRTY_BIT)
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
    pub unsafe fn map(&self, entry: PresentPageTableEntry) {
        let res = atomic_compare_exchange(&self.entry, 0, entry.0.get());
        res.expect("the page was already mapped");

        self.parent_table_entry()
            .increase_reference_count()
            .unwrap();
    }

    /// Atomically switch out a page table entry for another.
    ///
    /// # Panics
    ///
    /// Panics if the page isn't mapped.
    ///
    /// # Safety
    ///
    /// It has to be safe that stale TLB entries exist for a brief time.
    pub unsafe fn remap(
        &self,
        old_entry: PresentPageTableEntry,
        new_entry: PresentPageTableEntry,
    ) -> Result<(), PresentPageTableEntry> {
        let _ = atomic_compare_exchange(&self.entry, old_entry.0.get(), new_entry.0.get())
            .map_err(|entry| PresentPageTableEntry::try_from(entry).unwrap())?;

        self.flush(old_entry.global());

        Ok(())
    }

    /// # Panics
    ///
    /// Panics if the page isn't mapped.
    pub unsafe fn unmap(&self) -> PresentPageTableEntry {
        let old_entry = atomic_swap(&self.entry, 0);
        let old_entry = PresentPageTableEntry::try_from(old_entry).unwrap();
        self.flush(old_entry.global());

        // FIXME: Free up the frame.
        let _maybe_frame = unsafe { self.parent_table_entry().release_reference_count() };

        old_entry
    }

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

        atomic_fetch_or(&self.entry, add_mask);
        atomic_fetch_and(&self.entry, !remove_mask);

        self.flush(global);
    }

    pub unsafe fn remove_flags(&self, flags: PageTableFlags) {
        let mut add_mask = 0;
        let mut remove_mask = 0;

        let writable = flags.contains(PageTableFlags::WRITABLE);
        remove_mask.set_bit(WRITE_BIT, writable);
        remove_mask.set_bit(USER_BIT, flags.contains(PageTableFlags::USER));
        let global = flags.contains(PageTableFlags::GLOBAL);
        remove_mask.set_bit(GLOBAL_BIT, global);
        let cow = flags.contains(PageTableFlags::COW);
        remove_mask.set_bit(COW_BIT, cow);
        add_mask.set_bit(
            DISABLE_EXECUTE_BIT,
            flags.contains(PageTableFlags::EXECUTABLE),
        );

        if cow {
            assert!(!writable);
        }

        atomic_fetch_or(&self.entry, add_mask);
        atomic_fetch_and(&self.entry, !remove_mask);

        self.flush(global);
    }

    pub fn entry(&self) -> Option<PresentPageTableEntry> {
        let entry = atomic_load(&self.entry);
        if !entry.get_bit(PRESENT_BIT) {
            return None;
        }
        let entry = NonZeroU64::new(entry).unwrap();
        Some(PresentPageTableEntry(entry))
    }
}

trait ParentEntry {
    unsafe fn release_parent(&self);
}

impl ParentEntry for ActivePageTableEntry<Level4> {
    unsafe fn release_parent(&self) {}
}

impl<L> ParentEntry for ActivePageTableEntry<L>
where
    L: HasParentLevel + TableLevel,
{
    unsafe fn release_parent(&self) {
        let frame = unsafe { self.parent_table_entry().release_reference_count() };
        assert_eq!(frame, None);
    }
}

#[must_use]
struct ActivePageTableEntryGuard<'a, L>
where
    L: TableLevel,
    ActivePageTableEntry<L>: ParentEntry,
{
    entry: &'a ActivePageTableEntry<L>,
}

impl<'a, L> Deref for ActivePageTableEntryGuard<'a, L>
where
    L: TableLevel,
    ActivePageTableEntry<L>: ParentEntry,
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
    ActivePageTableEntry<L>: ParentEntry,
{
    fn drop(&mut self) {
        // Release reference count.
        let frame = unsafe {
            // SAFETY: We're releasing the reference count acquired in
            // ActivePageTableEntry::acquire`.
            self.entry.release_reference_count()
        };

        // Check if the entry was freed.
        if let Some(frame) = frame {
            // Deallocate the backing frame for the entry.
            unsafe {
                (&FRAME_ALLOCATOR).deallocate_frame(frame);
            }

            // Decrease the reference count on the parent entry.
            unsafe {
                self.entry.release_parent();
            }
        }
    }
}

const PRESENT_BIT: usize = 0;
const WRITE_BIT: usize = 1;
const USER_BIT: usize = 2;
const DIRTY_BIT: usize = 6;
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
            let frame = allocator.allocate_frame().ok_or(Error::no_mem(()))?;
            self.frame = Some(frame);
        }

        Ok(ReservedFrameAllocation { storage: self })
    }

    pub fn release(mut self, allocator: &mut (impl FrameDeallocator<Size4KiB> + ?Sized)) {
        let Some(frame) = self.frame.take() else {
            return;
        };
        unsafe {
            allocator.deallocate_frame(frame);
        }
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

/// A page table entry that's present.
#[derive(Clone, Copy)]
pub struct PresentPageTableEntry(NonZeroU64);

impl PresentPageTableEntry {
    pub fn new(frame: PhysFrame, flags: PageTableFlags) -> Self {
        let mut entry = frame.start_address().as_u64();

        entry.set_bit(PRESENT_BIT, true);
        let writable = flags.contains(PageTableFlags::WRITABLE);
        entry.set_bit(WRITE_BIT, writable);
        entry.set_bit(USER_BIT, flags.contains(PageTableFlags::USER));
        let global = flags.contains(PageTableFlags::GLOBAL);
        entry.set_bit(GLOBAL_BIT, global);
        entry.set_bit(
            DISABLE_EXECUTE_BIT,
            !flags.contains(PageTableFlags::EXECUTABLE),
        );
        let cow = flags.contains(PageTableFlags::COW);
        entry.set_bit(COW_BIT, cow);

        if cow {
            assert!(!writable);
        }

        Self(NonZeroU64::new(entry).unwrap())
    }

    pub fn frame(&self) -> PhysFrame {
        PhysFrame::containing_address(PhysAddr::new_truncate(self.0.get()))
    }

    pub fn flags(&self) -> PageTableFlags {
        let mut flags = PageTableFlags::empty();
        flags.set(PageTableFlags::WRITABLE, self.writable());
        flags.set(PageTableFlags::USER, self.user());
        flags.set(PageTableFlags::GLOBAL, self.global());
        flags.set(PageTableFlags::EXECUTABLE, self.executable());
        flags.set(PageTableFlags::COW, self.cow());
        flags
    }

    pub fn writable(&self) -> bool {
        self.0.get().get_bit(WRITE_BIT)
    }

    pub fn user(&self) -> bool {
        self.0.get().get_bit(USER_BIT)
    }

    pub fn global(&self) -> bool {
        self.0.get().get_bit(GLOBAL_BIT)
    }

    pub fn executable(&self) -> bool {
        !self.0.get().get_bit(DISABLE_EXECUTE_BIT)
    }

    pub fn cow(&self) -> bool {
        self.0.get().get_bit(COW_BIT)
    }
}

impl TryFrom<u64> for PresentPageTableEntry {
    type Error = PageNotPresentError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value.get_bit(PRESENT_BIT) {
            Ok(Self(NonZeroU64::new(value).unwrap()))
        } else {
            Err(PageNotPresentError(()))
        }
    }
}

impl fmt::Debug for PresentPageTableEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PresentPageTableEntry")
            .field("frame", &self.frame())
            .field("flags", &self.flags())
            .finish()
    }
}

#[derive(Debug)]
pub struct PageNotPresentError(());

/// Wrapper around `AtomicU64::load` without address sanitizer checks.
#[inline(always)]
fn atomic_load(entry: &AtomicU64) -> u64 {
    if cfg!(sanitize = "address") {
        let out;
        unsafe {
            asm! {
                "mov {out}, [{ptr}]",
                out = out(reg) out,
                ptr = in(reg) entry.as_ptr(),
            }
        }
        out
    } else {
        entry.load(Ordering::SeqCst)
    }
}

/// Wrapper around `AtomicU64::store` without address sanitizer checks.
#[inline(always)]
fn atomic_store(entry: &AtomicU64, val: u64) {
    if cfg!(sanitize = "address") {
        unsafe {
            asm! {
                "mov [{ptr}], {val}",
                val = in(reg) val,
                ptr = in(reg) entry.as_ptr(),
            }
        }
    } else {
        entry.store(val, Ordering::SeqCst)
    }
}

/// Wrapper around `AtomicU64::swap` without address sanitizer checks.
#[inline(always)]
fn atomic_swap(entry: &AtomicU64, val: u64) -> u64 {
    if cfg!(sanitize = "address") {
        let out;
        unsafe {
            asm! {
                "xchg [{ptr}], {val}",
                val = inout(reg) val => out,
                ptr = in(reg) entry.as_ptr(),
            }
        }
        out
    } else {
        entry.swap(val, Ordering::SeqCst)
    }
}

/// Wrapper around `AtomicU64::compare_exchange` without address sanitizer checks.
#[inline(always)]
fn atomic_compare_exchange(entry: &AtomicU64, current: u64, new: u64) -> Result<u64, u64> {
    if cfg!(sanitize = "address") {
        let success: u16;
        let current_value: u64;
        unsafe {
            asm! {
                "lock cmpxchg [{ptr}], {new_value}",
                "setne {success:l}",
                ptr = in(reg) entry.as_ptr(),
                new_value = in(reg) new,
                inout("rax") current => current_value,
                success = lateout(reg) success,
            }
        }
        if success & 0xff == 0 {
            Ok(current_value)
        } else {
            Err(current_value)
        }
    } else {
        entry.compare_exchange(current, new, Ordering::SeqCst, Ordering::SeqCst)
    }
}

/// Wrapper around `AtomicU64::fetch_or` without address sanitizer checks.
#[inline(always)]
fn atomic_fetch_or(entry: &AtomicU64, val: u64) -> u64 {
    if cfg!(sanitize = "address") {
        let mut current = atomic_load(entry);
        loop {
            let new = current | val;
            let res = atomic_compare_exchange(entry, current, new);
            match res {
                Ok(current) => return current,
                Err(new) => current = new,
            }
        }
    } else {
        entry.fetch_or(val, Ordering::SeqCst)
    }
}

/// Wrapper around `AtomicU64::fetch_and` without address sanitizer checks.
#[inline(always)]
fn atomic_fetch_and(entry: &AtomicU64, val: u64) -> u64 {
    if cfg!(sanitize = "address") {
        let mut current = atomic_load(entry);
        loop {
            let new = current & val;
            let res = atomic_compare_exchange(entry, current, new);
            match res {
                Ok(current) => return current,
                Err(new) => current = new,
            }
        }
    } else {
        entry.fetch_and(val, Ordering::SeqCst)
    }
}
