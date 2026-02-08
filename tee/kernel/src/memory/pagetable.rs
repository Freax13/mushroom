//! Concurrent page tables.

use alloc::sync::Arc;
use core::{
    arch::asm,
    cell::RefMut,
    cmp, fmt,
    iter::Step,
    marker::{PhantomData, PhantomPinned},
    num::NonZeroU64,
    ops::{Bound, Deref, Index, Range, RangeBounds},
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};

use bit_field::BitField;
use bitflags::bitflags;
use constants::{
    ApBitmap,
    physical_address::{kernel::*, *},
};
use log::trace;
use static_page_tables::{StaticPageTable, StaticPd, StaticPdp, StaticPml4, flags};
use x86_64::{
    PhysAddr, VirtAddr,
    instructions::tlb::Pcid,
    registers::{
        control::{Cr3, Cr3Flags, Cr4, Cr4Flags},
        rflags::{self, RFlags},
    },
    structures::paging::{Page, PageTableIndex, PhysFrame, Size4KiB},
};

use self::flush::{FlushGuard, GlobalFlushGuard};
use crate::{
    error::{Result, ensure, err},
    memory::{
        frame::{allocate_frame, deallocate_frame},
        temporary::{copy_into_frame, zero_frame},
    },
    per_cpu::{PerCpu, PerCpuSync},
    spin::{lazy::Lazy, mutex::Mutex, rwlock::RwLock},
};

pub mod flush;

const RECURSIVE_INDEX: PageTableIndex = PageTableIndex::new(510);

#[used]
#[unsafe(link_section = ".pagetables.pml4")]
static PML4: StaticPml4 = {
    let mut page_table = StaticPageTable::new();
    page_table.set_table(256, &PDP_256, flags!(WRITE));
    page_table.set_table(257, &PDP_257, flags!(WRITE | EXECUTE_DISABLE));
    page_table.set_table(352, &PDP_352, flags!(WRITE | EXECUTE_DISABLE));
    page_table.set_recursive_table(510, &PML4, flags!(WRITE));
    page_table
};

#[unsafe(link_section = ".ropagetables")]
static PDP_256: StaticPdp = {
    let mut page_table = StaticPageTable::new();
    page_table.set_table(0, &PD_256_0, flags!(WRITE));
    page_table.set_page(1, PROFILER_BUFFER, flags!(WRITE | GLOBAL));
    page_table
};

#[unsafe(link_section = ".ropagetables")]
static PD_256_0: StaticPd = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page(0, RESET_VECTOR, flags!(GLOBAL));
    page_table.set_page_range(1, TEXT, flags!(GLOBAL));
    page_table.set_page_range(8, RODATA, flags!(GLOBAL | EXECUTE_DISABLE));
    page_table.set_page_range(16, DATA, flags!(WRITE | GLOBAL | EXECUTE_DISABLE));
    page_table.set_page_range(32, STACK, flags!(WRITE | GLOBAL | EXECUTE_DISABLE));
    page_table.set_page_range(
        40,
        PROFILER_CONTROL,
        flags!(WRITE | GLOBAL | EXECUTE_DISABLE),
    );
    page_table.set_page(56, LOG_BUFFER, flags!(WRITE | GLOBAL | EXECUTE_DISABLE));
    page_table
};

#[unsafe(link_section = ".ropagetables")]
static PDP_352: StaticPdp = {
    let mut page_table = StaticPageTable::new();
    page_table.set_table(0, &PD_352_0, flags!(WRITE | EXECUTE_DISABLE));
    page_table.set_table(72, &PD_352_72, flags!(EXECUTE_DISABLE));
    page_table.set_table(80, &PD_352_80, flags!(EXECUTE_DISABLE));
    page_table
};

#[unsafe(link_section = ".ropagetables")]
static PD_352_0: StaticPd = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page(0, TEXT_SHADOW, flags!(GLOBAL | EXECUTE_DISABLE));
    page_table.set_page(1, RODATA_SHADOW, flags!(GLOBAL | EXECUTE_DISABLE));
    page_table.set_page(2, DATA_SHADOW, flags!(WRITE | GLOBAL | EXECUTE_DISABLE));
    page_table.set_page(4, STACK_SHADOW, flags!(WRITE | GLOBAL | EXECUTE_DISABLE));
    page_table.set_page(7, LOG_BUFFER_SHADOW, flags!(GLOBAL | EXECUTE_DISABLE));
    page_table
};

#[unsafe(link_section = ".ropagetables")]
static PD_352_72: StaticPd = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page(0, INIT_FILE_SHADOW, flags!(GLOBAL | EXECUTE_DISABLE));
    page_table
};

#[unsafe(link_section = ".ropagetables")]
static PD_352_80: StaticPd = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page(0, INPUT_FILE_SHADOW, flags!(GLOBAL | EXECUTE_DISABLE));
    page_table
};

#[unsafe(link_section = ".ropagetables")]
static PDP_257: StaticPdp = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page_range(0, DYNAMIC, flags!(WRITE | GLOBAL | EXECUTE_DISABLE));
    page_table.set_page_range(128, INIT_FILE, flags!(GLOBAL | EXECUTE_DISABLE));
    page_table.set_page_range(192, INPUT_FILE, flags!(GLOBAL | EXECUTE_DISABLE));
    page_table
};

// Modified page tables for use with TDX. This set of page tables has the `S`
// bit set for the log buffer.

#[used]
#[unsafe(link_section = ".pagetables.tdx.pml4")]
static TDX_PML4: StaticPml4 = {
    // Most kernel mappings are set up through the HLAT PML4, so we can start
    // with an empty PML4.
    let mut page_table = StaticPageTable::new();
    page_table.set_recursive_table(510, &TDX_PML4, flags!(WRITE));
    page_table
};

#[used]
#[unsafe(link_section = ".ropagetables.tdx.pml4")]
static TDX_HLAT_PML4: StaticPml4 = {
    let mut page_table = unsafe { PML4.clone() };
    page_table.clear_entry(256);
    page_table.set_table(256, &TDX_PDP_256, flags!(WRITE));
    // Clear the recursive entry. It should get translated through the regular page tables.
    page_table.clear_entry(510);
    page_table.fill_hlat_restart();
    page_table
};

#[unsafe(link_section = ".ropagetables")]
static TDX_PDP_256: StaticPdp = {
    let mut page_table = unsafe { PDP_256.clone() };
    page_table.clear_entry(0);
    page_table.set_table(0, &TDX_PD_256_0, flags!(WRITE));
    page_table
};

#[unsafe(link_section = ".ropagetables")]
static TDX_PD_256_0: StaticPd = {
    let mut page_table = unsafe { PD_256_0.clone() };
    page_table.clear_entry(56);
    page_table.set_page(56, LOG_BUFFER, flags!(S | WRITE | GLOBAL | EXECUTE_DISABLE));
    page_table
};

static INIT_KERNEL_PML4ES: Lazy<()> = Lazy::new(|| {
    let pml4 = ActivePageTable::get();
    for pml4e in pml4.entries[256..].iter() {
        pml4e.acquire_reference_count(PageTableFlags::GLOBAL);
    }
});

pub unsafe fn map_page(page: Page, entry: PresentPageTableEntry) -> Result<()> {
    trace!("mapping page {page:?}->{entry:?} pml4={:?}", Cr3::read().0);

    let level4 = ActivePageTable::get();
    let level4_entry = &level4[page.p4_index()];

    let level3_guard = level4_entry.acquire(entry.flags(), &GlobalFlushGuard)?;
    let level3 = &*level3_guard;
    let level3_entry = &level3[page.p3_index()];

    let level2_guard = level3_entry.acquire(entry.flags(), &GlobalFlushGuard)?;
    let level2 = &*level2_guard;
    let level2_entry = &level2[page.p2_index()];

    let level1_guard = level2_entry.acquire(entry.flags(), &GlobalFlushGuard)?;
    let level1 = &*level1_guard;
    let level1_entry = &level1[page.p1_index()];

    unsafe {
        level1_entry.map(entry);
    }

    Ok(())
}

/// Unmap a page without flushing it from the TLB.
///
/// # Panics
///
/// This function panics if the page is not mapped.
pub unsafe fn unmap_page_no_flush(page: Page) -> PresentPageTableEntry {
    trace!("unmapping page {page:?}");

    let level4 = ActivePageTable::get();
    let level4_entry = &level4[page.p4_index()];

    let level3_guard = level4_entry.acquire_existing(&GlobalFlushGuard).unwrap();
    let level3 = &*level3_guard;
    let level3_entry = &level3[page.p3_index()];

    let level2_guard = level3_entry.acquire_existing(&GlobalFlushGuard).unwrap();
    let level2 = &*level2_guard;
    let level2_entry = &level2[page.p2_index()];

    let level1_guard = level2_entry.acquire_existing(&GlobalFlushGuard).unwrap();
    let level1 = &*level1_guard;
    let level1_entry = &level1[page.p1_index()];

    unsafe { level1_entry.unmap_no_flush() }
}

/// Unmap a page.
///
/// # Panics
///
/// This function panics if the page is not mapped.
#[cfg(sanitize = "address")]
pub unsafe fn unmap_page(page: Page) -> PresentPageTableEntry {
    let entry = unsafe { unmap_page_no_flush(page) };
    GlobalFlushGuard.flush_page(page);
    entry
}

pub fn entry_for_page(page: Page) -> Option<PresentPageTableEntry> {
    let pml4 = ActivePageTable::get();
    let pml4e = &pml4[page.p4_index()];
    let pdp = pml4e.acquire_existing(&GlobalFlushGuard)?;
    let pdpe = &pdp[page.p3_index()];
    let pd = pdpe.acquire_existing(&GlobalFlushGuard)?;
    let pde = &pd[page.p2_index()];
    let pt = pde.acquire_existing(&GlobalFlushGuard)?;
    let pte = &pt[page.p1_index()];
    pte.entry()
}

/// Try to copy memory from `src` into `dest`.
///
/// This function is not unsafe. If the read fails for some reason `Err(())` is
/// returned.
#[inline(always)]
fn try_read_fast(src: VirtAddr, dest: NonNull<[u8]>) -> Result<(), ()> {
    let failed: u64;
    unsafe {
        asm!(
            "66:",
            "rep movsb",
            "67:",
            ".pushsection .recoverable",
            ".quad 66b",
            ".quad 67b",
            ".popsection",
            inout("rsi") src.as_u64() => _,
            inout("rdi") dest.as_mut_ptr() => _,
            inout("rcx") dest.len() => _,
            inout("rdx") 0u64 => failed,
            options(nostack, preserves_flags),
        );
    }

    if failed == 0 { Ok(()) } else { Err(()) }
}

/// Try to copy memory from `src` into `dest`.
///
/// If the write fails for some reason `Err(())` is returned.
///
/// # Safety
///
/// The caller has to ensure that `src` is safe to read from volatily. Reads
/// may be racy.
///
/// The caller has to ensure writing to `dest` doesn't invalidate any of Rust's
/// rules.
#[inline(always)]
unsafe fn try_write_fast(src: NonNull<[u8]>, dest: VirtAddr) -> Result<(), ()> {
    let failed: u64;
    unsafe {
        asm!(
            "66:",
            "rep movsb",
            "67:",
            ".pushsection .recoverable",
            ".quad 66b",
            ".quad 67b",
            ".popsection",
            inout("rsi") src.as_ptr() as *const u8 => _,
            inout("rdi") dest.as_u64() => _,
            inout("rcx") src.len() => _,
            inout("rdx") 0u64 => failed,
            options(readonly, nostack, preserves_flags),
        );
    }
    if failed == 0 { Ok(()) } else { Err(()) }
}

/// Try to write `count` zero bytes to `dest`.
///
/// If the write fails for some reason `Err(())` is returned.
///
/// # Safety
///
/// The caller has to ensure writing to `dest` doesn't invalidate any of Rust's
/// rules.
#[inline(always)]
unsafe fn try_set_bytes_fast(dest: VirtAddr, count: usize, val: u8) -> Result<(), ()> {
    let failed: u64;
    unsafe {
        asm!(
            "66:",
            "rep stosb",
            "67:",
            ".pushsection .recoverable",
            ".quad 66b",
            ".quad 67b",
            ".popsection",
            in("al") val,
            inout("rdi") dest.as_u64() => _,
            inout("rcx") count => _,
            inout("rdx") 0u64 => failed,
            options(readonly, nostack, preserves_flags),
        );
    }
    if failed == 0 { Ok(()) } else { Err(()) }
}

/// Check that the page is in the lower half.
#[inline(always)]
pub fn check_user_page(page: Page) -> Result<()> {
    ensure!(u16::from(page.p4_index()) < 256, Fault);
    Ok(())
}

#[inline(always)]
pub fn check_user_address(addr: VirtAddr, len: usize) -> Result<()> {
    let Some(len_m1) = len.checked_sub(1) else {
        return Ok(());
    };

    // Make sure that even the end is still in the lower half.
    let end_inclusive = Step::forward_checked(addr, len_m1).ok_or(err!(Fault))?;
    let page = Page::containing_address(end_inclusive);
    check_user_page(page)
}

struct FlushState {
    /// A bitmap containing all APs currently using the page table.
    active: ApBitmap,
    /// A bitmap containing all APs that activated the page tables in the past
    /// or now and have not yet flushed.
    used: ApBitmap,
    /// A bitmap containing all APs that need to flush the PCID the next time
    /// they activate the page tables.
    needs_flush: ApBitmap,
}

impl FlushState {
    pub fn new() -> Self {
        Self {
            active: ApBitmap::empty(),
            used: ApBitmap::empty(),
            needs_flush: ApBitmap::all(),
        }
    }
}

pub struct PagetablesAllocations {
    pml4: PhysFrame,
    flush_state: Mutex<FlushState>,
    /// None if PCID is not supported.
    pcid_allocation: Option<PcidAllocation>,
}

impl Drop for PagetablesAllocations {
    fn drop(&mut self) {
        assert!(self.flush_state.get_mut().active.is_empty());

        unsafe {
            deallocate_frame(self.pml4);
        }
    }
}

pub struct Pagetables {
    allocations: Arc<PagetablesAllocations>,
    /// A lock guarding modifications to the pagetables.
    update_lock: RwLock<()>,
}

impl Pagetables {
    pub fn new() -> Result<Self> {
        // Make sure that all pml4 kernel entries are initialized.
        Lazy::force(&INIT_KERNEL_PML4ES);

        // Allocate a frame for the new pml4.
        let frame = allocate_frame();

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
            copy_into_frame(frame, bytemuck::cast_mut(&mut entries));
        }

        let cr4 = Cr4::read();
        let pcid_allocation = cr4
            .contains(Cr4Flags::PCID)
            .then(|| ALLOCATIONS.lock().allocate());
        let allocations = PagetablesAllocations {
            pml4: frame,
            flush_state: Mutex::new(FlushState::new()),
            pcid_allocation,
        };
        let allocations = Arc::new(allocations);

        Ok(Self {
            allocations,
            update_lock: RwLock::new(()),
        })
    }

    pub fn run_with<R>(&self, f: impl FnOnce() -> R) -> R {
        let _guard = self.activate();
        f()
    }

    #[must_use]
    fn activate(&self) -> ActivePageTableGuard {
        PerCpuSync::get().interrupt_data.check_max_interrupt(None);

        let allocations = &self.allocations;

        let per_cpu = PerCpu::get();
        let mut guard = per_cpu.last_pagetables.borrow_mut();

        let update_required = !guard
            .as_ref()
            .is_some_and(|existing| Arc::ptr_eq(existing, allocations));

        let mut flush_state_guard = allocations.flush_state.lock();
        let ap_index = PerCpu::get().idx;
        flush_state_guard.active.set(ap_index, true);
        flush_state_guard.used.set(ap_index, true);
        let needs_flush = flush_state_guard.needs_flush.get(ap_index);
        if needs_flush {
            flush_state_guard.needs_flush.set(ap_index, false);
        }

        if update_required || needs_flush {
            if let Some(pcid_allocation) = allocations.pcid_allocation.as_ref() {
                if needs_flush {
                    unsafe {
                        Cr3::write_pcid(allocations.pml4, pcid_allocation.pcid);
                    }
                } else {
                    unsafe {
                        Cr3::write_pcid_no_flush(allocations.pml4, pcid_allocation.pcid);
                    }
                }
            } else {
                unsafe {
                    Cr3::write(allocations.pml4, Cr3Flags::empty());
                }
            }
        }
        drop(flush_state_guard);

        if update_required {
            *guard = Some(allocations.clone());
        }

        let guard = RefMut::map(guard, |a| a.as_mut().unwrap());

        ActivePageTableGuard {
            guard,
            pml4: ActivePageTable::get(),
            _marker: PhantomData,
        }
    }

    /// Map a page regardless of whether there's already a page mapped there.
    pub fn set_page(&self, page: Page, entry: PresentPageTableEntry) -> Result<()> {
        check_user_page(page)?;
        trace!("mapping page {page:?}");

        let _guard = self.update_lock.read();
        let level4 = self.activate();
        let level4_entry = &level4[page.p4_index()];

        let level3_guard = level4_entry.acquire(entry.flags(), &level4)?;
        let level3 = &*level3_guard;
        let level3_entry = &level3[page.p3_index()];

        let level2_guard = level3_entry.acquire(entry.flags(), &level4)?;
        let level2 = &*level2_guard;
        let level2_entry = &level2[page.p2_index()];

        let level1_guard = level2_entry.acquire(entry.flags(), &level4)?;
        let level1 = &*level1_guard;
        let level1_entry = &level1[page.p1_index()];

        unsafe {
            level1_entry.set_page(entry);
        }

        Ok(())
    }

    /// Remove the write-bit on all mapped userspace pages.
    pub fn freeze_userspace(&self) {
        let _guard = self.update_lock.write();

        let level4 = self.activate();
        for entry in level4.entries[..256].iter() {
            unsafe {
                entry.freeze();
            }
        }

        level4.flush_all();
    }

    /// Unmap a page if it's mapped.
    pub fn try_unmap_user_page(&self, page: Page) {
        self.try_unmap_user_pages(page..=page)
    }

    /// Unmap all pages in the given range. Not all pages have to be mapped.
    pub fn try_unmap_user_pages(&self, pages: impl RangeBounds<Page>) {
        const LAST_USER_PAGE: Page =
            unsafe { Page::from_start_address_unchecked(VirtAddr::new(0x7fff_ffff_f000)) };

        // Convert to inclusive range.
        let start = match pages.start_bound() {
            Bound::Included(&page) => page,
            Bound::Excluded(&page) => Step::forward_checked(page, 1).unwrap_or(LAST_USER_PAGE),
            Bound::Unbounded => Page::containing_address(VirtAddr::zero()),
        };
        let start = cmp::min(start, LAST_USER_PAGE);
        let end = match pages.end_bound() {
            Bound::Included(&page) => page,
            Bound::Excluded(&page) => {
                if let Some(page) = Step::backward_checked(page, 1) {
                    page
                } else {
                    return;
                }
            }
            Bound::Unbounded => LAST_USER_PAGE,
        };
        let end = cmp::min(end, LAST_USER_PAGE);

        // Don't do anything if the range is empty.
        if start > end {
            return;
        }

        let mut needs_flush = false;
        let _guard = self.update_lock.read();
        let pml4 = self.activate();
        for p4_index in start.p4_index()..=end.p4_index() {
            let pml4e = &pml4[p4_index];
            let Some(pdp) = pml4e.acquire_existing(&pml4) else {
                continue;
            };

            let start = cmp::max(
                start,
                Page::from_page_table_indices(
                    p4_index,
                    PageTableIndex::new(0),
                    PageTableIndex::new(0),
                    PageTableIndex::new(0),
                ),
            );
            let end = cmp::min(
                end,
                Page::from_page_table_indices(
                    p4_index,
                    PageTableIndex::new(511),
                    PageTableIndex::new(511),
                    PageTableIndex::new(511),
                ),
            );

            for p3_index in start.p3_index()..=end.p3_index() {
                let pdpe = &pdp[p3_index];
                let Some(pd) = pdpe.acquire_existing(&pml4) else {
                    continue;
                };

                let start = cmp::max(
                    start,
                    Page::from_page_table_indices(
                        p4_index,
                        p3_index,
                        PageTableIndex::new(0),
                        PageTableIndex::new(0),
                    ),
                );
                let end = cmp::min(
                    end,
                    Page::from_page_table_indices(
                        p4_index,
                        p3_index,
                        PageTableIndex::new(511),
                        PageTableIndex::new(511),
                    ),
                );

                for p2_index in start.p2_index()..=end.p2_index() {
                    let pde = &pd[p2_index];
                    let Some(pt) = pde.acquire_existing(&pml4) else {
                        continue;
                    };

                    let start = cmp::max(
                        start,
                        Page::from_page_table_indices(
                            p4_index,
                            p3_index,
                            p2_index,
                            PageTableIndex::new(0),
                        ),
                    );
                    let end = cmp::min(
                        end,
                        Page::from_page_table_indices(
                            p4_index,
                            p3_index,
                            p2_index,
                            PageTableIndex::new(511),
                        ),
                    );

                    for p1_index in start.p1_index()..=end.p1_index() {
                        let pte = &pt[p1_index];
                        needs_flush |= unsafe { pte.try_unmap() };
                    }
                }
            }
        }

        if needs_flush {
            pml4.flush_pages(start..=end);
        }
    }

    /// Try to copy user memory from `src` into `dest`.
    ///
    /// This function is not unsafe. If the read fails for some reason `Err(())` is
    /// returned. If `src` isn't user memory `Err(())` is returned.
    #[inline(always)]
    pub fn try_read_user_fast(&self, src: VirtAddr, dest: NonNull<[u8]>) -> Result<(), ()> {
        if dest.is_empty() {
            return Ok(());
        }

        check_user_address(src, dest.len()).map_err(|_| ())?;

        let _guard = self.activate();

        without_smap(|| try_read_fast(src, dest))
    }

    /// Try to copy memory from `src` into `dest`.
    ///
    /// If the write fails for some reason `Err(())` is returned. If `src` isn't
    /// user memory `Err(())` is returned.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that `src` is safe to read from volatily. Reads
    /// may be racy.
    #[inline(always)]
    pub fn try_write_user_fast(&self, src: NonNull<[u8]>, dest: VirtAddr) -> Result<(), ()> {
        if src.is_empty() {
            return Ok(());
        }

        check_user_address(dest, src.len()).map_err(|_| ())?;

        let _guard = self.activate();

        without_smap(|| unsafe { try_write_fast(src, dest) })
    }

    /// Write `count` zero bytes to `dest`.
    ///
    /// If the write fails for some reason `Err(())` is returned. If `src` isn't
    /// user memory `Err(())` is returned.
    #[inline(always)]
    pub fn try_set_bytes_user_fast(&self, dest: VirtAddr, count: usize, val: u8) -> Result<(), ()> {
        if count == 0 {
            return Ok(());
        }

        check_user_address(dest, count).map_err(|_| ())?;

        let _guard = self.activate();

        without_smap(|| unsafe { try_set_bytes_fast(dest, count, val) })
    }
}

fn without_smap<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let rflags = rflags::read();
    let changed = !rflags.contains(RFlags::ALIGNMENT_CHECK);
    if changed {
        unsafe {
            asm!("stac", options(nostack, preserves_flags));
        }
    }

    let result = f();

    if changed {
        unsafe {
            asm!("clac", options(nostack, preserves_flags));
        }
    }

    result
}

struct ActivePageTableGuard {
    guard: RefMut<'static, Arc<PagetablesAllocations>>,
    pml4: &'static ActivePageTable<Level4>,
    // Make sure the type is neither `Send` nor `Sync`.
    _marker: PhantomData<*const ()>,
}

impl Deref for ActivePageTableGuard {
    type Target = ActivePageTable<Level4>;

    fn deref(&self) -> &Self::Target {
        self.pml4
    }
}

impl Drop for ActivePageTableGuard {
    fn drop(&mut self) {
        let mut guard = self.guard.flush_state.lock();
        guard.active.set(PerCpu::get().idx, false);
    }
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
    pub fn acquire<'a, F>(
        &'a self,
        flags: PageTableFlags,
        guard: &'a F,
    ) -> Result<ActivePageTableEntryGuard<'a, Level4, F>>
    where
        F: FlushGuard,
    {
        self.acquire_reference_count(flags).unwrap();
        Ok(ActivePageTableEntryGuard { entry: self, guard })
    }

    pub fn acquire_existing<'a, F>(
        &'a self,
        guard: &'a F,
    ) -> Option<ActivePageTableEntryGuard<'a, Level4, F>>
    where
        F: FlushGuard,
    {
        self.increase_reference_count().ok()?;
        Some(ActivePageTableEntryGuard { entry: self, guard })
    }
}

impl<L> ActivePageTableEntry<L>
where
    L: HasParentLevel + TableLevel,
{
    pub fn acquire<'a, F>(
        &'a self,
        flags: PageTableFlags,
        guard: &'a F,
    ) -> Result<ActivePageTableEntryGuard<'a, L, F>>
    where
        F: FlushGuard,
    {
        let initialized = self.acquire_reference_count(flags).unwrap();

        if initialized {
            let parent_entry = self.parent_table_entry();
            parent_entry.increase_reference_count().unwrap();
        }

        Ok(ActivePageTableEntryGuard { entry: self, guard })
    }

    pub fn acquire_existing<'a, F>(
        &'a self,
        guard: &'a F,
    ) -> Option<ActivePageTableEntryGuard<'a, L, F>>
    where
        F: FlushGuard,
    {
        self.increase_reference_count().ok()?;
        Some(ActivePageTableEntryGuard { entry: self, guard })
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
    fn acquire_reference_count(&self, flags: PageTableFlags) -> Option<bool> {
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

                if !self.is_static_entry() {
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

                // Allocate memory for the page table and zero initialize it.
                // Note that it's important to zero the memory before mapping
                // it because the CPU may speculatively read from it and
                // install TLB entries based on the uninitialized data.
                let frame = allocate_frame();
                unsafe {
                    zero_frame(frame);
                }

                // Prepare the entry.
                let mut new_entry = frame.start_address().as_u64();
                new_entry.set_bit(PRESENT_BIT, true);
                new_entry.set_bit(WRITE_BIT, true);
                new_entry.set_bit(USER_BIT, user);
                new_entry.set_bit(GLOBAL_BIT, global);
                new_entry.set_bits(REFERENCE_COUNT_BITS, 0);

                // Write the entry back.
                atomic_store(&self.entry, new_entry);

                // We're done.
                return Some(true);
            }
        }
    }

    /// Increases the reference count. Returns `Ok(())` if there reference count
    /// was increased, returns `Err(())` if the page table didn't exist.
    fn increase_reference_count(&self) -> Result<(), ()> {
        if self.is_static_entry() {
            return Ok(());
        }

        let mut current_entry = atomic_load(&self.entry);
        loop {
            // If the entry is being initialized right now, this means that
            // there's no page table yet and the caller likely isn't interested
            // in a page table that only exists in a short while.
            if current_entry.get_bit(INITIALIZING_BIT) {
                return Err(());
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
    unsafe fn release_reference_count(&self, guard: &impl FlushGuard) -> Option<PhysFrame> {
        if self.is_static_entry() {
            return None;
        }

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

                // We remove the page table in three steps:
                // 1. Zero out the entry, but set `INITIALIZING_BIT`. This
                //    prevents other threads from changing anything until step
                //    2 is complete.
                // 2. Flush the page table from all APs.
                // 3. Write zero to the entry.

                let new_entry = 1 << INITIALIZING_BIT;

                // Step 1:
                // First try to commit the zeroing.
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

                // Step 2:
                self.flush(guard);

                // Step 3:
                atomic_store(&self.entry, 0);

                // Extract the freed frame and return it.
                let phys_addr = PhysAddr::new_truncate(current_entry);
                let frame = PhysFrame::containing_address(phys_addr);
                return Some(frame);
            }
        }
    }

    /// Only decrease the reference count, but don't do any resource
    /// management.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the entry is that `release` is only called
    /// after the `acquire` is no longer needed. Additionally, the caller must
    /// ensure that the reference count doesn't hit zero.
    unsafe fn release_reference_count_fast(&self) {
        if self.is_static_entry() {
            return;
        }

        fetch_sub(&self.entry, 1 << REFERENCE_COUNT_BITS.start);
    }

    fn as_table_ptr(&self) -> *const ActivePageTable<<L as TableLevel>::Next> {
        let addr = VirtAddr::from_ptr(self);
        let p4_index = addr.p3_index();
        let p3_index = addr.p2_index();
        let p2_index = addr.p1_index();
        let p1_index = PageTableIndex::new(u16::from(addr.page_offset()) >> 3);
        let page = Page::from_page_table_indices(p4_index, p3_index, p2_index, p1_index);
        let addr = page.start_address();
        addr.as_ptr()
    }
}

impl<L> ActivePageTableEntry<L> {
    fn flush(&self, guard: &impl FlushGuard) {
        guard.flush_page(self.page());
    }

    pub fn page(&self) -> Page<Size4KiB> {
        let addr = VirtAddr::from_ptr(self);
        let p4_index = addr.p3_index();
        let p3_index = addr.p2_index();
        let p2_index = addr.p1_index();
        let p1_index = PageTableIndex::new(u16::from(addr.page_offset()) >> 3);
        Page::from_page_table_indices(p4_index, p3_index, p2_index, p1_index)
    }

    /// Returns whether this entry is one of the pml4 entries used for kernel
    /// memory. These entries are not reference counted because they will never
    /// change.
    pub fn is_static_entry(&self) -> bool {
        let start = Page::from_page_table_indices(
            RECURSIVE_INDEX,
            RECURSIVE_INDEX,
            RECURSIVE_INDEX,
            PageTableIndex::new(256),
        );
        let end = Page::from_page_table_indices(
            RECURSIVE_INDEX,
            RECURSIVE_INDEX,
            RECURSIVE_INDEX,
            PageTableIndex::new(511),
        );
        (start..=end).contains(&self.page())
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

    /// Map a new page or replace an existing page.
    pub unsafe fn set_page(&self, entry: PresentPageTableEntry) {
        let mut old_entry = atomic_load(&self.entry);
        loop {
            let mut new_entry = entry;
            if let Ok(old_entry) = PresentPageTableEntry::try_from(old_entry) {
                new_entry.set_accessed(old_entry.accessed());
            }

            match atomic_compare_exchange(&self.entry, old_entry, new_entry.0.get()) {
                Ok(_) => break,
                Err(new_old_entry) => old_entry = new_old_entry,
            }
        }

        if old_entry == 0 {
            self.parent_table_entry()
                .increase_reference_count()
                .unwrap();
        }
    }

    /// # Panics
    ///
    /// Panics if the page isn't mapped.
    pub unsafe fn unmap_no_flush(&self) -> PresentPageTableEntry {
        let old_entry = atomic_swap(&self.entry, 0);
        let old_entry = PresentPageTableEntry::try_from(old_entry).unwrap();

        unsafe {
            self.parent_table_entry().release_reference_count_fast();
        }

        old_entry
    }

    /// Unmap a page if it's mapped or do nothing if it isn't.
    ///
    /// Returns true if there previously was an entry and that entry had been
    /// accessed.
    pub unsafe fn try_unmap(&self) -> bool {
        let old_entry = atomic_swap(&self.entry, 0);
        if let Ok(entry) = PresentPageTableEntry::try_from(old_entry) {
            unsafe {
                self.parent_table_entry().release_reference_count_fast();
            }
            entry.accessed()
        } else {
            false
        }
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
        unsafe {
            self.parent_table_entry().release_reference_count_fast();
        }
    }
}

#[must_use]
struct ActivePageTableEntryGuard<'a, L, F>
where
    L: TableLevel,
    ActivePageTableEntry<L>: ParentEntry,
    F: FlushGuard,
{
    entry: &'a ActivePageTableEntry<L>,
    guard: &'a F,
}

impl<L, F> Deref for ActivePageTableEntryGuard<'_, L, F>
where
    L: TableLevel,
    ActivePageTableEntry<L>: ParentEntry,
    F: FlushGuard,
{
    type Target = ActivePageTable<L::Next>;

    fn deref(&self) -> &Self::Target {
        let table_ptr = self.entry.as_table_ptr();
        unsafe { &*table_ptr }
    }
}

impl<L, F> Drop for ActivePageTableEntryGuard<'_, L, F>
where
    L: TableLevel,
    ActivePageTableEntry<L>: ParentEntry,
    F: FlushGuard,
{
    fn drop(&mut self) {
        // Release reference count.
        let frame = unsafe {
            // SAFETY: We're releasing the reference count acquired in
            // ActivePageTableEntry::acquire`.
            self.entry.release_reference_count(self.guard)
        };

        // Check if the entry was freed.
        if let Some(frame) = frame {
            // Deallocate the backing frame for the entry.
            unsafe {
                deallocate_frame(frame);
            }

            // Decrease the reference count on the parent entry.
            unsafe {
                self.entry.release_parent();
            }
        }
    }
}

pub trait Clear {
    /// Clear the write bit for all mapped pages.
    ///
    /// Note that this function doesn't flush any entries from the TLB.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that no other thread is modifying the
    /// pagetables at the same time.
    unsafe fn freeze(&self);
}

impl<L> Clear for ActivePageTableEntry<L>
where
    L: TableLevel,
    ActivePageTableEntry<L::Next>: Clear,
{
    /// Clear the write bit for all mapped pages.
    ///
    /// Note that this function doesn't flush any entries from the TLB.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that no other thread is modifying the
    /// pagetables at the same time.
    unsafe fn freeze(&self) {
        // Skip empty entries.
        let value = unsafe { load(&self.entry) };
        if value == 0 {
            return;
        }

        // Recursively clear each entry.
        let ptr = self.as_table_ptr();
        let table = unsafe { &*ptr };
        table.entries.iter().for_each(|e| unsafe { e.freeze() });
    }
}

impl Clear for ActivePageTableEntry<Level1> {
    /// Clear the write bit for all mapped pages.
    ///
    /// Note that this function doesn't flush any entries from the TLB.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that no other thread is modifying the
    /// pagetables at the same time.
    #[inline]
    unsafe fn freeze(&self) {
        atomic_fetch_and(&self.entry, !(1 << WRITE_BIT));
    }
}

const PRESENT_BIT: usize = 0;
const WRITE_BIT: usize = 1;
const USER_BIT: usize = 2;
const ACCESSED_BIT: usize = 5;
const DIRTY_BIT: usize = 6;
const GLOBAL_BIT: usize = 8;
const DISABLE_EXECUTE_BIT: usize = 63;

/// Indicates that the page table is currently being initialized.
const INITIALIZING_BIT: usize = 9;

/// Bits that are used to reference count the entry.
///
/// The reference count is represented as one less than the actual count. So if
/// the bits are 0, it's really 1. This increases the amount of possible values
/// by one.
///
/// The total capacity of the reference count is 1<<10 = 1024.
const REFERENCE_COUNT_BITS: Range<usize> = 52..62;

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct PageTableFlags: u8 {
        const WRITABLE = 1 << 0;
        const EXECUTABLE = 1 << 1;
        const USER = 1 << 2;
        const GLOBAL = 1 << 3;
        const ACCESSED = 1 << 4;
        const DIRTY = 1 << 5;
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
        let accessed = flags.contains(PageTableFlags::ACCESSED);
        entry.set_bit(ACCESSED_BIT, accessed);
        let dirty = flags.contains(PageTableFlags::DIRTY);
        entry.set_bit(DIRTY_BIT, dirty);

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
        flags.set(PageTableFlags::ACCESSED, self.accessed());
        flags.set(PageTableFlags::DIRTY, self.dirty());
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

    pub fn accessed(&self) -> bool {
        self.0.get().get_bit(ACCESSED_BIT)
    }

    pub fn set_accessed(&mut self, accessed: bool) {
        self.0.get().set_bit(ACCESSED_BIT, accessed);
    }

    pub fn dirty(&self) -> bool {
        self.0.get().get_bit(DIRTY_BIT)
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
                options(nostack, readonly, preserves_flags),
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
                "xchg qword ptr [{ptr}], {val}",
                val = inout(reg) val => _,
                ptr = in(reg) entry.as_ptr(),
                options(nostack, preserves_flags),
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
                "xchg qword ptr [{ptr}], {val}",
                val = inout(reg) val => out,
                ptr = in(reg) entry.as_ptr(),
                options(nostack, preserves_flags),
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
                options(nostack),
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

/// Wrapper around `AtomicU64::fetch_add` without address sanitizer checks.
#[inline(always)]
fn fetch_add(entry: &AtomicU64, val: u64) -> u64 {
    if cfg!(sanitize = "address") {
        let out;
        unsafe {
            asm! {
                "lock xadd [{ptr}], {out}",
                out = inout(reg) val => out,
                ptr = in(reg) entry.as_ptr(),
                options(nostack),
            }
        }
        out
    } else {
        entry.fetch_add(val, Ordering::SeqCst)
    }
}

/// Wrapper around `AtomicU64::fetch_sub` without address sanitizer checks.
#[inline(always)]
fn fetch_sub(entry: &AtomicU64, val: u64) -> u64 {
    fetch_add(entry, (-(val as i64)) as u64)
}

/// Wrapper around `core::ptr::read` without address sanitizer checks.
///
/// # Safety
///
/// The caller has to ensure that the read isn't subject to a data race.
#[inline(always)]
unsafe fn load(entry: &AtomicU64) -> u64 {
    if cfg!(sanitize = "address") {
        let out;
        unsafe {
            asm! {
                "mov {out}, [{ptr}]",
                out = out(reg) out,
                ptr = in(reg) entry.as_ptr(),
                options(nostack, preserves_flags),
            }
        }
        out
    } else {
        unsafe { core::ptr::read(entry.as_ptr()) }
    }
}

static ALLOCATIONS: Mutex<PcidAllocations> = Mutex::new(PcidAllocations::new());

struct PcidAllocations {
    last_idx: usize,
    in_use: [bool; 4096],
}

impl PcidAllocations {
    const fn new() -> Self {
        let mut in_use = [false; 4096];
        in_use[0] = true; // Reserve the first PCID for the kernel.
        Self {
            last_idx: 0,
            in_use,
        }
    }

    fn allocate(&mut self) -> PcidAllocation {
        let mut counter = 0;

        while self.in_use[self.last_idx] {
            self.last_idx += 1;
            self.last_idx %= self.in_use.len();
            counter += 1;
            assert!(counter < self.in_use.len());
        }

        self.in_use[self.last_idx] = true;
        let pcid = Pcid::new(self.last_idx as u16).unwrap();
        self.last_idx += 1;
        self.last_idx %= self.in_use.len();
        PcidAllocation { pcid }
    }

    unsafe fn deallocate(&mut self, pcid: Pcid) {
        self.in_use[usize::from(pcid.value())] = false;
    }
}

pub struct PcidAllocation {
    pcid: Pcid,
}

impl Drop for PcidAllocation {
    fn drop(&mut self) {
        let mut guard = ALLOCATIONS.lock();
        unsafe {
            guard.deallocate(self.pcid);
        }
    }
}
