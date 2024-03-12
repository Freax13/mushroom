use core::{
    arch::asm,
    borrow::Borrow,
    cmp::{self, Ordering},
    iter::Step,
    ops::{Deref, RangeBounds},
    ptr::NonNull,
};

use crate::{
    fs::fd::OpenFileDescription,
    memory::{
        invlpgb::INVLPGB,
        page::{KernelPage, UserPage},
        pagetable::{
            freeze_userspace, set_page, try_set_page, try_unmap_user_page, try_unmap_user_pages,
        },
    },
    rt::spawn,
    spin::{
        lazy::Lazy,
        mutex::Mutex,
        rwlock::{RwLock, WriteRwLockGuard},
    },
};
use alloc::{
    boxed::Box,
    collections::{btree_map::Entry, BTreeMap},
    ffi::CString,
    sync::Arc,
    vec::Vec,
};
use bit_field::BitField;
use bitflags::bitflags;
use crossbeam_queue::SegQueue;
use log::debug;
use usize_conversions::{usize_from, FromUsize};
use x86_64::{
    align_down,
    instructions::{random::RdRand, tlb::Pcid},
    registers::{
        control::{Cr3, Cr3Flags, Cr4, Cr4Flags},
        rflags::{self, RFlags},
    },
    structures::{
        idt::PageFaultErrorCode,
        paging::{Page, PageOffset, PhysFrame},
    },
    VirtAddr,
};

use crate::{
    error::{Error, Result},
    memory::{
        frame::FRAME_ALLOCATOR,
        pagetable::{allocate_pml4, PageTableFlags},
    },
    rt::oneshot,
};

use super::syscall::{
    args::{
        pointee::{AbiAgnosticPointee, ReadablePointee, WritablePointee},
        Pointer, ProtFlags,
    },
    traits::Abi,
};

const SIGRETURN_TRAMPOLINE_PAGE: u64 = 0x7fff_f000;
pub const SIGRETURN_TRAMPOLINE_I386: u64 = SIGRETURN_TRAMPOLINE_PAGE;
pub const SIGRETURN_TRAMPOLINE_AMD64: u64 = SIGRETURN_TRAMPOLINE_PAGE + 0x10;

type DynVirtualMemoryOp = Box<dyn FnOnce(&mut VirtualMemoryActivator) + Send>;
static PENDING_VIRTUAL_MEMORY_OPERATIONS: SegQueue<DynVirtualMemoryOp> = SegQueue::new();

/// Returns true if a virtual memory op was executed.
pub fn do_virtual_memory_op(virtual_memory_activator: &mut VirtualMemoryActivator) -> bool {
    let Some(op) = PENDING_VIRTUAL_MEMORY_OPERATIONS.pop() else {
        return false;
    };
    op(virtual_memory_activator);
    true
}

pub struct VirtualMemoryActivator(());

impl VirtualMemoryActivator {
    pub async fn r#do<R>(f: impl FnOnce(&mut VirtualMemoryActivator) -> R + Send + 'static) -> R
    where
        R: Send + 'static,
    {
        let (sender, receiver) = oneshot::new();

        PENDING_VIRTUAL_MEMORY_OPERATIONS.push(Box::new(|virtual_memory_activator| {
            let result = f(virtual_memory_activator);
            let _ = sender.send(result);
        }));

        receiver.recv().await.unwrap()
    }

    /// A function that allows an async function to activate a virtual memory.
    pub async fn use_from_async<R>(
        virtual_memory: Arc<VirtualMemory>,
        f: impl FnOnce(&mut ActiveVirtualMemory) -> R + Send + 'static,
    ) -> R
    where
        R: Send + 'static,
    {
        Self::r#do(move |vm_activator| vm_activator.activate(&virtual_memory, f)).await
    }

    pub unsafe fn new() -> Self {
        Self(())
    }

    pub fn activate<'a, 'b, R, F>(&'a mut self, virtual_memory: &'b VirtualMemory, f: F) -> R
    where
        F: for<'r> FnOnce(&'r mut ActiveVirtualMemory<'a, 'b>) -> R,
    {
        // Save the current page tables.
        let (prev_pml4, bits) = Cr3::read_raw();

        // Switch the page tables.
        if let Some(pcid_allocation) = virtual_memory.pcid_allocation.as_ref() {
            unsafe {
                Cr3::write_pcid(virtual_memory.pml4, pcid_allocation.pcid);
            }
        } else {
            unsafe {
                Cr3::write(virtual_memory.pml4, Cr3Flags::empty());
            }
        }

        let mut active_virtual_memory = ActiveVirtualMemory {
            _activator: self,
            virtual_memory,
        };

        // Run the closure.
        let res = f(&mut active_virtual_memory);

        // Restore the page tables.
        unsafe {
            Cr3::write_raw(prev_pml4, bits);
        }

        res
    }
}

pub struct VirtualMemory {
    state: RwLock<VirtualMemoryState>,
    pml4: PhysFrame,
    /// None if PCID is not supported.
    pcid_allocation: Option<PcidAllocation>,
}

impl VirtualMemory {
    pub fn new() -> Self {
        Self::default()
    }

    /// # Safety
    ///
    /// The virtual memory must be active.
    pub unsafe fn handle_page_fault(&self, addr: u64, error_code: PageFaultErrorCode) -> bool {
        let addr = VirtAddr::new(addr);
        let page = Page::containing_address(addr);

        debug!(target: "kernel::exception", "{addr:?} {error_code:?}");

        let mut required_flags = PageTableFlags::empty();
        required_flags.set(
            PageTableFlags::WRITABLE,
            error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE),
        );
        required_flags.set(
            PageTableFlags::EXECUTABLE,
            error_code.contains(PageFaultErrorCode::INSTRUCTION_FETCH),
        );

        // TODO: remove this.
        let vm = ActiveVirtualMemory {
            _activator: &mut VirtualMemoryActivator(()),
            virtual_memory: self,
        };
        vm.map_page(page, required_flags).is_ok()
    }

    /// Create a deep copy of the memory.
    pub fn clone(&self, vm_activator: &mut VirtualMemoryActivator) -> Result<Self> {
        let mut this = Self::new();
        let new_state = this.state.get_mut();

        let mut guard = self.state.write();
        new_state.brk_end = guard.brk_end;

        // Prevent userspace from writing to memory.
        vm_activator.activate(self, |_| unsafe {
            freeze_userspace();
        });

        // Clone the backing memory.
        for (page, user_page) in guard.pages.iter_mut() {
            let user_page = user_page.get_mut().clone()?;
            new_state.pages.insert(*page, Mutex::new(user_page));
        }

        drop(guard);

        Ok(this)
    }

    pub fn brk_end(&self) -> VirtAddr {
        self.state.read().brk_end
    }
}

impl Default for VirtualMemory {
    fn default() -> Self {
        let cr4 = &Cr4::read();
        let pcid_allocation = cr4
            .contains(Cr4Flags::PCID)
            .then(|| ALLOCATIONS.lock().allocate());

        let pml4 = allocate_pml4().unwrap();

        Self {
            state: RwLock::new(VirtualMemoryState::new()),
            pml4,
            pcid_allocation,
        }
    }
}

impl Drop for VirtualMemory {
    fn drop(&mut self) {
        let state = self.state.get_mut();
        if !state.pages.is_empty() {
            let this = core::mem::take(self);
            spawn(async move {
                VirtualMemoryActivator::use_from_async(Arc::new(this), |a| {
                    a.modify().unmap(VirtAddr::new(0), !0)
                })
                .await;
            });
        }
    }
}

/// Check that the page is in the lower half.
fn check_user_page(page: Page) -> Result<()> {
    if u16::from(page.p4_index()) < 256 {
        Ok(())
    } else {
        Err(Error::fault(()))
    }
}

pub struct ActiveVirtualMemory<'a, 'b> {
    _activator: &'a mut VirtualMemoryActivator,
    virtual_memory: &'b VirtualMemory,
}

impl<'a, 'b> ActiveVirtualMemory<'a, 'b> {
    pub fn modify(&self) -> ActiveVirtualMemoryWriteGuard<'_> {
        ActiveVirtualMemoryWriteGuard {
            guard: self.state.write(),
        }
    }

    pub fn map_page(&self, page: Page, required_flags: PageTableFlags) -> Result<()> {
        let state = self.state.read();
        let user_page = state.pages.get(&page).ok_or_else(|| Error::fault(()))?;

        let mut guard = user_page.lock();

        if required_flags.contains(PageTableFlags::WRITABLE)
            && guard.perms().contains(MemoryPermissions::WRITE)
        {
            try_unmap_user_page(page);
            guard.make_mut()?;
        }

        let entry = guard.entry();

        if !entry.flags().contains(required_flags) {
            return Err(Error::fault(()));
        }

        unsafe {
            set_page(page, entry, &mut &FRAME_ALLOCATOR)?;
        }

        drop(guard);

        Ok(())
    }

    pub fn map_addrs(
        &self,
        addr: VirtAddr,
        len: usize,
        required_flags: PageTableFlags,
    ) -> Result<()> {
        assert_ne!(len, 0);

        let start = Page::containing_address(addr);
        let end = Page::containing_address(addr + u64::from_usize(len - 1));
        for page in start..=end {
            self.map_page(page, required_flags)?;
        }

        Ok(())
    }

    pub fn read_bytes(&self, addr: VirtAddr, bytes: &mut [u8]) -> Result<()> {
        unsafe { self.read_bytes_volatile(addr, NonNull::from(bytes)) }
    }

    pub unsafe fn read_bytes_volatile(&self, addr: VirtAddr, bytes: NonNull<[u8]>) -> Result<()> {
        if bytes.len() == 0 {
            return Ok(());
        }

        check_user_address(addr, bytes.len())?;

        if try_read_user_fast(addr, bytes).is_ok() {
            return Ok(());
        }

        self.map_addrs(addr, bytes.len(), PageTableFlags::empty())?;

        try_read_user_fast(addr, bytes).unwrap();

        Ok(())
    }

    /// Read a pointee from userspace with the given ABI and return the amount of bytes read.
    pub fn read_sized_with_abi<T, P>(&self, pointer: Pointer<T>, abi: Abi) -> Result<(usize, T)>
    where
        T: ReadablePointee<P>,
    {
        T::read(pointer.get(), self, abi)
    }

    /// Read a pointee from userspace with the given ABI.
    pub fn read_with_abi<T, P>(&self, pointer: Pointer<T>, abi: Abi) -> Result<T>
    where
        T: ReadablePointee<P>,
    {
        let (_size, value) = self.read_sized_with_abi(pointer, abi)?;
        Ok(value)
    }

    /// Read a pointee from userspace.
    pub fn read<T, P>(&self, pointer: Pointer<T>) -> Result<T>
    where
        T: ReadablePointee<P> + AbiAgnosticPointee,
    {
        self.read_with_abi(pointer, Abi::Amd64)
    }

    /// Read a string from userspace.
    pub fn read_cstring(&self, pointer: Pointer<CString>, max_length: usize) -> Result<CString> {
        let mut addr = pointer.get();
        let mut ret = Vec::new();
        loop {
            let mut buf = 0;
            self.read_bytes(addr, core::array::from_mut(&mut buf))?;
            if buf == 0 {
                break;
            }
            if ret.len() == max_length {
                return Err(Error::name_too_long(()));
            }
            addr = Step::forward(addr, 1);
            ret.push(buf);
        }
        let ret = CString::new(ret).unwrap();
        Ok(ret)
    }

    pub fn write_bytes(&self, addr: VirtAddr, bytes: &[u8]) -> Result<()> {
        unsafe { self.write_bytes_volatile(addr, NonNull::from(bytes)) }
    }

    pub unsafe fn write_bytes_volatile(&self, addr: VirtAddr, bytes: NonNull<[u8]>) -> Result<()> {
        if bytes.len() == 0 {
            return Ok(());
        }

        check_user_address(addr, bytes.len())?;

        if unsafe { try_write_user_fast(bytes, addr) }.is_ok() {
            return Ok(());
        }

        self.map_addrs(addr, bytes.len(), PageTableFlags::WRITABLE)?;

        unsafe { try_write_user_fast(bytes, addr) }.unwrap();

        Ok(())
    }

    /// Write a pointee to userspace with the given abi. Returns the amount of
    /// written bytes.
    pub fn write_with_abi<T, P>(
        &self,
        pointer: Pointer<T>,
        value: impl Borrow<T>,
        abi: Abi,
    ) -> Result<usize>
    where
        T: WritablePointee<P> + ?Sized,
    {
        value.borrow().write(pointer.get(), self, abi)
    }

    /// Write a pointee to userspace. Returns the amount of  written bytes.
    pub fn write<T, P>(&self, pointer: Pointer<T>, value: impl Borrow<T>) -> Result<usize>
    where
        T: WritablePointee<P> + AbiAgnosticPointee + ?Sized,
    {
        self.write_with_abi(pointer, value, Abi::Amd64)
    }

    pub fn mprotect(&self, addr: VirtAddr, len: u64, prot: ProtFlags) -> Result<()> {
        if len == 0 {
            return Ok(());
        }

        if !addr.is_aligned(0x1000u64) || len % 0x1000 != 0 {
            return Err(Error::inval(()));
        }

        let state = self.state.read();

        let start = Page::containing_address(addr);
        let end = Page::containing_address(addr + (len - 1));
        for page in start..=end {
            let user_page = state.pages.get(&page).ok_or_else(|| Error::fault(()))?;

            let mut guard = user_page.lock();
            guard.set_perms(MemoryPermissions::from(prot));
            let entry = guard.entry();

            unsafe {
                try_set_page(page, entry);
            }

            drop(guard);
        }

        Ok(())
    }
}

impl Deref for ActiveVirtualMemory<'_, '_> {
    type Target = VirtualMemory;

    fn deref(&self) -> &Self::Target {
        self.virtual_memory
    }
}

pub struct ActiveVirtualMemoryWriteGuard<'a> {
    guard: WriteRwLockGuard<'a, VirtualMemoryState>,
}

impl ActiveVirtualMemoryWriteGuard<'_> {
    fn add_user_page(
        &mut self,
        page: Page,
        mut user_page: UserPage,
        range: impl RangeBounds<usize> + Clone,
    ) -> Result<()> {
        check_user_page(page)?;

        match self.guard.pages.entry(page) {
            Entry::Vacant(entry) => {
                // Zero out the parts of the page outside of `range`.
                user_page.zero_range_inv(range)?;

                entry.insert(Mutex::new(user_page));
            }
            Entry::Occupied(mut entry) => {
                let existing = entry.get_mut().get_mut();

                // Merge the permissions.
                existing.set_perms(existing.perms() | user_page.perms());

                // Merge the content with the existing page.
                if user_page.is_zero_page() {
                    existing.zero_range(range)?;
                } else {
                    try_unmap_user_page(page);

                    existing.make_mut()?;
                    let existing_ptr = existing.index(range.clone());

                    let new_ptr = user_page.index(range);

                    unsafe {
                        core::intrinsics::volatile_copy_nonoverlapping_memory(
                            existing_ptr.as_mut_ptr(),
                            new_ptr.as_mut_ptr(),
                            existing_ptr.len(),
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn mmap(
        &mut self,
        bias: Bias,
        len: u64,
        permissions: MemoryPermissions,
        mut get_page: impl FnMut(usize) -> Result<KernelPage>,
    ) -> Result<VirtAddr> {
        assert_ne!(len, 0);

        let addr = match bias {
            Bias::Fixed(bias) => bias,
            Bias::Dynamic(abi) => self.guard.find_free_address(len, abi),
        };

        let start = addr;
        let end = start + len;
        let start_page = Page::containing_address(start);
        let end_page = Page::containing_address(end - 1);

        for (i, page) in (start_page..=end_page).enumerate() {
            let page_start = page.start_address();
            let page_end = page_start + 0x1000;

            let kernel_page = get_page(i)?;
            let user_page = UserPage::new(kernel_page, permissions);

            let map_start = usize_from(cmp::max(start, page_start) - page_start);
            let map_end = usize_from(cmp::min(end, page_end) - page_start);

            self.add_user_page(page, user_page, map_start..map_end)?;
        }

        Ok(addr)
    }

    pub fn mmap_zero(
        &mut self,
        bias: Bias,
        len: u64,
        permissions: MemoryPermissions,
    ) -> Result<VirtAddr> {
        self.mmap(bias, len, permissions, |_| Ok(KernelPage::zeroed()))
    }

    pub fn mmap_file(
        &mut self,
        bias: Bias,
        len: u64,
        file: &dyn OpenFileDescription,
        offset: u64,
        permissions: MemoryPermissions,
    ) -> Result<VirtAddr> {
        if (offset % 0x1000) != u64::from(bias.page_offset()) {
            return Err(Error::inval(()));
        }
        let page_offset = usize_from(offset / 0x1000);

        self.mmap(bias, len, permissions, |i| file.get_page(page_offset + i))
    }

    pub fn allocate_stack(&mut self, bias: Bias, len: u64) -> Result<VirtAddr> {
        self.mmap_zero(
            bias,
            len,
            MemoryPermissions::READ | MemoryPermissions::WRITE,
        )
    }

    pub fn map_sigreturn_trampoline(&mut self) -> Result<()> {
        static PAGE: Lazy<Mutex<KernelPage>> = Lazy::new(|| {
            let sigreturn_trampoline = &[
                // i386 sigreturn trampoline
                0xb8, 0xad, 0x00, 0x00, 0x00, // mov eax,0xad
                0xcd, 0x80, // int 0x80
                0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // padding
                // amd64 sigreturn trampoline
                0xb8, 0x0f, 0x00, 0x00, 0x00, // mov eax,0xf
                0x0f, 0x05, // syscall
            ];

            let mut page = KernelPage::zeroed();
            page.make_mut().unwrap();
            let ptr = page.index(..sigreturn_trampoline.len());
            unsafe {
                core::ptr::copy_nonoverlapping(
                    sigreturn_trampoline.as_ptr(),
                    ptr.as_mut_ptr(),
                    sigreturn_trampoline.len(),
                );
            }
            Mutex::new(page)
        });

        let user_page = UserPage::new(
            PAGE.lock().clone()?,
            MemoryPermissions::READ | MemoryPermissions::EXECUTE,
        );
        let page = Page::from_start_address(VirtAddr::new(SIGRETURN_TRAMPOLINE_PAGE)).unwrap();
        self.add_user_page(page, user_page, ..)
    }

    pub fn unmap(&mut self, addr: VirtAddr, len: u64) {
        unsafe {
            self.guard.unmap(addr, len);
        }
    }

    pub fn init_brk(&mut self, brk_start: VirtAddr) {
        self.guard.brk_end = brk_start;
    }

    pub fn set_brk_end(&mut self, brk_end: VirtAddr) -> Result<()> {
        let old_brk_end = core::mem::replace(&mut self.guard.brk_end, brk_end);

        match old_brk_end.cmp(&brk_end) {
            Ordering::Less => {
                self.mmap_zero(
                    Bias::Fixed(old_brk_end),
                    brk_end - old_brk_end,
                    MemoryPermissions::WRITE | MemoryPermissions::READ,
                )?;
            }
            Ordering::Equal => {}
            Ordering::Greater => {
                self.unmap(brk_end, old_brk_end - brk_end);
            }
        }

        Ok(())
    }
}

struct VirtualMemoryState {
    pages: BTreeMap<Page, Mutex<UserPage>>,
    brk_end: VirtAddr,
}

impl VirtualMemoryState {
    pub fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            brk_end: VirtAddr::zero(),
        }
    }

    fn find_free_address(&self, size: u64, abi: Abi) -> VirtAddr {
        assert_ne!(size, 0);
        assert!(
            size < (1 << 47),
            "mapping of size {size:#x} can never exist"
        );

        let rdrand = RdRand::new().unwrap();
        let vm_size = match abi {
            Abi::I386 => 31,
            Abi::Amd64 => 47,
        };
        let align_mask = (1 << vm_size as usize) - 1;
        const MAX_ATTEMPTS: usize = 64;
        (0..MAX_ATTEMPTS)
            .find_map(|_| {
                let candidate = rdrand.get_u64()?;
                let candidate = candidate & align_mask;
                let candidate = align_down(candidate, 0x1000);

                let candidate = VirtAddr::new(candidate);

                // Check if there are already pages in the range.
                let start = Page::containing_address(candidate);
                let end = Page::containing_address(candidate + (size - 1));
                if self.pages.range(start..=end).next().is_some() {
                    return None;
                }

                Some(candidate)
            })
            .unwrap()
    }

    /// # Safety
    ///
    /// The virtual memory has to be active.
    unsafe fn unmap(&mut self, addr: VirtAddr, len: u64) {
        // Page align the start.
        let start = addr.align_up(0x1000u64);
        let len = len.saturating_sub(start - addr);

        // Page align the end.
        let len = align_down(len, 0x1000);
        let end = start + len;

        let start_page = Page::from_start_address(start).unwrap();
        let end_page = Page::from_start_address(end).unwrap();
        let pages = start_page..end_page;

        // Flush all pages in the range.
        try_unmap_user_pages(pages.clone());

        loop {
            // Find the next page in the range.
            let Some((&page, _)) = self.pages.range(pages.clone()).next() else {
                break;
            };

            // Remove the page.
            self.pages.remove(&page);
        }
    }
}

bitflags! {
    pub struct MemoryPermissions: u8 {
        const EXECUTE = 1 << 0;
        const WRITE = 1 << 1;
        const READ = 1 << 2;
    }
}

impl From<ProtFlags> for MemoryPermissions {
    fn from(value: ProtFlags) -> Self {
        let mut perms = Self::empty();
        perms.set(Self::EXECUTE, value.contains(ProtFlags::EXEC));
        perms.set(Self::WRITE, value.contains(ProtFlags::WRITE));
        perms.set(Self::READ, value.contains(ProtFlags::READ));
        perms
    }
}

impl From<MemoryPermissions> for PageTableFlags {
    fn from(value: MemoryPermissions) -> Self {
        let mut flags = Self::empty();
        flags.set(Self::EXECUTABLE, value.contains(MemoryPermissions::EXECUTE));
        flags.set(Self::WRITABLE, value.contains(MemoryPermissions::WRITE));
        flags
    }
}

pub fn without_smap<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let rflags = rflags::read();
    let changed = !rflags.contains(RFlags::ALIGNMENT_CHECK);
    if changed {
        unsafe {
            asm!("stac");
        }
    }

    let result = f();

    if changed {
        unsafe {
            asm!("clac");
        }
    }

    result
}

static ALLOCATIONS: Mutex<PcidAllocations> = Mutex::new(PcidAllocations::new());

struct PcidAllocations {
    last_idx: usize,
    in_use: [bool; 4096],
}

impl PcidAllocations {
    const fn new() -> Self {
        Self {
            last_idx: 0,
            in_use: [false; 4096],
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
        INVLPGB.flush_pcid(pcid);

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
        );
    }

    // assert_eq!(failed, 0);

    if failed == 0 {
        Ok(())
    } else {
        Err(())
    }
}

#[inline(always)]
fn check_user_address(addr: VirtAddr, len: usize) -> Result<()> {
    let Some(len_m1) = len.checked_sub(1) else {
        return Ok(());
    };

    // Make sure that even the end is still in the lower half.
    let end_inclusive = Step::forward_checked(addr, len_m1).ok_or_else(|| Error::fault(()))?;
    if end_inclusive.as_u64().get_bit(63) {
        return Err(Error::fault(()));
    }
    Ok(())
}

/// Try to copy user memory from `src` into `dest`.
///
/// This function is not unsafe. If the read fails for some reason `Err(())` is
/// returned. If `src` isn't user memory `Err(())` is returned.
#[inline(always)]
fn try_read_user_fast(src: VirtAddr, dest: NonNull<[u8]>) -> Result<(), ()> {
    if dest.len() == 0 {
        return Ok(());
    }

    check_user_address(src, dest.len()).map_err(|_| ())?;

    without_smap(|| try_read_fast(src, dest))
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
        );
    }
    if failed == 0 {
        Ok(())
    } else {
        Err(())
    }
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
unsafe fn try_write_user_fast(src: NonNull<[u8]>, dest: VirtAddr) -> Result<(), ()> {
    if src.len() == 0 {
        return Ok(());
    }

    // Make sure that even the end is still in the lower half.
    let end_inclusive = Step::forward_checked(dest, src.len() - 1).ok_or(())?;
    if end_inclusive.as_u64().get_bit(63) {
        return Err(());
    }

    without_smap(|| unsafe { try_write_fast(src, dest) })
}

#[derive(Debug, Clone, Copy)]
pub enum Bias {
    Fixed(VirtAddr),
    Dynamic(Abi),
}

impl Bias {
    fn page_offset(&self) -> PageOffset {
        match self {
            Bias::Fixed(bias) => bias.page_offset(),
            Bias::Dynamic(_) => PageOffset::new(0),
        }
    }
}
