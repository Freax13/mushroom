use core::{
    arch::asm,
    borrow::Borrow,
    cmp::{self, Ordering},
    iter::Step,
    ops::RangeBounds,
    ptr::NonNull,
};

use crate::{
    fs::fd::OpenFileDescription,
    memory::{
        page::{KernelPage, UserPage},
        pagetable::{check_user_address, check_user_page, Pagetables},
    },
    spin::{
        lazy::Lazy,
        mutex::Mutex,
        rwlock::{RwLock, WriteRwLockGuard},
    },
};
use alloc::{
    collections::{btree_map::Entry, BTreeMap},
    ffi::CString,
    vec::Vec,
};
use bit_field::BitField;
use bitflags::bitflags;
use log::debug;
use usize_conversions::{usize_from, FromUsize};
use x86_64::{
    align_down,
    instructions::random::RdRand,
    registers::rflags::{self, RFlags},
    structures::{
        idt::PageFaultErrorCode,
        paging::{Page, PageOffset},
    },
    VirtAddr,
};

use crate::{
    error::{Error, Result},
    memory::{frame::FRAME_ALLOCATOR, pagetable::PageTableFlags},
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

pub struct VirtualMemory {
    state: RwLock<VirtualMemoryState>,
    pagetables: Pagetables,
}

impl VirtualMemory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn run_with<R>(&self, f: impl FnOnce() -> R) -> R {
        self.pagetables.run_with(f)
    }

    pub fn handle_page_fault(
        &self,
        addr: u64,
        error_code: PageFaultErrorCode,
    ) -> Result<(), PageFaultError> {
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

        self.map_page(page, required_flags)
    }

    /// Create a deep copy of the memory.
    pub fn clone(&self) -> Result<Self> {
        let mut this = Self::new();
        let new_state = this.state.get_mut();

        let mut guard = self.state.write();
        new_state.brk_end = guard.brk_end;

        // Prevent userspace from writing to memory.
        self.pagetables.freeze_userspace();

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

    pub fn modify(&self) -> VirtualMemoryWriteGuard<'_> {
        VirtualMemoryWriteGuard {
            guard: self.state.write(),
            virtual_memory: self,
        }
    }

    pub fn map_page(
        &self,
        page: Page,
        required_flags: PageTableFlags,
    ) -> Result<(), PageFaultError> {
        let state = self.state.read();
        let user_page = state
            .pages
            .get(&page)
            .ok_or_else(|| PageFaultError::Unmapped(Error::fault(())))?;

        let mut guard = user_page.lock();

        // Check whether the page should be mapped at all.
        if !guard
            .perms()
            .intersects(MemoryPermissions::READ | MemoryPermissions::WRITE)
        {
            return Err(PageFaultError::MissingPermissions(Error::fault(())));
        }

        if required_flags.contains(PageTableFlags::WRITABLE)
            && guard.perms().contains(MemoryPermissions::WRITE)
        {
            self.pagetables.try_unmap_user_page(page);
            guard.make_mut().map_err(PageFaultError::Other)?;
        }

        let entry = guard.entry();

        if !entry.flags().contains(required_flags) {
            return Err(PageFaultError::MissingPermissions(Error::fault(())));
        }

        self.pagetables
            .set_page(page, entry, &mut &FRAME_ALLOCATOR)
            .map_err(PageFaultError::Other)?;

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

        if self.pagetables.try_read_user_fast(addr, bytes).is_ok() {
            return Ok(());
        }

        self.map_addrs(addr, bytes.len(), PageTableFlags::empty())?;

        self.pagetables.try_read_user_fast(addr, bytes).unwrap();

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

        if self.pagetables.try_write_user_fast(bytes, addr).is_ok() {
            return Ok(());
        }

        self.map_addrs(addr, bytes.len(), PageTableFlags::WRITABLE)?;

        self.pagetables.try_write_user_fast(bytes, addr).unwrap();

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

            if guard
                .perms()
                .intersects(MemoryPermissions::READ | MemoryPermissions::WRITE)
            {
                let entry = guard.entry();

                self.pagetables.try_set_page(page, entry)?;
            } else {
                self.pagetables.try_unmap_user_page(page);
            }

            drop(guard);
        }

        Ok(())
    }
}

impl Default for VirtualMemory {
    fn default() -> Self {
        Self {
            state: RwLock::new(VirtualMemoryState::new()),
            pagetables: Pagetables::new().unwrap(),
        }
    }
}

impl Drop for VirtualMemory {
    fn drop(&mut self) {
        self.modify().unmap(VirtAddr::new(0), !0);
    }
}

pub struct VirtualMemoryWriteGuard<'a> {
    guard: WriteRwLockGuard<'a, VirtualMemoryState>,
    virtual_memory: &'a VirtualMemory,
}

impl VirtualMemoryWriteGuard<'_> {
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
                    self.virtual_memory.pagetables.try_unmap_user_page(page);

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
        self.virtual_memory
            .pagetables
            .try_unmap_user_pages(pages.clone());

        loop {
            // Find the next page in the range.
            let Some((&page, _)) = self.guard.pages.range(pages.clone()).next() else {
                break;
            };

            // Remove the page.
            self.guard.pages.remove(&page);
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
                let end = Step::forward_checked(candidate, usize_from(size - 1))?;
                if end.as_u64().get_bit(47) {
                    return None;
                }

                // Check if there are already pages in the range.
                let start = Page::containing_address(candidate);
                let end = Page::containing_address(end);
                if self.pages.range(start..=end).next().is_some() {
                    return None;
                }

                Some(candidate)
            })
            .unwrap()
    }
}

bitflags! {
    #[derive(Clone, Copy)]
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

pub enum PageFaultError {
    Unmapped(Error),
    MissingPermissions(Error),
    Other(Error),
}

impl From<PageFaultError> for Error {
    fn from(value: PageFaultError) -> Self {
        let (PageFaultError::Unmapped(error)
        | PageFaultError::MissingPermissions(error)
        | PageFaultError::Other(error)) = value;
        error
    }
}
