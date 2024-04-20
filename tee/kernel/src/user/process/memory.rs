use core::{arch::asm, borrow::Borrow, cmp::Ordering, iter::Step, ops::Bound, ptr::NonNull};

use crate::{
    error::{ensure, err},
    fs::fd::FileDescriptor,
    memory::{
        page::{KernelPage, UserPage},
        pagetable::{check_user_address, Pagetables},
    },
    spin::{
        lazy::Lazy,
        mutex::Mutex,
        rwlock::{RwLock, WriteRwLockGuard},
    },
};
use alloc::{collections::BTreeMap, ffi::CString, sync::Arc, vec::Vec};
use bit_field::BitField;
use bitflags::bitflags;
use log::debug;
use usize_conversions::{usize_from, FromUsize};
use x86_64::{
    align_down, align_up,
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
        for (page, mapping) in guard.mappings.iter_mut() {
            let mapping = mapping.get_mut().clone()?;
            new_state.mappings.insert(*page, Mutex::new(mapping));
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
        let (&mapping_page, mapping) = state
            .mappings
            .range(..=page)
            .next_back()
            .ok_or(PageFaultError::Unmapped(err!(Fault)))?;

        let mut guard = mapping.lock();
        let offset = page - mapping_page;
        let user_page = guard.get_page(offset)?;

        // Check whether the page should be mapped at all.
        if !user_page
            .perms()
            .intersects(MemoryPermissions::READ | MemoryPermissions::WRITE)
        {
            return Err(PageFaultError::MissingPermissions(err!(Fault)));
        }

        if required_flags.contains(PageTableFlags::WRITABLE)
            && user_page.perms().contains(MemoryPermissions::WRITE)
        {
            self.pagetables.try_unmap_user_page(page);
            user_page.make_mut().map_err(PageFaultError::Other)?;
        }

        let entry = user_page.entry();

        if !entry.flags().contains(required_flags) {
            return Err(PageFaultError::MissingPermissions(err!(Fault)));
        }

        self.pagetables
            .set_page(page, entry, &mut &FRAME_ALLOCATOR)
            .map_err(PageFaultError::Other)?;

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
            ensure!(ret.len() < max_length, NameTooLong);
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
    fn mmap(
        &mut self,
        bias: Bias,
        len: u64,
        permissions: MemoryPermissions,
        backing: impl Backing,
        page_offset: u64,
    ) -> VirtAddr {
        assert_ne!(len, 0);

        let addr = match bias {
            Bias::Fixed(bias) => bias,
            Bias::Dynamic(abi) => self.guard.find_free_address(len, abi),
        };

        let start = addr;
        let end = start + len;
        let start_page = Page::containing_address(start);
        let end_page = Page::containing_address(end - 1);

        self.unmap(addr, len);

        let size = usize_from(end_page - start_page) + 1;
        let mut pages = Vec::with_capacity(size);
        pages.resize_with(size, || None);
        self.guard.mappings.insert(
            start_page,
            Mutex::new(Mapping {
                backing: Arc::new(backing),
                page_offset,
                permissions,
                pages,
            }),
        );

        addr
    }

    pub fn mmap_zero(&mut self, bias: Bias, len: u64, permissions: MemoryPermissions) -> VirtAddr {
        struct ZeroBacking;

        impl Backing for ZeroBacking {
            fn get_initial_page(&self, _offset: u64) -> Result<KernelPage> {
                Ok(KernelPage::zeroed())
            }
        }

        self.mmap(bias, len, permissions, ZeroBacking, 0)
    }

    pub fn mmap_file(
        &mut self,
        bias: Bias,
        len: u64,
        file: FileDescriptor,
        offset: u64,
        permissions: MemoryPermissions,
    ) -> Result<VirtAddr> {
        self.mmap_file_with_zeros(bias, len, align_up(len, 4096), file, offset, permissions)
    }

    pub fn mmap_file_with_zeros(
        &mut self,
        bias: Bias,
        file_sz: u64,
        mem_sz: u64,
        file: FileDescriptor,
        offset: u64,
        permissions: MemoryPermissions,
    ) -> Result<VirtAddr> {
        ensure!(offset % 0x1000 == u64::from(bias.page_offset()), Inval);
        let page_offset = offset / 0x1000;

        struct FileBacking {
            file: FileDescriptor,
            zero_offset: u64,
        }

        impl Backing for FileBacking {
            fn get_initial_page(&self, offset: u64) -> Result<KernelPage> {
                let start_offset = usize_from(self.zero_offset.saturating_sub(offset * 0x1000));
                match start_offset {
                    0 => Ok(KernelPage::zeroed()),
                    1..=0xfff => {
                        let mut page = self.file.get_page(usize_from(offset))?;
                        page.zero_range(start_offset..)?;
                        Ok(page)
                    }
                    _ => self.file.get_page(usize_from(offset)),
                }
            }
        }

        let addr = self.mmap(
            bias,
            mem_sz,
            permissions,
            FileBacking {
                file,
                zero_offset: offset + file_sz,
            },
            page_offset,
        );
        Ok(addr)
    }

    pub fn allocate_stack(&mut self, bias: Bias, len: u64) -> VirtAddr {
        self.mmap_zero(
            bias,
            len,
            MemoryPermissions::READ | MemoryPermissions::WRITE,
        )
    }

    pub fn map_sigreturn_trampoline(&mut self) {
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

        struct TrampolineCode;

        impl Backing for TrampolineCode {
            fn get_initial_page(&self, offset: u64) -> Result<KernelPage> {
                assert_eq!(offset, 0);
                PAGE.lock().clone()
            }
        }

        self.mmap(
            Bias::Fixed(VirtAddr::new(SIGRETURN_TRAMPOLINE_PAGE)),
            4096,
            MemoryPermissions::READ | MemoryPermissions::EXECUTE,
            TrampolineCode,
            0,
        );
    }

    pub fn mprotect(
        &mut self,
        addr: VirtAddr,
        len: u64,
        permissions: MemoryPermissions,
    ) -> Result<()> {
        if len == 0 {
            return Ok(());
        }

        let start_page = Page::from_start_address(addr).map_err(|_| err!(Inval))?;
        let end_page = Page::from_start_address(addr + (len - 0x1000)).map_err(|_| err!(Inval))?;

        // Flush all pages in the range.
        self.virtual_memory
            .pagetables
            .try_unmap_user_pages(start_page..=end_page);

        let mut cursor = self
            .guard
            .mappings
            .upper_bound_mut(Bound::Included(&start_page));
        cursor.prev();
        while let Some((&page, mapping)) = cursor.next() {
            let mapping = mapping.get_mut();

            let mapping_end = page + u64::from_usize(mapping.pages.len()) - 1;
            if page < start_page {
                ensure!(mapping_end >= start_page, Fault);

                let offset = start_page - page;
                let new_mapping = mapping.split_off(offset);
                cursor
                    .insert_after(start_page, Mutex::new(new_mapping))
                    .unwrap();
                continue;
            } else {
                if page > end_page {
                    break;
                }

                if end_page >= mapping_end {
                    mapping.set_perms(permissions);
                    continue;
                }

                let offset = (end_page - page) + 1;
                let new_mapping = mapping.split_off(offset);
                mapping.set_perms(permissions);
                cursor
                    .insert_before(end_page + 1, Mutex::new(new_mapping))
                    .unwrap();
                break;
            }
        }

        Ok(())
    }

    pub fn unmap(&mut self, addr: VirtAddr, len: u64) {
        if len == 0 {
            return;
        }

        let start = addr;
        let end = addr + (len - 1);
        let start_page = Page::containing_address(start);
        let end_page = Page::containing_address(end);

        // Flush all pages in the range.
        self.virtual_memory
            .pagetables
            .try_unmap_user_pages(start_page..=end_page);

        let mut cursor = self
            .guard
            .mappings
            .upper_bound_mut(Bound::Included(&start_page));
        cursor.prev();
        while let Some((&page, mapping)) = cursor.next() {
            let mapping = mapping.get_mut();

            let mapping_end = page + u64::from_usize(mapping.pages.len() - 1);
            if page < start_page {
                if mapping_end < start_page {
                    break;
                }

                let offset = start_page - page;
                let new_mapping = mapping.split_off(offset);
                cursor
                    .insert_after(start_page, Mutex::new(new_mapping))
                    .unwrap();
                continue;
            } else {
                if page > end_page {
                    break;
                }

                if end_page >= mapping_end {
                    cursor.remove_prev();
                    continue;
                }

                let offset = (end_page - page) + 1;
                let new_mapping = mapping.split_off(offset);
                cursor.remove_prev();
                cursor
                    .insert_before(end_page + 1, Mutex::new(new_mapping))
                    .unwrap();
                break;
            }
        }
    }

    pub fn init_brk(&mut self, brk_start: VirtAddr) {
        self.guard.brk_end = brk_start;
    }

    pub fn set_brk_end(&mut self, brk_end: VirtAddr) {
        let old_brk_end = core::mem::replace(&mut self.guard.brk_end, brk_end);

        match old_brk_end.cmp(&brk_end) {
            Ordering::Less => {
                self.mmap_zero(
                    Bias::Fixed(old_brk_end),
                    brk_end - old_brk_end,
                    MemoryPermissions::WRITE | MemoryPermissions::READ,
                );
            }
            Ordering::Equal => {}
            Ordering::Greater => {
                self.unmap(brk_end, old_brk_end - brk_end);
            }
        }
    }
}

struct VirtualMemoryState {
    mappings: BTreeMap<Page, Mutex<Mapping>>,
    brk_end: VirtAddr,
}

impl VirtualMemoryState {
    pub fn new() -> Self {
        Self {
            mappings: BTreeMap::new(),
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
                let mut cursor = self.mappings.upper_bound(Bound::Included(&start));
                cursor.prev();
                while let Some((&page, mapping)) = cursor.next() {
                    let mapping_end = page + u64::from_usize(mapping.lock().pages.len() - 1);
                    if page <= end && start <= mapping_end {
                        return None;
                    }
                    if page > end {
                        break;
                    }
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

pub struct Mapping {
    backing: Arc<dyn Backing>,
    page_offset: u64,
    permissions: MemoryPermissions,
    pages: Vec<Option<UserPage>>,
}

impl Mapping {
    pub fn get_page(&mut self, page_offset: u64) -> Result<&mut UserPage, PageFaultError> {
        let page = self
            .pages
            .get_mut(usize_from(page_offset))
            .ok_or(PageFaultError::Unmapped(err!(Fault)))?;

        if page.is_none() {
            let user_page = UserPage::new(
                self.backing
                    .get_initial_page(self.page_offset + page_offset)
                    .map_err(PageFaultError::Other)?,
                self.permissions,
            );
            *page = Some(user_page);
        }

        Ok(page.as_mut().unwrap())
    }

    pub fn split_off(&mut self, offset: u64) -> Self {
        let pages = self.pages.split_off(usize_from(offset));

        Self {
            backing: self.backing.clone(),
            page_offset: self.page_offset + offset,
            permissions: self.permissions,
            pages,
        }
    }

    pub fn clone(&mut self) -> Result<Self> {
        let mut pages = Vec::with_capacity(self.pages.len());
        for page in self.pages.iter_mut() {
            if let Some(page) = page {
                pages.push(Some(page.clone()?));
            } else {
                pages.push(None);
            }
        }

        Ok(Self {
            backing: self.backing.clone(),
            page_offset: self.page_offset,
            permissions: self.permissions,
            pages,
        })
    }

    fn set_perms(&mut self, permissions: MemoryPermissions) {
        self.permissions = permissions;
        for page in self.pages.iter_mut().flatten() {
            page.set_perms(permissions);
        }
    }
}

pub trait Backing: Send + Sync + 'static {
    fn get_initial_page(&self, offset: u64) -> Result<KernelPage>;
}
