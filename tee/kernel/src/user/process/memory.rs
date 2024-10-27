use core::{
    arch::asm,
    borrow::Borrow,
    cell::SyncUnsafeCell,
    cmp::{self, Ordering},
    fmt::{self, Display, Write},
    iter::Step,
    mem::{needs_drop, MaybeUninit},
    ops::Bound,
    ptr::{drop_in_place, NonNull},
};

use crate::{
    error::{bail, ensure, err},
    fs::{fd::FileDescriptor, path::Path},
    memory::{
        page::{KernelPage, UserPage},
        pagetable::{check_user_address, Pagetables},
    },
    spin::{
        lazy::Lazy,
        mutex::Mutex,
        rwlock::{RwLock, WriteRwLockGuard},
    },
    user::process::syscall::args::Stat,
};
use alloc::{collections::BTreeMap, ffi::CString, format, sync::Arc, vec::Vec};
use bitflags::bitflags;
use log::debug;
use usize_conversions::{usize_from, FromUsize};
use x86_64::{
    align_up,
    registers::rflags::{self, RFlags},
    structures::{
        idt::PageFaultErrorCode,
        paging::{Page, PageOffset, PageSize, Size4KiB},
    },
    VirtAddr,
};

use crate::{
    error::{Error, Result},
    memory::pagetable::PageTableFlags,
};

use super::{
    syscall::{
        args::{
            pointee::{AbiAgnosticPointee, ReadablePointee, WritablePointee},
            Pointer, ProtFlags,
        },
        traits::Abi,
    },
    usage::MemoryUsage,
};

const SIGRETURN_TRAMPOLINE_PAGE: u64 = 0x7fff_f000;
pub const SIGRETURN_TRAMPOLINE_I386: u64 = SIGRETURN_TRAMPOLINE_PAGE;
pub const SIGRETURN_TRAMPOLINE_AMD64: u64 = SIGRETURN_TRAMPOLINE_PAGE + 0x10;

pub struct VirtualMemory {
    state: RwLock<VirtualMemoryState>,
    pagetables: Pagetables,
    usage: MemoryUsage,
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

        this.usage = self.usage.fork();

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
        self.usage.record_minor_page_fault();

        let state = self.state.read();
        let (&mapping_page, mapping) = state
            .mappings
            .range(..=page)
            .next_back()
            .ok_or(PageFaultError::Unmapped(err!(Fault)))?;

        let mut guard = mapping.lock();
        let offset = page - mapping_page;
        let user_page = guard.get_page(offset, &self.usage)?;

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
            .set_page(page, entry)
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
        if bytes.is_empty() {
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

    /// Read a pointee from userspace and return the amount of bytes read.
    pub fn read_sized<T, P>(&self, pointer: Pointer<T>) -> Result<(usize, T)>
    where
        T: ReadablePointee<P> + AbiAgnosticPointee,
    {
        self.read_sized_with_abi(pointer, Abi::Amd64)
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
        if bytes.is_empty() {
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

    pub fn maps(&self) -> Vec<u8> {
        let mut maps = Vec::new();
        let guard = self.state.read();
        for (&page, mapping) in guard.mappings.iter() {
            let mapping = mapping.lock();
            let start = page.start_address().as_u64();
            let end = (page + u64::from_usize(mapping.pages.len()))
                .start_address()
                .as_u64();
            let permissions = mapping.permissions;
            let offset = mapping.page_offset;
            let (major, minor, ino, path) = mapping.backing.location();
            let line= format!("{start:08x}-{end:08x} {permissions}p {offset:05x}000 {major:02x}:{minor:02x} {ino} ");
            maps.extend_from_slice(line.as_bytes());
            if let Some(path) = path {
                maps.extend_from_slice(path.as_bytes());
            }
            maps.push(b'\n');
        }
        maps
    }

    pub fn usage(&self) -> &MemoryUsage {
        &self.usage
    }
}

impl Default for VirtualMemory {
    fn default() -> Self {
        Self {
            state: RwLock::new(VirtualMemoryState::new()),
            pagetables: Pagetables::new().unwrap(),
            usage: MemoryUsage::default(),
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
        shared: bool,
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
        let pages = SplitVec::new(size);
        self.guard.mappings.insert(
            start_page,
            Mutex::new(Mapping {
                backing: Arc::new(backing),
                page_offset,
                permissions,
                pages,
                shared,
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

            fn location(&self) -> (u16, u8, u64, Option<Path>) {
                (0, 0, 0, None)
            }
        }

        self.mmap(bias, len, permissions, ZeroBacking, 0, false)
    }

    pub fn mmap_file(
        &mut self,
        bias: Bias,
        len: u64,
        file: FileDescriptor,
        offset: u64,
        permissions: MemoryPermissions,
        shared: bool,
    ) -> Result<VirtAddr> {
        self.mmap_file_with_zeros(
            bias,
            len,
            align_up(len, 4096),
            file,
            offset,
            permissions,
            shared,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mmap_file_with_zeros(
        &mut self,
        bias: Bias,
        file_sz: u64,
        mem_sz: u64,
        file: FileDescriptor,
        offset: u64,
        permissions: MemoryPermissions,
        shared: bool,
    ) -> Result<VirtAddr> {
        ensure!(offset % 0x1000 == u64::from(bias.page_offset()), Inval);
        let page_offset = offset / 0x1000;

        struct FileBacking {
            file: FileDescriptor,
            zero_offset: u64,
            stat: Stat,
            shared: bool,
        }

        impl Backing for FileBacking {
            fn get_initial_page(&self, offset: u64) -> Result<KernelPage> {
                let start_offset = usize_from(self.zero_offset.saturating_sub(offset * 0x1000));
                match start_offset {
                    0 => Ok(KernelPage::zeroed()),
                    1..=0xfff => {
                        let mut page = self.file.get_page(usize_from(offset), self.shared)?;
                        if !self.shared {
                            page.zero_range(start_offset.., false)?;
                        }
                        Ok(page)
                    }
                    _ => self.file.get_page(usize_from(offset), self.shared),
                }
            }

            fn location(&self) -> (u16, u8, u64, Option<Path>) {
                let path = self
                    .file
                    .path()
                    .unwrap_or_else(|_| Path::new(b"(inaccessible)".to_vec()).unwrap());
                (
                    self.stat.major(),
                    self.stat.minor(),
                    self.stat.ino,
                    Some(path),
                )
            }
        }

        let stat = file.stat()?;
        let addr = self.mmap(
            bias,
            mem_sz,
            permissions,
            FileBacking {
                file,
                zero_offset: offset + file_sz,
                stat,
                shared,
            },
            page_offset,
            shared,
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
            page.make_mut(false).unwrap();
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

            fn location(&self) -> (u16, u8, u64, Option<Path>) {
                (0, 0, 0, Some(Path::new(b"[trampoline]".to_vec()).unwrap()))
            }
        }

        self.mmap(
            Bias::Fixed(VirtAddr::new(SIGRETURN_TRAMPOLINE_PAGE)),
            4096,
            MemoryPermissions::READ | MemoryPermissions::EXECUTE,
            TrampolineCode,
            0,
            false,
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
        let end_page = Page::containing_address(addr + (len - 1));

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
                    if let Some((_, mapping)) = cursor.remove_prev() {
                        mapping
                            .into_inner()
                            .record_unmapping(&self.virtual_memory.usage)
                    }
                    continue;
                }

                let offset = (end_page - page) + 1;
                let new_mapping = mapping.split_off(offset);
                if let Some((_, mapping)) = cursor.remove_prev() {
                    mapping
                        .into_inner()
                        .record_unmapping(&self.virtual_memory.usage)
                }
                cursor
                    .insert_before(end_page + 1, Mutex::new(new_mapping))
                    .unwrap();
                break;
            }
        }
    }

    pub fn discard_pages(&mut self, address: VirtAddr, len: u64) -> Result<()> {
        let mut start_page = Page::from_start_address(address).map_err(|_| err!(Inval))?;
        let end_page = Page::from_start_address(address + len).map_err(|_| err!(Inval))?;

        // Flush all pages in the range.
        self.virtual_memory
            .pagetables
            .try_unmap_user_pages(start_page..end_page);

        let mut cursor = self
            .guard
            .mappings
            .upper_bound_mut(Bound::Included(&start_page));
        cursor.prev();

        while start_page != end_page {
            let (&page, mapping) = cursor.next().ok_or_else(|| err!(NoMem))?;
            let mapping = mapping.get_mut();

            ensure!(page <= start_page, NoMem);
            let start_offset = start_page - page;
            ensure!(usize_from(start_offset) <= mapping.pages.len(), NoMem);
            let end_offset = cmp::min(end_page - page, u64::from_usize(mapping.pages.len()));

            for offset in start_offset..end_offset {
                mapping.discard_page(offset, &self.virtual_memory.usage)?;
            }

            start_page = page + end_offset;
        }

        Ok(())
    }

    pub fn init_brk(&mut self, brk_start: VirtAddr) {
        self.guard.brk_end = brk_start;
    }

    fn is_free(&mut self, addr: VirtAddr, len: u64) -> bool {
        let Some(len_m1) = len.checked_sub(1) else {
            return true;
        };

        let start_page = Page::containing_address(addr);
        let end_page = Page::containing_address(addr + len_m1);

        let mut cursor = self
            .guard
            .mappings
            .upper_bound_mut(Bound::Included(&end_page));
        let Some((&page, mapping)) = cursor.prev() else {
            return false;
        };
        let mapping = mapping.get_mut();
        let mapping_end = page + u64::from_usize(mapping.pages.len());
        start_page >= mapping_end
    }

    pub fn set_brk_end(&mut self, brk_end: VirtAddr) -> Result<()> {
        let old_brk_end = core::mem::replace(&mut self.guard.brk_end, brk_end);

        match old_brk_end.cmp(&brk_end) {
            Ordering::Less => {
                // Check if the range is free.
                if !self.is_free(old_brk_end, brk_end - old_brk_end) {
                    // It's not. Roll back and return an error.
                    self.guard.brk_end = old_brk_end;
                    bail!(NoMem)
                }

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

        Ok(())
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

    fn find_free_address(&mut self, size: u64, abi: Abi) -> VirtAddr {
        assert_ne!(size, 0);
        assert!(
            size < (1 << 47),
            "mapping of size {size:#x} can never exist"
        );
        let size = align_up(size, Size4KiB::SIZE);

        // We want to add one guard page at before and after the mapping.
        // We do this by increasing the size of the allocation by two pages.
        let size = size + Size4KiB::SIZE * 2;

        let dynamic_base_address = match abi {
            Abi::I386 => 0xff00_0000,
            Abi::Amd64 => 0x7fff_0000_0000,
        };
        let dynamic_base_address = VirtAddr::new(dynamic_base_address);

        // Find the first `address < dynamic_base_address` which can fit `size`.
        let mut cursor = self
            .mappings
            .upper_bound_mut(Bound::Included(&Page::containing_address(
                dynamic_base_address,
            )));
        let mut last_address = dynamic_base_address;
        while let Some((&page, mapping)) = cursor.prev() {
            let mapping = mapping.get_mut();
            let mapping_end = page + u64::from_usize(mapping.pages.len());

            // If `size` fits between this mapping and the previous mapping (or
            // the base), we found an fitting address.
            if last_address >= mapping_end.start_address() {
                let free = last_address - mapping_end.start_address();
                if free >= size {
                    break;
                }
            }

            last_address = page.start_address();
        }

        // Add one to skip the guard page at the start.
        last_address - size + Size4KiB::SIZE
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

impl Display for MemoryPermissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char(if self.contains(Self::READ) { 'r' } else { '-' })?;
        f.write_char(if self.contains(Self::WRITE) { 'w' } else { '-' })?;
        f.write_char(if self.contains(Self::EXECUTE) {
            'x'
        } else {
            '-'
        })
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
    shared: bool,
    pages: SplitVec<Option<UserPage>>,
}

impl Mapping {
    pub fn get_page(
        &mut self,
        page_offset: u64,
        usage: &MemoryUsage,
    ) -> Result<&mut UserPage, PageFaultError> {
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
                self.shared,
            );
            *page = Some(user_page);

            usage.record_major_page_fault();
            usage.increase_rss();
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
            shared: self.shared,
        }
    }

    pub fn clone(&mut self) -> Result<Self> {
        let mut pages = SplitVec::new(self.pages.len());
        for (i, page) in self.pages.iter_mut().enumerate() {
            let Some(page) = page else { continue };
            *pages.get_mut(i).unwrap() = Some(page.clone()?);
        }

        Ok(Self {
            backing: self.backing.clone(),
            page_offset: self.page_offset,
            permissions: self.permissions,
            pages,
            shared: self.shared,
        })
    }

    fn set_perms(&mut self, permissions: MemoryPermissions) {
        self.permissions = permissions;
        for page in self.pages.iter_mut().flatten() {
            page.set_perms(permissions);
        }
    }

    pub fn discard_page(&mut self, page_offset: u64, usage: &MemoryUsage) -> Result<()> {
        let page = self
            .pages
            .get_mut(usize_from(page_offset))
            .ok_or(PageFaultError::Unmapped(err!(Fault)))?;
        if page.is_some() {
            usage.decrease_rss(1);
        }
        page.take();
        Ok(())
    }

    pub fn record_unmapping(mut self, usage: &MemoryUsage) {
        let delta = self.pages.iter_mut().filter(|page| page.is_some()).count();
        usage.decrease_rss(delta);
    }
}

pub trait Backing: Send + Sync + 'static {
    fn get_initial_page(&self, offset: u64) -> Result<KernelPage>;
    /// Returns a tuple of (major dev, minor dev, ino, path).
    fn location(&self) -> (u16, u8, u64, Option<Path>);
}

/// Like a `Vec<T>` but with constant time `split_at`.
struct SplitVec<T> {
    entries: Arc<[MaybeUninit<SyncUnsafeCell<T>>]>,
    offset: usize,
    len: usize,
}

impl<T> SplitVec<T> {
    pub fn new(len: usize) -> Self
    where
        T: Default,
    {
        let mut entries = Arc::new_uninit_slice(len);
        let mut_entries = Arc::get_mut(&mut entries).unwrap();
        for entry in mut_entries {
            entry.write(SyncUnsafeCell::new(T::default()));
        }
        Self {
            entries,
            offset: 0,
            len,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns the entries owned by this instance.
    fn entries(&self) -> &[MaybeUninit<SyncUnsafeCell<T>>] {
        unsafe {
            self.entries
                .get_unchecked(self.offset..)
                .get_unchecked(..self.len)
        }
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &'_ mut T> + '_ {
        self.entries()
            .iter()
            .map(|entry| unsafe { &mut *entry.assume_init_ref().get() })
    }

    pub fn get_mut(&mut self, idx: usize) -> Option<&mut T> {
        self.entries()
            .get(idx)
            .map(|entry| unsafe { &mut *entry.assume_init_ref().get() })
    }

    pub fn split_off(&mut self, at: usize) -> Self {
        assert!(self.len >= at);

        let new = Self {
            entries: self.entries.clone(),
            offset: self.offset + at,
            len: self.len - at,
        };
        self.len = at;
        new
    }
}

impl<T> Drop for SplitVec<T> {
    fn drop(&mut self) {
        if needs_drop::<T>() {
            for entry in self.entries() {
                unsafe {
                    drop_in_place(entry.as_ptr().cast::<T>().cast_mut());
                }
            }
        }
    }
}
