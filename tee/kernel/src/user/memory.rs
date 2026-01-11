use alloc::{
    collections::{BTreeMap, btree_map::Entry},
    ffi::CString,
    sync::Arc,
    vec::Vec,
};
use core::{
    borrow::Borrow,
    cell::SyncUnsafeCell,
    cmp::{self, Ordering},
    fmt::{self, Display, Write},
    iter::{Step, repeat_with},
    mem::{MaybeUninit, needs_drop},
    num::{NonZeroU32, NonZeroUsize},
    ops::{Bound, Range, RangeBounds},
    ptr::{NonNull, drop_in_place},
};

use bitflags::bitflags;
use log::debug;
use usize_conversions::{FromUsize, usize_from};
use x86_64::{
    VirtAddr, align_up,
    structures::{
        idt::PageFaultErrorCode,
        paging::{Page, PageOffset, PageSize, Size4KiB},
    },
};

use crate::{
    error::{Error, Result, bail, ensure, err},
    fs::{fd::FileDescriptor, path::Path},
    memory::{
        page::{KernelPage, UserPage},
        pagetable::{PageTableFlags, Pagetables, check_user_address},
    },
    rt::mpsc,
    spin::{
        lazy::Lazy,
        mutex::Mutex,
        rwlock::{RwLock, WriteRwLockGuard},
    },
    user::{
        futex::{FutexScope, Futexes, WaitFuture},
        process::{limits::CurrentAsLimit, usage::MemoryUsage},
        syscall::{
            args::{
                FileType, OpenFlags, Pointer, ProtFlags, Stat,
                pointee::{AbiAgnosticPointee, ReadablePointee, WritablePointee},
            },
            traits::Abi,
        },
    },
};

const SIGRETURN_TRAMPOLINE_PAGE: u64 = 0x7fff_f000;
pub const SIGRETURN_TRAMPOLINE_I386: u64 = SIGRETURN_TRAMPOLINE_PAGE;
pub const SIGRETURN_TRAMPOLINE_AMD64: u64 = SIGRETURN_TRAMPOLINE_PAGE + 0x10;

pub struct VirtualMemory {
    state: RwLock<VirtualMemoryState>,
    mapping_ctrl: MappingCtrl,
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
            let mapping = mapping.get_mut().clone(this.mapping_ctrl.clone())?;
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

    pub fn read_uninit_bytes<'a>(
        &self,
        addr: VirtAddr,
        bytes: &'a mut [MaybeUninit<u8>],
    ) -> Result<&'a mut [u8]> {
        let len = bytes.len();
        let data = NonNull::from(&mut *bytes).cast();
        let ptr = NonNull::slice_from_raw_parts(data, len);
        Ok(unsafe {
            self.read_bytes_volatile(addr, ptr)?;
            bytes.assume_init_mut()
        })
    }

    const ACCESS_RETRIES: usize = 8;

    pub unsafe fn read_bytes_volatile(&self, addr: VirtAddr, bytes: NonNull<[u8]>) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }

        check_user_address(addr, bytes.len())?;

        for _ in 0..Self::ACCESS_RETRIES {
            if self.pagetables.try_read_user_fast(addr, bytes).is_ok() {
                return Ok(());
            }

            self.map_addrs(addr, bytes.len(), PageTableFlags::empty())?;
        }

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
    pub fn read_cstring(&self, pointer: Pointer<CString>, max_len: usize) -> Result<CString> {
        let mut buf = Vec::new();

        loop {
            // Make sure that the string doesn't exceed the maximum length.
            ensure!(buf.len() < max_len, NameTooLong);

            // Allocate some more memory.
            buf.reserve(1);
            let (init, uninit) = buf.split_at_spare_mut();

            // Determine how many bytes to read. Reads are limited by the following:
            // - the remaining capacity
            // - the maximum (remaining) string length
            // - the end of the page
            let current_len = init.len();
            let addr = pointer.get() + u64::from_usize(current_len);
            let page_offset = u16::from(addr.page_offset());
            let remaining_len_in_page =
                usize::from((page_offset + 1).next_multiple_of(0x1000) - page_offset);
            let read_len = cmp::min(uninit.len(), max_len - current_len);
            let read_len = cmp::min(read_len, remaining_len_in_page);
            debug_assert_ne!(read_len, 0);

            // Read more string bytes.
            let bytes = self.read_uninit_bytes(addr, &mut uninit[..read_len])?;

            // Look for a null-byte in the newly read bytes.
            let idx = bytes.iter().position(|&b| b == 0);

            // Update the buffer length.
            let new_len = current_len + read_len;
            unsafe {
                buf.set_len(new_len);
            }

            // If there was a null-byte, then we're done.
            if let Some(idx) = idx {
                // Truncate the string just after the null-byte.
                let cstring_len = current_len + idx + 1;
                buf.truncate(cstring_len);

                let cstr = unsafe { CString::from_vec_with_nul_unchecked(buf) };
                return Ok(cstr);
            }
        }
    }

    pub fn set_bytes(&self, addr: VirtAddr, count: usize, byte: u8) -> Result<()> {
        if count == 0 {
            return Ok(());
        }

        check_user_address(addr, count)?;

        for _ in 0..Self::ACCESS_RETRIES {
            if self
                .pagetables
                .try_set_bytes_user_fast(addr, count, byte)
                .is_ok()
            {
                return Ok(());
            }

            self.map_addrs(addr, count, PageTableFlags::WRITABLE)?;
        }

        self.pagetables
            .try_set_bytes_user_fast(addr, count, byte)
            .unwrap();

        Ok(())
    }

    pub fn write_bytes(&self, addr: VirtAddr, bytes: &[u8]) -> Result<()> {
        unsafe { self.write_bytes_volatile(addr, NonNull::from(bytes)) }
    }

    pub unsafe fn write_bytes_volatile(&self, addr: VirtAddr, bytes: NonNull<[u8]>) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }

        check_user_address(addr, bytes.len())?;

        for _ in 0..Self::ACCESS_RETRIES {
            if self.pagetables.try_write_user_fast(bytes, addr).is_ok() {
                return Ok(());
            }

            self.map_addrs(addr, bytes.len(), PageTableFlags::WRITABLE)?;
        }

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
            let (major, minor, ino, path) = mapping
                .backing
                .as_deref()
                .map_or((0, 0, 0, None), Backing::location);
            write!(maps,"{start:08x}-{end:08x} {permissions}p {offset:05x}000 {major:02x}:{minor:02x} {ino} ").unwrap();
            if let Some((path, deleted)) = path {
                maps.extend_from_slice(path.as_bytes());
                if deleted {
                    maps.extend_from_slice(b" (deleted)");
                }
            }
            maps.push(b'\n');
        }
        maps
    }

    pub fn usage(&self) -> &MemoryUsage {
        &self.usage
    }

    pub fn size(&self) -> usize {
        self.state
            .read()
            .mappings
            .values()
            .map(|mapping| mapping.lock().pages.len())
            .sum::<usize>()
            * 0x1000
    }

    pub fn futex_wait(
        &self,
        uaddr: Pointer<u32>,
        val: u32,
        scope: FutexScope,
        bitset: Option<NonZeroU32>,
    ) -> Result<WaitFuture> {
        let uaddr = uaddr.get();
        ensure!(uaddr.is_aligned(4u64), Inval);
        let page = Page::containing_address(uaddr);

        let state = self.state.read();

        // Find the mapping.
        let (&mapping_page, mapping) = state
            .mappings
            .range(..=page)
            .next_back()
            .ok_or(PageFaultError::Unmapped(err!(Fault)))?;

        let mut guard = mapping.lock();
        let futexes = guard.futexes.clone();

        // Offset into the mapping.
        let offset = page - mapping_page;
        // Offset into the mapping's backing.
        let abs_offset = usize_from(uaddr - (mapping_page - guard.page_offset).start_address());

        // Populate and get the page.
        let user_page = guard.get_page(offset, &self.usage)?;

        // Start the wait operation.
        let wait = futexes.wait(abs_offset, val, scope, bitset, user_page)?;

        // Release all locks.
        drop(guard);
        drop(state);

        Ok(wait)
    }

    pub fn futex_wake(
        &self,
        uaddr: Pointer<u32>,
        num_waiters: u32,
        scope: FutexScope,
        bitset: Option<NonZeroU32>,
    ) -> Result<u32> {
        let uaddr = uaddr.get();
        ensure!(uaddr.is_aligned(4u64), Inval);
        let page = Page::containing_address(uaddr);

        let state = self.state.read();

        // Find the mapping.
        let (&mapping_page, mapping) = state
            .mappings
            .range(..=page)
            .next_back()
            .ok_or(PageFaultError::Unmapped(err!(Fault)))?;

        let guard = mapping.lock();

        // Offset into the mapping's backing.
        let abs_offset = usize_from(uaddr - (mapping_page - guard.page_offset).start_address());

        // Release all locks.
        let futexes = guard.futexes.clone();
        drop(guard);
        drop(state);

        // Wake the futexes.
        Ok(futexes.wake(abs_offset, num_waiters, scope, bitset))
    }
}

impl Default for VirtualMemory {
    fn default() -> Self {
        let (mapping_ctrl, unmap_rx) = MappingCtrl::new();
        Self {
            state: RwLock::new(VirtualMemoryState::new(unmap_rx)),
            mapping_ctrl,
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
    pub fn handle_async_unmap(&mut self) {
        let state = &mut *self.guard;
        for op in state.unmap_rx.try_iter() {
            for (mapping_start, mapping) in state.mappings.iter_mut() {
                let mapping = mapping.get_mut();

                // Check if the flush operation targeted this mapping.
                if mapping
                    .backing
                    .as_ref()
                    .is_none_or(|backing| backing.ino() != op.ino)
                {
                    continue;
                }

                // Make the offsets relative to the page offset of the mapping.
                let start = op.start.saturating_sub(mapping.page_offset);
                let Some(end) = op.end.checked_sub(mapping.page_offset) else {
                    continue;
                };
                let end = cmp::min(end, u64::from_usize(mapping.pages.len()));

                // Remove cached pages from the mapping. This will cause them
                // to be refetched from the underlying file.
                mapping
                    .pages
                    .remove_range(usize_from(start)..usize_from(end + 1));

                // Convert the offsets into virtual addresses.
                let start = *mapping_start + start;
                let end = *mapping_start + end;

                // Flush the pages.
                self.virtual_memory
                    .pagetables
                    .try_unmap_user_pages(start..=end);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mmap(
        &mut self,
        bias: Bias,
        len: u64,
        permissions: MemoryPermissions,
        backing: Option<Arc<dyn Backing>>,
        page_offset: u64,
        shared: bool,
        stack_optimization: bool,
        futexes: Arc<Futexes>,
        as_limit: CurrentAsLimit,
    ) -> Result<VirtAddr> {
        assert_ne!(len, 0);

        let addr = match bias {
            Bias::Fixed(bias) => bias,
            Bias::Dynamic { abi, map_32bit } => {
                self.guard.find_free_address(len, abi, map_32bit)?
            }
        };

        let start = addr;
        let end = start + len;
        let start_page = Page::containing_address(start);
        let end_page = Page::containing_address(end - 1);

        let size = usize_from(end_page - start_page) + 1;
        self.virtual_memory.usage.increase_vmsize(size, as_limit)?;

        self.unmap(addr, len);

        let pages = SparseSplitVec::new(size, stack_optimization);
        if let Some(backing) = backing.as_ref() {
            backing.register(&self.virtual_memory.mapping_ctrl);
        }
        self.guard.mappings.insert(
            start_page,
            Mutex::new(Mapping {
                backing,
                page_offset,
                permissions,
                pages,
                shared,
                futexes,
                mapping_ctrl: self.virtual_memory.mapping_ctrl.clone(),
            }),
        );

        Ok(addr)
    }

    pub fn mmap_private_zero(
        &mut self,
        bias: Bias,
        len: u64,
        permissions: MemoryPermissions,
        as_limit: CurrentAsLimit,
    ) -> Result<VirtAddr> {
        self.mmap(
            bias,
            len,
            permissions,
            None,
            0,
            false,
            false,
            Arc::new(Futexes::new()),
            as_limit,
        )
    }

    pub fn mmap_private_zero_special(
        &mut self,
        bias: Bias,
        len: u64,
        permissions: MemoryPermissions,
        name: &'static str,
        stack_optimization: bool,
        as_limit: CurrentAsLimit,
    ) -> Result<VirtAddr> {
        struct ZeroBacking {
            path: Path,
        }

        impl Backing for ZeroBacking {
            fn get_initial_page(&self, _offset: u64) -> Result<KernelPage> {
                Ok(KernelPage::zeroed())
            }

            fn ino(&self) -> u64 {
                0
            }

            fn location(&self) -> (u16, u8, u64, Option<(Path, bool)>) {
                (0, 0, 0, Some((self.path.clone(), false)))
            }
        }

        let path = alloc::format!("[{name}]");
        let path = Path::new(path.into_bytes()).unwrap();

        self.mmap(
            bias,
            len,
            permissions,
            Some(Arc::new(ZeroBacking { path })),
            0,
            false,
            stack_optimization,
            Arc::new(Futexes::new()),
            as_limit,
        )
    }

    pub fn mmap_shared_zero(
        &mut self,
        bias: Bias,
        len: u64,
        permissions: MemoryPermissions,
        as_limit: CurrentAsLimit,
    ) -> Result<VirtAddr> {
        struct ZeroBacking {
            pages: Mutex<Vec<KernelPage>>,
        }

        impl Backing for ZeroBacking {
            fn get_initial_page(&self, offset: u64) -> Result<KernelPage> {
                let mut pages = self.pages.lock();
                let page = pages.get_mut(usize_from(offset)).ok_or(err!(Acces))?;
                page.make_mut(true)?;
                page.clone()
            }

            fn ino(&self) -> u64 {
                0
            }

            fn location(&self) -> (u16, u8, u64, Option<(Path, bool)>) {
                (0, 0, 0, None)
            }
        }

        let backing = ZeroBacking {
            pages: Mutex::new(
                repeat_with(KernelPage::zeroed)
                    .take(usize_from(len).div_ceil(0x1000))
                    .collect(),
            ),
        };
        let backing = Some(Arc::new(backing) as _);

        self.mmap(
            bias,
            len,
            permissions,
            backing,
            0,
            true,
            false,
            Arc::new(Futexes::new()),
            as_limit,
        )
    }

    #[expect(clippy::too_many_arguments)]
    pub fn mmap_file(
        &mut self,
        bias: Bias,
        len: u64,
        file: FileDescriptor,
        offset: u64,
        permissions: MemoryPermissions,
        shared: bool,
        as_limit: CurrentAsLimit,
    ) -> Result<VirtAddr> {
        self.mmap_file_with_zeros(
            bias,
            len,
            align_up(len, 4096),
            file,
            offset,
            permissions,
            shared,
            false,
            as_limit,
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
        zero_pad: bool,
        as_limit: CurrentAsLimit,
    ) -> Result<VirtAddr> {
        ensure!(offset % 0x1000 == u64::from(bias.page_offset()), Inval);
        let page_offset = offset / 0x1000;

        struct FileBacking {
            file: FileDescriptor,
            zero_offset: u64,
            stat: Stat,
            shared: bool,
            zero_pad: bool,
        }

        impl Backing for FileBacking {
            fn get_initial_page(&self, offset: u64) -> Result<KernelPage> {
                let start_offset = usize_from(self.zero_offset.saturating_sub(offset * 0x1000));
                match start_offset {
                    0 => {
                        ensure!(self.zero_pad, Acces);
                        Ok(KernelPage::zeroed())
                    }
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

            fn ino(&self) -> u64 {
                self.stat.ino
            }

            fn location(&self) -> (u16, u8, u64, Option<(Path, bool)>) {
                let deleted = self.file.deleted();
                let path = self
                    .file
                    .path()
                    .unwrap_or_else(|_| Path::new(b"(inaccessible)".to_vec()).unwrap());
                (
                    self.stat.major(),
                    self.stat.minor(),
                    self.stat.ino,
                    Some((path, deleted)),
                )
            }

            fn register(&self, mapping_ctrl: &MappingCtrl) {
                self.file.register(mapping_ctrl);
            }

            fn unregister(&self, mapping_ctrl: &MappingCtrl) {
                self.file.unregister(mapping_ctrl);
            }
        }

        let flags = file.flags();
        let allowed = if flags.contains(OpenFlags::WRONLY) {
            MemoryPermissions::empty()
        } else if flags.contains(OpenFlags::RDWR) {
            MemoryPermissions::READ | MemoryPermissions::WRITE
        } else {
            // RDONLY
            MemoryPermissions::READ
        };
        if shared {
            ensure!(allowed.contains(permissions), Acces);
        } else {
            ensure!(allowed.contains(MemoryPermissions::READ), Acces);
        }

        let stat = file.stat()?;
        ensure!(stat.mode.ty() == FileType::File, NoDev);
        let futexes = if shared {
            file.futexes().expect("TODO")
        } else {
            Arc::new(Futexes::new())
        };
        self.mmap(
            bias,
            mem_sz,
            permissions,
            Some(Arc::new(FileBacking {
                file,
                zero_offset: offset + file_sz,
                stat,
                shared,
                zero_pad,
            })),
            page_offset,
            shared,
            false,
            futexes,
            as_limit,
        )
    }

    pub fn allocate_stack(
        &mut self,
        bias: Bias,
        len: u64,
        as_limit: CurrentAsLimit,
    ) -> Result<VirtAddr> {
        self.mmap_private_zero_special(
            bias,
            len,
            MemoryPermissions::READ | MemoryPermissions::WRITE,
            "stack",
            true,
            as_limit,
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
                0x48, 0xc7, 0xc0, 0x0f, 0x00, 0x00, 0x00, // mov rax,0xf
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

            fn ino(&self) -> u64 {
                0
            }

            fn location(&self) -> (u16, u8, u64, Option<(Path, bool)>) {
                (
                    0,
                    0,
                    0,
                    Some((Path::new(b"[trampoline]".to_vec()).unwrap(), false)),
                )
            }
        }

        self.mmap(
            Bias::Fixed(VirtAddr::new(SIGRETURN_TRAMPOLINE_PAGE)),
            4096,
            MemoryPermissions::READ | MemoryPermissions::EXECUTE,
            Some(Arc::new(TrampolineCode)),
            0,
            false,
            false,
            Arc::new(Futexes::new()),
            CurrentAsLimit::INFINITE,
        )
        .unwrap();
    }

    /// If any mapping contains `page`, split the mapping at `page`.
    fn shatter_mapping_at(&mut self, page: Page) {
        let mut cursor = self.guard.mappings.upper_bound_mut(Bound::Included(&page));
        let Some((&mapping_start, mapping)) = cursor.peek_prev() else {
            return;
        };
        let mapping = mapping.get_mut();
        let mapping_end = mapping_start + u64::from_usize(mapping.pages.len());

        // If the mapping doesn't contain `page`, nothing needs to be done.
        if mapping_end < page {
            return;
        }

        // If the mapping starts at `page`, nothing needs to be done.
        if mapping_start == page {
            return;
        }

        // If the mapping ends at `page`, nothing needs to be done.
        if mapping_end == page {
            return;
        }

        // Otherwise, the mapping contains `page` and we need to split it.
        let offset = page - mapping_start;
        let new_mapping = mapping.split_off(offset);
        self.guard.mappings.insert(page, Mutex::new(new_mapping));
    }

    /// Checks if the given range is contigously mapped.
    fn check_contigously_mapped(&mut self, address: Page, size: u64) -> Result<()> {
        let mut iter = self.guard.mappings.range_mut(..address + size);

        let (&first_mapping_start, first_mapping) = iter.next_back().ok_or(err!(Fault))?;
        let first_mapping = first_mapping.get_mut();
        let first_mapping_end = first_mapping_start + u64::from_usize(first_mapping.pages.len());
        ensure!(first_mapping_end >= address + size, Fault);

        let mut end = first_mapping_start;
        while end > address {
            let (&mapping_start, mapping) = iter.next_back().ok_or(err!(Fault))?;
            let mapping = mapping.get_mut();
            let mapping_end = mapping_start + u64::from_usize(mapping.pages.len());
            ensure!(mapping_end == end, Fault);
            end = mapping_start;
        }
        Ok(())
    }

    /// Checks if the given range is contigously mapped by a single logical
    /// mapping. This method considers several contigous private anonymous
    /// mappings a single logical mapping. This doesn't apply to shared
    /// mappings or non-private mappings.
    ///
    /// Returns a tuple of the base address of the first and last mappings that
    /// make up the range.
    /// Returns an error if the pages are not logically contigous.
    fn check_contigously_mapped_by_single_type(
        &mut self,
        address: Page,
        size: u64,
    ) -> Result<(Page, Page)> {
        let mut iter = self.guard.mappings.range_mut(..address + size);

        let (&first_mapping_start, first_mapping) = iter.next_back().ok_or(err!(Fault))?;
        let first_mapping = first_mapping.get_mut();
        let first_mapping_end = first_mapping_start + u64::from_usize(first_mapping.pages.len());
        ensure!(first_mapping_end >= address + size, Fault);

        if first_mapping.backing.is_none() {
            // Several contigous anonymous private are treated as a single
            // mapping.
            // The first mapping is anonymous and private, make sure that the
            // others in the range are as well and make sure that the mappings
            // are contigous.
            let mut end = first_mapping_start;
            while end > address {
                let (&mapping_start, mapping) = iter.next_back().ok_or(err!(Fault))?;
                let mapping = mapping.get_mut();
                ensure!(mapping.backing.is_none(), Fault);
                // Check that all the pages have the same protection flags.
                ensure!(mapping.permissions == first_mapping.permissions, Fault);
                let mapping_end = mapping_start + u64::from_usize(mapping.pages.len());
                ensure!(mapping_end == end, Fault);
                end = mapping_start;
            }
            Ok((end, first_mapping_start))
        } else {
            // Make sure that the whole range is covered by the mapping.
            ensure!(first_mapping_start >= address, Fault);
            Ok((first_mapping_start, first_mapping_start))
        }
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
        let inclusive_end_page = Page::containing_address(addr + (len - 1));

        self.check_contigously_mapped(start_page, inclusive_end_page - start_page + 1)?;

        // Flush all pages in the range.
        self.virtual_memory
            .pagetables
            .try_unmap_user_pages(start_page..=inclusive_end_page);

        self.shatter_mapping_at(start_page);
        if let Some(end_page) = Step::forward_checked(inclusive_end_page, 1) {
            self.shatter_mapping_at(end_page);
        }

        for (_, mapping) in self
            .guard
            .mappings
            .range_mut(start_page..=inclusive_end_page)
        {
            mapping.get_mut().set_perms(permissions);
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
        let inclusive_end_page = Page::containing_address(end);

        // Flush all pages in the range.
        self.virtual_memory
            .pagetables
            .try_unmap_user_pages(start_page..=inclusive_end_page);

        self.shatter_mapping_at(start_page);
        if let Some(end_page) = Step::forward_checked(inclusive_end_page, 1) {
            self.shatter_mapping_at(end_page);
        }

        for (_, mapping) in self
            .guard
            .mappings
            .extract_if(start_page..=inclusive_end_page, |_, _| true)
        {
            mapping
                .into_inner()
                .record_unmapping(&self.virtual_memory.usage);
        }
    }

    pub fn shrink(&mut self, old_address: Page, old_size: u64, delta: u64) -> Result<()> {
        self.check_contigously_mapped_by_single_type(old_address, old_size)?;

        // Unmap the later pages.
        self.unmap(
            (old_address + (old_size - delta)).start_address(),
            delta * Size4KiB::SIZE,
        );

        Ok(())
    }

    pub fn grow_in_place(
        &mut self,
        old_address: Page,
        old_size: u64,
        delta: u64,
        as_limit: CurrentAsLimit,
    ) -> Result<()> {
        let (_, last_mapping_start) =
            self.check_contigously_mapped_by_single_type(old_address, old_size)?;

        // Check that there are no mappings starting immediately after the last
        // mapping in the range.
        let old_end_address =
            Step::forward_checked(old_address, usize_from(old_size)).ok_or(err!(Inval))?;
        let new_end_address =
            Step::forward_checked(old_end_address, usize_from(delta)).ok_or(err!(Inval))?;
        ensure!(
            self.guard
                .mappings
                .range(old_end_address..new_end_address)
                .next()
                .is_none(),
            NoMem
        );

        let last_mapping = self.guard.mappings.get_mut(&last_mapping_start).unwrap();
        let last_mapping = last_mapping.get_mut();
        // Make sure that the last mapping ends at `old_address+old_size`.
        ensure!(
            last_mapping_start + u64::from_usize(last_mapping.pages.len()) == old_end_address,
            NoMem
        );

        let delta = usize_from(delta);
        self.virtual_memory.usage.increase_vmsize(delta, as_limit)?;

        // Extend the mapping.
        last_mapping.pages.grow(delta);

        Ok(())
    }

    pub fn remap_somewhere_else(
        &mut self,
        abi: Abi,
        old_address: Page,
        old_size: u64,
        new_size: u64,
        as_limit: CurrentAsLimit,
    ) -> Result<Page> {
        let new_address = self
            .guard
            .find_free_address(new_size * Size4KiB::SIZE, abi, false)?;
        let new_address = Page::from_start_address(new_address).unwrap();
        self.remap_to(old_address, old_size, new_address, new_size, as_limit)?;
        Ok(new_address)
    }

    pub fn remap_to(
        &mut self,
        old_address: Page,
        old_size: u64,
        new_address: Page,
        new_size: u64,
        as_limit: CurrentAsLimit,
    ) -> Result<()> {
        // Make sure the ranges don't overlap.
        ensure!(
            new_address + new_size <= old_address || old_address + old_size <= new_address,
            Inval
        );

        self.check_contigously_mapped_by_single_type(old_address, old_size)?;

        match old_size.cmp(&new_size) {
            Ordering::Less => self
                .virtual_memory
                .usage
                .increase_vmsize(usize_from(new_size - old_size), as_limit)?,
            Ordering::Equal => {}
            Ordering::Greater => self
                .virtual_memory
                .usage
                .decrease_vmsize(usize_from(old_size - new_size)),
        }

        let old_end_address = old_address + old_size;
        let new_end_address = new_address + new_size;

        // Remove the pages from the page tables.
        self.virtual_memory
            .pagetables
            .try_unmap_user_pages(old_address..old_end_address);

        // Remove any other mappings in the new range.
        self.unmap(new_address.start_address(), new_size * Size4KiB::SIZE);

        self.shatter_mapping_at(old_address);
        self.shatter_mapping_at(old_end_address);
        if new_size < old_size {
            self.shatter_mapping_at(old_address + new_size);
        }

        // Move the mappings to the new address.
        let mut addr = old_address;
        while addr < old_end_address {
            let mapping = self.guard.mappings.remove(&addr).unwrap();
            let mut mapping = mapping.into_inner();
            let new_mapping_address = new_address + (addr - old_address);
            addr += u64::from_usize(mapping.pages.len());

            // If the remap operation was also asking for the mapping to be
            // grown, grow the last mapping.
            if addr == old_end_address && old_size < new_size {
                mapping.pages.grow(usize_from(new_size - old_size));
            }

            // Insert the mapping, if it doesn't exceed the size of the new
            // mapping.
            if new_mapping_address < new_end_address {
                self.guard
                    .mappings
                    .insert(new_mapping_address, Mutex::new(mapping));
            }
        }

        Ok(())
    }

    pub fn map_copy(
        &mut self,
        abi: Abi,
        old_address: Page,
        new_size: u64,
        new_address: Option<Page>,
        as_limit: CurrentAsLimit,
    ) -> Result<Page> {
        let new_address = if let Some(new_address) = new_address {
            new_address
        } else {
            let addr = self.guard.find_free_address(new_size, abi, false)?;
            Page::from_start_address(addr).unwrap()
        };

        let mut cursor = self
            .guard
            .mappings
            .upper_bound_mut(Bound::Included(&old_address));

        let (&mapping_start, mapping) = cursor.peek_prev().ok_or(err!(Fault))?;
        let mapping = mapping.get_mut();
        // Make sure that the mapping contains `old_address`.
        let mapping_end = mapping_start + u64::from_usize(mapping.pages.len() - 1);
        ensure!(old_address <= mapping_end, Fault);

        ensure!(mapping.shared, Inval);
        self.virtual_memory
            .usage
            .increase_vmsize(usize_from(new_size), as_limit)?;

        let offset = old_address - mapping_start;
        let mapping = mapping.recreate(offset, new_size);

        self.unmap(new_address.start_address(), new_size * Size4KiB::SIZE);

        self.guard.mappings.insert(new_address, Mutex::new(mapping));

        Ok(new_address)
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
            let (&page, mapping) = cursor.next().ok_or(err!(NoMem))?;
            let mapping = mapping.get_mut();

            ensure!(page <= start_page, NoMem);
            let start_offset = start_page - page;
            ensure!(usize_from(start_offset) <= mapping.pages.len(), NoMem);
            let end_offset = cmp::min(end_page - page, u64::from_usize(mapping.pages.len()));

            mapping.discard_range(start_offset, end_offset, &self.virtual_memory.usage);

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

    pub fn set_brk_end(&mut self, brk_end: VirtAddr, as_limit: CurrentAsLimit) -> Result<()> {
        let old_brk_end = core::mem::replace(&mut self.guard.brk_end, brk_end);

        match old_brk_end.cmp(&brk_end) {
            Ordering::Less => {
                // Check if the range is free.
                if !self.is_free(old_brk_end, brk_end - old_brk_end) {
                    // It's not. Roll back and return an error.
                    self.guard.brk_end = old_brk_end;
                    bail!(NoMem)
                }

                self.mmap_private_zero_special(
                    Bias::Fixed(old_brk_end),
                    brk_end - old_brk_end,
                    MemoryPermissions::WRITE | MemoryPermissions::READ,
                    "heap",
                    false,
                    as_limit,
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
    mappings: BTreeMap<Page, Mutex<Mapping>>,
    brk_end: VirtAddr,
    unmap_rx: mpsc::Receiver<UnmapCommand>,
}

impl VirtualMemoryState {
    pub fn new(unmap_rx: mpsc::Receiver<UnmapCommand>) -> Self {
        Self {
            mappings: BTreeMap::new(),
            brk_end: VirtAddr::zero(),
            unmap_rx,
        }
    }

    fn find_free_address(&mut self, size: u64, abi: Abi, map_32: bool) -> Result<VirtAddr> {
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
            Abi::I386 => 0xf6ff_f000,
            Abi::Amd64 => {
                if map_32 {
                    0x7fff_f000
                } else {
                    0x7fff_6fff_f000
                }
            }
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
            // the base), we found a fitting address.
            if last_address >= mapping_end.start_address() {
                let free = last_address - mapping_end.start_address();
                if free >= size {
                    break;
                }
            }

            last_address = page.start_address();
        }

        ensure!(last_address.as_u64() >= size, NoMem);

        // Add one to skip the guard page at the start.
        Ok(last_address - size + Size4KiB::SIZE)
    }
}

bitflags! {
    #[derive(PartialEq, Eq, Clone, Copy)]
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

#[derive(Debug, Clone, Copy)]
pub enum Bias {
    Fixed(VirtAddr),
    Dynamic { abi: Abi, map_32bit: bool },
}

impl Bias {
    fn page_offset(&self) -> PageOffset {
        match self {
            Self::Fixed(bias) => bias.page_offset(),
            Self::Dynamic { .. } => PageOffset::new(0),
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
    backing: Option<Arc<dyn Backing>>,
    page_offset: u64,
    permissions: MemoryPermissions,
    shared: bool,
    pages: SparseSplitVec<UserPage>,
    futexes: Arc<Futexes>,
    mapping_ctrl: MappingCtrl,
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
            let kernel_page = if let Some(backing) = self.backing.as_ref() {
                backing
                    .get_initial_page(self.page_offset + page_offset)
                    .map_err(PageFaultError::Other)?
            } else {
                KernelPage::zeroed()
            };
            let user_page = UserPage::new(kernel_page, self.permissions, self.shared);
            *page = Some(user_page);

            usage.record_major_page_fault();
            usage.increase_rss();
        }

        Ok(page.as_mut().unwrap())
    }

    pub fn split_off(&mut self, offset: u64) -> Self {
        let pages = self.pages.split_off(usize_from(offset));

        let mapping_ctrl = self.mapping_ctrl.clone();
        if let Some(backing) = self.backing.as_ref() {
            backing.register(&mapping_ctrl);
        }

        Self {
            backing: self.backing.clone(),
            page_offset: self.page_offset + offset,
            permissions: self.permissions,
            pages,
            shared: self.shared,
            futexes: self.futexes.clone(),
            mapping_ctrl,
        }
    }

    fn clone(&mut self, mapping_ctrl: MappingCtrl) -> Result<Self> {
        let mut pages = SparseSplitVec::new(self.pages.len(), self.pages.is_stack_optimized());
        for (i, page) in self.pages.iter_mut() {
            *pages.get_mut(i).unwrap() = Some(page.clone()?);
        }

        let futexes = if self.shared {
            self.futexes.clone()
        } else {
            Arc::new(Futexes::new())
        };

        if let Some(backing) = self.backing.as_ref() {
            backing.register(&mapping_ctrl);
        }

        Ok(Self {
            backing: self.backing.clone(),
            page_offset: self.page_offset,
            permissions: self.permissions,
            pages,
            shared: self.shared,
            futexes,
            mapping_ctrl,
        })
    }

    fn recreate(&mut self, offset: u64, new_size: u64) -> Self {
        debug_assert!(self.shared);
        let backing = self
            .backing
            .as_ref()
            .expect("shared mappings must have a backing");
        backing.register(&self.mapping_ctrl);
        Self {
            backing: self.backing.clone(),
            page_offset: self.page_offset + offset,
            permissions: self.permissions,
            pages: SparseSplitVec::new(usize_from(new_size), self.pages.is_stack_optimized()),
            shared: self.shared,
            futexes: self.futexes.clone(),
            mapping_ctrl: self.mapping_ctrl.clone(),
        }
    }

    fn set_perms(&mut self, permissions: MemoryPermissions) {
        self.permissions = permissions;
        for (_, page) in self.pages.iter_mut() {
            page.set_perms(permissions);
        }
    }

    pub fn discard_range(&mut self, start: u64, end: u64, usage: &MemoryUsage) {
        let removed = self.pages.remove_range(usize_from(start)..usize_from(end));
        usage.decrease_rss(removed);
    }

    pub fn record_unmapping(mut self, usage: &MemoryUsage) {
        let delta = self.pages.iter_mut().count();
        usage.decrease_rss(delta);
        usage.decrease_vmsize(self.pages.len());
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        if let Some(backing) = self.backing.as_ref() {
            backing.unregister(&self.mapping_ctrl);
        }
    }
}

trait Backing: Send + Sync + 'static {
    fn get_initial_page(&self, offset: u64) -> Result<KernelPage>;
    fn ino(&self) -> u64;
    /// Returns a tuple of (major dev, minor dev, ino, (path, deleted)).
    fn location(&self) -> (u16, u8, u64, Option<(Path, bool)>);

    fn register(&self, mapping_ctrl: &MappingCtrl) {
        let _ = mapping_ctrl;
    }
    fn unregister(&self, mapping_ctrl: &MappingCtrl) {
        let _ = mapping_ctrl;
    }
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

    fn from_vec(entries: Vec<T>) -> Self {
        let (ptr, length, capacity) = entries.into_raw_parts();
        let ptr = ptr.cast::<MaybeUninit<SyncUnsafeCell<T>>>();
        let vec = unsafe {
            // SAFETY: `T` and `MaybeUninit<SyncUnsafeCell<T>>` have the same
            // layout.
            Vec::from_raw_parts(ptr, length, capacity)
        };

        let entries = Arc::from(vec);
        Self {
            entries,
            offset: 0,
            len: length,
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

    pub fn grow(&mut self, additional: usize)
    where
        T: Default,
    {
        if additional == 0 {
            return;
        }

        let new_len = self.len + additional;
        let mut entries = Arc::new_uninit_slice(new_len);
        let mut_entries = Arc::get_mut(&mut entries).unwrap();

        // Move the old entries to the new allocation.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.entries.as_ptr().add(self.offset),
                mut_entries.as_mut_ptr(),
                self.len,
            );
        }

        // Default initialize the new entries.
        for entry in mut_entries[self.len..].iter_mut() {
            entry.write(SyncUnsafeCell::new(T::default()));
        }

        self.entries = entries;
        self.len = new_len;
        self.offset = 0;
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

struct StackOptimizedSplitVec<T> {
    entries: Vec<T>,
    len: usize,
}

impl<T> StackOptimizedSplitVec<T> {
    pub const fn new(len: usize) -> Self {
        Self {
            entries: Vec::new(),
            len,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (usize, &'_ mut T)> + '_ {
        (0..self.len).rev().zip(self.entries.iter_mut()).rev()
    }

    pub fn get_mut(&mut self, idx: usize) -> Option<&mut T>
    where
        T: Default,
    {
        let idx = self.len.checked_sub(idx)?.checked_sub(1)?;
        if idx >= self.entries.len() {
            self.entries.resize_with(idx + 1, T::default);
        }
        Some(&mut self.entries[idx])
    }
}

impl<T> From<StackOptimizedSplitVec<T>> for SplitVec<T>
where
    T: Default,
{
    fn from(mut value: StackOptimizedSplitVec<T>) -> Self {
        value.entries.reserve_exact(value.entries.len() - value.len);
        value.entries.resize_with(value.len, T::default);
        value.entries.reverse();
        Self::from_vec(value.entries)
    }
}

/// SparseSplitVec's exceeding this threshold store entries in a BTreeMap
/// instead of a contiguous array. Excessively large mappings can create large
/// arrays, but most entries will always be empty. This wastes a lot of memory.
/// Using a BTreeMap is slower, but way more space efficient.
const SPARSE_THRESHOLD: usize = 8192;

enum SparseSplitVec<T> {
    StackOptimized(StackOptimizedSplitVec<Option<T>>),
    Dense(SplitVec<Option<T>>),
    Sparse {
        entries: BTreeMap<usize, Option<T>>,
        offset: usize,
        len: usize,
    },
}

impl<T> SparseSplitVec<T> {
    pub fn new(len: usize, stack_optimization: bool) -> Self {
        if stack_optimization {
            Self::StackOptimized(StackOptimizedSplitVec::new(len))
        } else if len < SPARSE_THRESHOLD {
            Self::Dense(SplitVec::new(len))
        } else {
            Self::Sparse {
                entries: BTreeMap::new(),
                offset: 0,
                len,
            }
        }
    }

    pub fn len(&self) -> usize {
        match *self {
            Self::StackOptimized(ref stack_optimized) => stack_optimized.len(),
            Self::Dense(ref split_vec) => split_vec.len(),
            Self::Sparse { len, .. } => len,
        }
    }

    pub fn is_stack_optimized(&self) -> bool {
        matches!(self, Self::StackOptimized(..))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (usize, &'_ mut T)> + '_ {
        match *self {
            Self::StackOptimized(ref mut stack_optimized) => OneOfThree::U(
                stack_optimized
                    .iter_mut()
                    .filter_map(|(i, entry)| entry.as_mut().map(|entry| (i, entry))),
            ),
            Self::Dense(ref mut split_vec) => OneOfThree::T(
                split_vec
                    .iter_mut()
                    .enumerate()
                    .filter_map(|(i, entry)| entry.as_mut().map(|entry| (i, entry))),
            ),
            Self::Sparse {
                ref mut entries,
                offset,
                ..
            } => OneOfThree::V(
                entries
                    .iter_mut()
                    .filter_map(|(i, entry)| entry.as_mut().map(|entry| (i, entry)))
                    .map(move |(i, entry)| (i - offset, entry)),
            ),
        }
    }

    pub fn get_mut(&mut self, idx: usize) -> Option<&mut Option<T>> {
        match *self {
            Self::StackOptimized(ref mut split_vec) => split_vec.get_mut(idx),
            Self::Dense(ref mut split_vec) => split_vec.get_mut(idx),
            Self::Sparse {
                ref mut entries,
                offset,
                len,
            } => {
                if idx < len {
                    Some(entries.entry(offset + idx).or_default())
                } else {
                    None
                }
            }
        }
    }

    /// Removes entries in the given range. Returns the number of removed entries.
    pub fn remove_range(&mut self, range: Range<usize>) -> usize {
        match *self {
            Self::StackOptimized(_) => unimplemented!(),
            Self::Dense(ref mut split_vec) => split_vec
                .iter_mut()
                .take(range.end)
                .skip(range.start)
                .filter_map(Option::take)
                .count(),
            Self::Sparse {
                ref mut entries,
                offset,
                ..
            } => {
                let start_len = entries.len();
                let mut cursor = entries.lower_bound_mut(Bound::Excluded(&(range.start + offset)));
                while cursor
                    .peek_next()
                    .is_some_and(|(&idx, _)| idx < range.end + offset)
                {
                    cursor.remove_next();
                }
                start_len - entries.len()
            }
        }
    }

    fn deoptimize_stacks(&mut self) {
        let Self::StackOptimized(stack_optimized) = self else {
            return;
        };

        let stack_optimized = core::mem::replace(stack_optimized, StackOptimizedSplitVec::new(0));
        let split_vec = SplitVec::from(stack_optimized);
        *self = Self::Dense(split_vec);
    }

    pub fn split_off(&mut self, at: usize) -> Self {
        self.deoptimize_stacks();

        match self {
            Self::StackOptimized(..) => unreachable!(),
            Self::Dense(split_vec) => Self::Dense(split_vec.split_off(at)),
            Self::Sparse {
                entries,
                offset,
                len,
            } => {
                // This is a good opportunity to get rid of `None` entries in
                // the map.
                entries.retain(|_, value| value.is_some());

                let new_entries = entries.split_off(&(*offset + at));
                let mut new = Self::Sparse {
                    entries: new_entries,
                    offset: *offset + at,
                    len: *len - at,
                };
                *len = at;

                // Now that the entries have been split in two, there's a
                // chance that either (or both) halves are completely empty. If
                // that's the case, recreate the instance. This gives the
                // halves another chance of being dense instead of sparse.
                if entries.is_empty() {
                    *self = Self::new(*len, false);
                }
                let Self::Sparse {
                    entries: ref new_entries,
                    len: new_len,
                    ..
                } = new
                else {
                    unreachable!();
                };
                if new_entries.is_empty() {
                    new = Self::new(new_len, false);
                }

                new
            }
        }
    }

    pub fn grow(&mut self, additional: usize) {
        self.deoptimize_stacks();

        match self {
            Self::StackOptimized(..) => unreachable!(),
            Self::Dense(split_vec) => split_vec.grow(additional),
            Self::Sparse { len, .. } => *len += additional,
        }
    }
}

enum OneOfThree<T, U, V> {
    T(T),
    U(U),
    V(V),
}

impl<T, U, V> Iterator for OneOfThree<T, U, V>
where
    T: Iterator,
    U: Iterator<Item = T::Item>,
    V: Iterator<Item = T::Item>,
{
    type Item = T::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::T(iter) => iter.next(),
            Self::U(iter) => iter.next(),
            Self::V(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::T(iter) => iter.size_hint(),
            Self::U(iter) => iter.size_hint(),
            Self::V(iter) => iter.size_hint(),
        }
    }

    fn count(self) -> usize
    where
        Self: Sized,
    {
        match self {
            Self::T(iter) => iter.count(),
            Self::U(iter) => iter.count(),
            Self::V(iter) => iter.count(),
        }
    }
}

/// An extension trait for Vec<u8> that makes it possible to use the `write!()`
/// macro on it.
pub trait WriteToVec {
    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result;
}

impl WriteToVec for Vec<u8> {
    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
        struct WriteImpl<'a>(&'a mut Vec<u8>);
        impl Write for WriteImpl<'_> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                self.0.extend_from_slice(s.as_bytes());
                Ok(())
            }
        }
        core::fmt::write(&mut WriteImpl(self), args)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MappingCtrl(mpsc::Sender<UnmapCommand>);

impl MappingCtrl {
    fn new() -> (Self, mpsc::Receiver<UnmapCommand>) {
        let (tx, rx) = mpsc::new();
        (Self(tx), rx)
    }
}

pub struct MappingsCtrl {
    senders: Mutex<BTreeMap<MappingCtrl, NonZeroUsize>>,
}

impl MappingsCtrl {
    pub const fn new() -> Self {
        Self {
            senders: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn register(&self, ctrl: MappingCtrl) {
        let mut guard = self.senders.lock();
        match guard.entry(ctrl) {
            Entry::Vacant(entry) => {
                entry.insert(NonZeroUsize::MIN);
            }
            Entry::Occupied(mut entry) => {
                let new_counter = entry.get().checked_add(1).unwrap();
                *entry.get_mut() = new_counter;
            }
        }
    }

    pub fn unregister(&self, ctrl: MappingCtrl) {
        let mut guard = self.senders.lock();
        match guard.entry(ctrl) {
            Entry::Vacant(_) => unreachable!(),
            Entry::Occupied(mut entry) => {
                if let Some(new_counter) = NonZeroUsize::new(entry.get().get() - 1) {
                    *entry.get_mut() = new_counter;
                } else {
                    entry.remove();
                }
            }
        }
    }

    pub fn unmap(&self, ino: u64, pages: impl RangeBounds<u64>) {
        let start = match pages.start_bound() {
            Bound::Included(idx) => *idx,
            Bound::Excluded(idx) => *idx + 1,
            Bound::Unbounded => 0,
        };
        let end = match pages.end_bound() {
            Bound::Included(idx) => *idx,
            Bound::Excluded(idx) => *idx - 1,
            Bound::Unbounded => !0,
        };

        let mut guard = self.senders.lock();
        guard.retain(|tx, _| tx.0.send(UnmapCommand { ino, start, end }).is_ok());
    }
}

#[derive(Debug, Clone, Copy)]
struct UnmapCommand {
    ino: u64,
    start: u64,
    end: u64,
}
