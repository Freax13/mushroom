use core::{
    arch::asm,
    borrow::Borrow,
    cmp,
    intrinsics::volatile_copy_nonoverlapping_memory,
    iter::Step,
    ops::Deref,
};

use crate::spin::{lazy::Lazy, mutex::Mutex};
use alloc::{borrow::Cow, boxed::Box, ffi::CString, sync::Arc, vec::Vec};
use bitflags::bitflags;
use crossbeam_queue::SegQueue;
use log::debug;
use x86_64::{
    align_down,
    instructions::{
        interrupts::without_interrupts,
        random::RdRand,
        tlb::{Invlpgb, Pcid},
    },
    registers::{
        control::{Cr0, Cr0Flags, Cr3},
        rflags::{self, RFlags},
    },
    structures::{
        idt::PageFaultErrorCode,
        paging::{FrameAllocator, FrameDeallocator, Page, PhysFrame, Size4KiB},
    },
    VirtAddr,
};

use crate::{
    error::{Error, Result},
    fs::node::FileSnapshot,
    memory::{
        frame::FRAME_ALLOCATOR,
        pagetable::{
            add_flags, allocate_pml4, entry_for_page, find_dirty_userspace_pages, map_page,
            remap_page, remove_flags, unmap_page, PageTableFlags, PresentPageTableEntry,
        },
        temporary::{copy_into_frame, zero_frame},
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
        let (prev_pml4, prev_pcid) = Cr3::read_pcid();

        // Switch the page tables.
        unsafe {
            Cr3::write_pcid(virtual_memory.pml4, virtual_memory.pcid_allocation.pcid);
        }
        let mut active_virtual_memory = ActiveVirtualMemory {
            activator: self,
            virtual_memory,
        };

        // Run the closure.
        let res = f(&mut active_virtual_memory);

        // Restore the page tables.
        unsafe {
            Cr3::write_pcid(prev_pml4, prev_pcid);
        }

        res
    }
}

pub struct VirtualMemory {
    state: Mutex<VirtualMemoryState>,
    pml4: PhysFrame,
    pcid_allocation: PcidAllocation,
}

impl VirtualMemory {
    pub fn new() -> Self {
        Self::default()
    }

    /// # Safety
    ///
    /// The virtual memory must be active.
    pub unsafe fn handle_page_fault(
        &self,
        addr: u64,
        error_code: PageFaultErrorCode,
        rip: VirtAddr,
    ) {
        let addr = VirtAddr::new(addr);
        let page = Page::containing_address(addr);

        debug!(target: "kernel::exception", "{addr:?} {error_code:?}");

        let state = self.state.lock();
        let state = state.initialized();

        let mapping_opt = state.mappings.iter().find(|mapping| mapping.contains(addr));
        let Some(mapping) = mapping_opt else {
            panic!("page fault: {addr:#x} at {rip:?}");
        };

        // Ensure that the page is mapped.
        unsafe {
            mapping.make_readable(page).unwrap();
        }
        // Ensure that the page has the permissions requested in the error code.
        if error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
            unsafe {
                mapping.make_writable(page).unwrap();
            }
        }
        if error_code.contains(PageFaultErrorCode::INSTRUCTION_FETCH) {
            unsafe {
                mapping.make_executable(page).unwrap();
            }
        }
    }

    /// Create a deep copy of the memory.
    pub fn clone(&self, vm_activator: &mut VirtualMemoryActivator) -> Result<Self> {
        let mut this = Self::new();
        *this.state.get_mut() = self.state.lock().clone();

        vm_activator.activate(self, |vm| {
            vm.find_dirty_userspace_pages(|page, content, vm_activator| {
                vm_activator.activate(&this, |vm| vm.force_write(page, content))
            })
        })?;

        Ok(this)
    }
}

impl Default for VirtualMemory {
    fn default() -> Self {
        let pcid_allocation = ALLOCATIONS.lock().allocate();

        let pml4 = allocate_pml4().unwrap();

        Self {
            state: Mutex::new(VirtualMemoryState::new()),
            pml4,
            pcid_allocation,
        }
    }
}

pub struct ActiveVirtualMemory<'a, 'b> {
    activator: &'a mut VirtualMemoryActivator,
    virtual_memory: &'b VirtualMemory,
}

impl<'a, 'b> ActiveVirtualMemory<'a, 'b> {
    pub fn vm_activator(&mut self) -> &mut VirtualMemoryActivator {
        self.activator
    }

    pub fn init(&mut self, vm_size: VmSize) {
        self.state.lock().init(vm_size)
    }

    pub fn read_bytes(&self, addr: VirtAddr, bytes: &mut [u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }

        let state = self.state.lock();
        let state = state.initialized();

        let start = addr;
        let end_inclusive = addr + (bytes.len() - 1);

        let start_page = Page::<Size4KiB>::containing_address(start);
        let end_inclusive_page = Page::<Size4KiB>::containing_address(end_inclusive);

        for page in Page::range_inclusive(start_page, end_inclusive_page) {
            let copy_start = cmp::max(page.start_address(), start);
            let copy_end_inclusive = cmp::min(page.start_address() + 0xfffu64, end_inclusive);

            let mapping = state
                .mappings
                .iter()
                .find(|mapping| mapping.contains_page(page))
                .ok_or(Error::fault(()))?;
            let ptr = unsafe { mapping.make_readable(page)? };

            let src_offset = usize::try_from(copy_start - addr).unwrap();

            let copy_start_offset = usize::from(copy_start.page_offset());
            let copy_end_inclusive_offset = usize::from(copy_end_inclusive.page_offset());
            let len = copy_end_inclusive_offset - copy_start_offset + 1;

            without_smap(|| unsafe {
                core::intrinsics::volatile_copy_nonoverlapping_memory(
                    bytes.as_mut_ptr().add(src_offset),
                    ptr.cast::<u8>().add(copy_start_offset),
                    len,
                );
            });
        }

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
        if bytes.is_empty() {
            return Ok(());
        }

        let state = self.state.lock();
        let state = state.initialized();

        let start = addr;
        let end_inclusive = addr + (bytes.len() - 1);

        let start_page = Page::<Size4KiB>::containing_address(start);
        let end_inclusive_page = Page::<Size4KiB>::containing_address(end_inclusive);

        for page in Page::range_inclusive(start_page, end_inclusive_page) {
            let copy_start = cmp::max(page.start_address(), start);
            let copy_end_inclusive = cmp::min(page.start_address() + 0xfffu64, end_inclusive);

            let mapping = state
                .mappings
                .iter()
                .find(|mapping| mapping.contains_page(page))
                .ok_or(Error::fault(()))?;
            let ptr = unsafe { mapping.make_writable(page)? };

            let src_offset = usize::try_from(copy_start - addr).unwrap();

            let copy_start_offset = usize::from(copy_start.page_offset());
            let copy_end_inclusive_offset = usize::from(copy_end_inclusive.page_offset());
            let len = copy_end_inclusive_offset - copy_start_offset + 1;

            without_smap(|| unsafe {
                let dst = ptr.cast::<u8>().add(copy_start_offset);
                let src = bytes.as_ptr().add(src_offset);
                core::intrinsics::volatile_copy_nonoverlapping_memory(dst, src, len);
            });
        }

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

    pub fn force_write(&self, page: Page, bytes: &[u8; 0x1000]) -> Result<()> {
        let mut state = self.state.lock();
        let state = state.initialized_mut();

        let mapping = state
            .mappings
            .iter_mut()
            .find(|mapping| mapping.contains_page(page))
            .ok_or(Error::fault(()))?;

        let writeable = mapping.permissions.contains(MemoryPermissions::WRITE);
        if !writeable {
            mapping.permissions |= MemoryPermissions::WRITE;
        }

        let ptr = unsafe { mapping.make_writable(page)? };

        without_smap(|| unsafe {
            let dst = ptr.cast::<u8>();
            let src = bytes.as_ptr();
            core::intrinsics::volatile_copy_nonoverlapping_memory(dst, src, bytes.len());
        });

        if !writeable {
            mapping.permissions.remove(MemoryPermissions::WRITE);
            unsafe {
                remove_flags(page, PageTableFlags::WRITABLE);
            }
        }

        Ok(())
    }

    pub fn mprotect(&self, addr: VirtAddr, len: u64, prot: ProtFlags) -> Result<()> {
        if len == 0 {
            return Ok(());
        }

        if !addr.is_aligned(0x1000u64) || len % 0x1000 != 0 {
            return Err(Error::inval(()));
        }
        let addr = Page::from_start_address(addr).unwrap();
        let num_pages = len / 4096;

        let mut state = self.state.lock();
        let state = state.initialized_mut();

        loop {
            let mapping = state
                .mappings
                .iter_mut()
                .filter(|m| m.contains_page_range(addr, num_pages))
                .min_by_key(|m| m.start)
                .ok_or(Error::fault(()))?;

            let new_page = cmp::max(addr, mapping.start);
            let len = num_pages - (new_page - addr);
            let addr = new_page;

            let start_offset = addr - mapping.start;
            if start_offset > 0 {
                let mut new_mapping = mapping.split(start_offset);
                let new_permissions = MemoryPermissions::from(prot);
                let old_permissions =
                    core::mem::replace(&mut new_mapping.permissions, new_permissions);

                // Check if permissions have been removed.
                let removed_permissions = !new_permissions & old_permissions;
                let flags = PageTableFlags::from(removed_permissions);
                if !flags.is_empty() {
                    let start = new_mapping.start;
                    let end_inclusive = new_mapping.end();
                    for page in start..end_inclusive {
                        unsafe {
                            remove_flags(page, flags);
                        }
                    }
                }

                state.mappings.push(new_mapping);

                continue;
            }

            let new_mapping = if mapping.num_pages > len {
                Some(mapping.split(len))
            } else {
                None
            };

            let new_permissions = MemoryPermissions::from(prot);
            let old_permissions = core::mem::replace(&mut mapping.permissions, new_permissions);

            // Check if permissions have been removed.
            let removed_permissions = !new_permissions & old_permissions;
            let flags = PageTableFlags::from(removed_permissions);
            if !flags.is_empty() {
                let start = mapping.start;
                let end_inclusive = mapping.end() - 1u64;
                for page in start..=end_inclusive {
                    unsafe {
                        remove_flags(page, flags);
                    }
                }
            }

            if let Some(new_mapping) = new_mapping {
                state.mappings.push(new_mapping);
            }

            break;
        }

        Ok(())
    }

    pub fn allocate_stack(&self, addr: Option<VirtAddr>, len: u64) -> Result<VirtAddr> {
        let addr = self.add_mapping(
            addr,
            len,
            MemoryPermissions::READ | MemoryPermissions::WRITE,
            Backing::Stack,
        )?;
        Ok(addr)
    }

    pub fn mmap_into(
        &self,
        addr: Option<VirtAddr>,
        len: u64,
        offset: u64,
        bytes: FileSnapshot,
        permissions: MemoryPermissions,
    ) -> Result<VirtAddr> {
        self.add_mapping(
            addr,
            len,
            permissions,
            Backing::File(FileBacking { offset, bytes }),
        )
    }

    pub fn mmap_zero(
        &self,
        addr: Option<VirtAddr>,
        len: u64,
        permissions: MemoryPermissions,
    ) -> Result<VirtAddr> {
        self.add_mapping(addr, len, permissions, Backing::Zero)
    }

    fn add_mapping(
        &self,
        addr: Option<VirtAddr>,
        len: u64,
        permissions: MemoryPermissions,
        backing: Backing,
    ) -> Result<VirtAddr> {
        assert!(len < (1 << 47), "mapping of size {len:#x} can never exist");

        let mut state = self.state.lock();
        let state = state.initialized_mut();

        state.add_mapping(addr, len, permissions, backing)
    }

    pub fn unmap(&mut self, addr: VirtAddr, len: u64) {
        let mut state = self.state.lock();
        let state = state.initialized_mut();
        state.unmap(addr, len)
    }

    pub fn find_dirty_userspace_pages(
        &mut self,
        mut f: impl FnMut(Page, &[u8; 0x1000], &mut VirtualMemoryActivator) -> Result<()>,
    ) -> Result<()> {
        unsafe {
            find_dirty_userspace_pages(|page| {
                let bytes = &mut [0; 0x1000];
                let addr = page.start_address();
                self.read_bytes(addr, bytes)?;
                f(page, bytes, self.vm_activator())
            })
        }
    }

    pub fn brk_end(&mut self) -> Result<VirtAddr> {
        self.state.lock().initialized_mut().brk_end()
    }

    pub fn set_brk_end(&mut self, brk_end: u64) -> Result<VirtAddr> {
        self.state.lock().initialized_mut().set_brk_end(brk_end)
    }
}

impl Deref for ActiveVirtualMemory<'_, '_> {
    type Target = VirtualMemory;

    fn deref(&self) -> &Self::Target {
        self.virtual_memory
    }
}

#[derive(Clone)]
enum VirtualMemoryState {
    Uninitialized,
    Initialized(InitializedVirtualMemoryState),
}

#[derive(Clone)]
struct InitializedVirtualMemoryState {
    vm_size: VmSize,
    mappings: Vec<Mapping>,
    brk: Option<Brk>,
}

impl VirtualMemoryState {
    pub fn new() -> Self {
        Self::Uninitialized
    }

    pub fn init(&mut self, vm_size: VmSize) {
        assert!(matches!(self, Self::Uninitialized));
        *self = Self::Initialized(InitializedVirtualMemoryState {
            vm_size,
            mappings: Vec::new(),
            brk: None,
        });
    }

    pub fn initialized(&self) -> &InitializedVirtualMemoryState {
        match self {
            VirtualMemoryState::Uninitialized => {
                panic!("virtual memory state hasn't been initialized")
            }
            VirtualMemoryState::Initialized(i) => i,
        }
    }

    pub fn initialized_mut(&mut self) -> &mut InitializedVirtualMemoryState {
        match self {
            VirtualMemoryState::Uninitialized => {
                panic!("virtual memory state hasn't been initialized")
            }
            VirtualMemoryState::Initialized(i) => i,
        }
    }
}

impl InitializedVirtualMemoryState {
    fn find_free_address(&self, size: u64) -> VirtAddr {
        assert!(
            size < (1 << 47),
            "mapping of size {size:#x} can never exist"
        );

        let rdrand = RdRand::new().unwrap();
        const MAX_ATTEMPTS: usize = 64;
        (0..MAX_ATTEMPTS)
            .find_map(|_| {
                let candidate = rdrand.get_u64()?;
                let candidate = candidate & ((1 << self.vm_size as usize) - 1);
                let candidate = align_down(candidate, 0x1000);

                let candidate = VirtAddr::new(candidate);

                if self
                    .mappings
                    .iter()
                    .any(|m| m.contains_range(candidate, size))
                {
                    return None;
                }

                Some(candidate)
            })
            .unwrap()
    }

    fn add_mapping(
        &mut self,
        addr: Option<VirtAddr>,
        len: u64,
        permissions: MemoryPermissions,
        mut backing: Backing,
    ) -> Result<VirtAddr> {
        assert!(len < (1 << 47), "mapping of size {len:#x} can never exist");

        let addr = addr.unwrap_or_else(|| self.find_free_address(len));
        let end = addr + len;

        debug!(
            "adding mapping {:?}-{:?} {:?}",
            addr,
            addr + len,
            permissions
        );

        self.unmap(addr, len);

        // If the mapping isn't page aligned, immediately map pages for the unaligned start and end.
        match (addr.is_aligned(0x1000u64), end.is_aligned(0x1000u64)) {
            (false, false) => {
                let start_page: Page = Page::containing_address(addr);
                let end_page: Page = Page::containing_address(end);
                if start_page == end_page {
                    self.map_unaligned(addr, len, &backing, 0, permissions)?;
                } else {
                    let unaligned_len = 0x1000 - (addr.as_u64() % 0x1000);
                    self.map_unaligned(addr, unaligned_len, &backing, 0, permissions)?;

                    let unaligned_len = end.as_u64() % 0x1000;
                    self.map_unaligned(
                        end - unaligned_len,
                        unaligned_len,
                        &backing,
                        len - unaligned_len,
                        permissions,
                    )?;
                }
            }
            (false, true) => {
                let unaligned_len = 0x1000 - (addr.as_u64() % 0x1000);
                self.map_unaligned(addr, unaligned_len, &backing, 0, permissions)?;
            }
            (true, false) => {
                let unaligned_len = end.as_u64() % 0x1000;
                self.map_unaligned(
                    end - unaligned_len,
                    unaligned_len,
                    &backing,
                    len - unaligned_len,
                    permissions,
                )?;
            }
            (true, true) => {}
        }

        let start_page = Page::containing_address(addr.align_up(0x1000u64));
        let end_page = Page::containing_address(end);
        if end_page > start_page {
            let num_pages = end_page - start_page;
            let backing = if addr.is_aligned(0x1000u64) {
                backing
            } else {
                let unaligned_len = 0x1000 - (addr.as_u64() % 0x1000);
                backing.split(unaligned_len)
            };

            let mapping = Mapping {
                start: start_page,
                num_pages,
                permissions,
                backing,
            };

            self.mappings.push(mapping);
        }

        Ok(addr)
    }

    fn map_unaligned(
        &mut self,
        start: VirtAddr,
        len: u64,
        backing: &Backing,
        offset: u64,
        permissions: MemoryPermissions,
    ) -> Result<()> {
        assert!(len <= 0x1000);
        let end = start + len;
        let page = Page::containing_address(start);
        assert_eq!(page, Page::containing_address(end - 1u64));

        // Collect the unaligned part into a buffer.
        let mut buffer = [0; 0x1000];
        let start_idx = start.as_u64() as usize % 0x1000;
        let end_idx = end.as_u64() as usize % 0x1000;
        let end_idx = if end_idx == 0 { 0x1000 } else { end_idx };
        let buffer = &mut buffer[start_idx..end_idx];
        backing.copy_initial_memory_to_slice(offset, buffer);

        if let Some(existing_mapping) = self.mappings.iter_mut().find(|m| m.contains_page(page)) {
            let mapping = if existing_mapping.num_pages > 1 {
                let mapping = existing_mapping.split(existing_mapping.num_pages - 1);
                self.mappings.push(mapping);
                self.mappings.last_mut().unwrap()
            } else {
                existing_mapping
            };

            mapping.permissions |= permissions;

            unsafe {
                mapping.remove_cow(page)?;
            }
        } else {
            let mapping = Mapping {
                start: page,
                num_pages: 1,
                permissions,
                backing: Backing::Zero,
            };
            unsafe {
                mapping.remove_cow(page)?;
            }
            self.mappings.push(mapping);
        }

        without_smap(|| {
            without_write_protect(|| unsafe {
                volatile_copy_nonoverlapping_memory(
                    start.as_mut_ptr(),
                    buffer.as_ptr(),
                    buffer.len(),
                );
            })
        });

        Ok(())
    }

    fn unmap(&mut self, addr: VirtAddr, len: u64) {
        // Page align the start.
        let start = addr.align_up(0x1000u64);
        let len = len.saturating_sub(start - addr);
        // Page align the end.
        let len = align_down(len, 0x1000);

        let end = start + len;
        let start = Page::containing_address(start);
        let end = Page::containing_address(end);
        if start == end {
            return;
        }

        debug!("unmapping {addr:?}-{end:?}");

        let mut i = 0;
        while let Some(mapping) = self.mappings.get_mut(i) {
            if !mapping.contains_page_range(start, end - start) {
                i += 1;
                continue;
            }

            if mapping.start >= start && mapping.start + mapping.num_pages <= end {
                for page in mapping.start..mapping.end() {
                    if entry_for_page(page).is_some() {
                        unsafe {
                            unmap_page(page);
                        }
                    }
                }
                self.mappings.swap_remove(i);
                continue;
            }

            if start > mapping.start {
                let offset = start - mapping.start;
                let new_mapping = mapping.split(offset);
                self.mappings.push(new_mapping);
                continue;
            }

            if mapping.end() > end {
                let offset = end - mapping.start;
                let new_mapping = mapping.split(offset);
                self.mappings.push(new_mapping);
                continue;
            }

            unreachable!()
        }
    }

    fn brk_mut(&mut self) -> Result<&mut Brk> {
        if self.brk.is_none() {
            let len = 0x1000;
            let start = self.add_mapping(
                None,
                len,
                MemoryPermissions::READ | MemoryPermissions::WRITE,
                Backing::Zero,
            )?;

            let brk = Brk {
                _start: start,
                end: start + len,
            };
            self.brk = Some(brk);
        }

        Ok(self.brk.as_mut().unwrap())
    }

    pub fn brk_end(&mut self) -> Result<VirtAddr> {
        self.brk_mut().map(|brk| brk.end)
    }

    pub fn set_brk_end(&mut self, brk_end: u64) -> Result<VirtAddr> {
        let brk = self.brk_mut()?;
        let prev_end = brk.end;

        if let Some(grow) = brk_end
            .checked_sub(brk.end.as_u64())
            .filter(|&len| len != 0)
        {
            self.add_mapping(
                Some(prev_end),
                grow,
                MemoryPermissions::READ | MemoryPermissions::WRITE,
                Backing::Zero,
            )?;
        }

        if let Some(shrink) = prev_end
            .as_u64()
            .checked_sub(brk_end)
            .filter(|&len| len != 0)
        {
            self.unmap(VirtAddr::new(brk_end), shrink);
        }

        let brk = self.brk_mut()?;
        brk.end = VirtAddr::new(brk_end);
        Ok(brk.end)
    }
}

#[derive(Clone)]
pub struct Mapping {
    start: Page,
    num_pages: u64,
    permissions: MemoryPermissions,
    backing: Backing,
}

impl Mapping {
    pub fn end(&self) -> Page {
        self.start + self.num_pages
    }

    pub fn contains(&self, addr: VirtAddr) -> bool {
        self.contains_page(Page::containing_address(addr))
    }

    pub fn contains_page(&self, page: Page) -> bool {
        (self.start..self.start + self.num_pages).contains(&page)
    }

    /// Returns true if the mapping contains any memory in the specified range.
    pub fn contains_range(&self, addr: VirtAddr, size: u64) -> bool {
        let Some(sizem1) = size.checked_sub(1) else {
            return false;
        };
        let end = addr + sizem1;

        self.contains(addr)
            || self.contains(end)
            || (addr..=end).contains(&self.start.start_address())
            || (addr..=end).contains(&(self.end().start_address() - 1u64))
    }

    /// Returns true if the mapping contains any memory in the specified range.
    pub fn contains_page_range(&self, addr: Page, num_pages: u64) -> bool {
        let Some(sizem1) = num_pages.checked_sub(1) else {
            return false;
        };
        let end = addr + sizem1;

        self.contains_page(addr)
            || self.contains_page(end)
            || (addr..=end).contains(&self.start)
            || (addr..=end).contains(&(self.end() - 1u64))
    }

    /// Split the mapping into two parts. `self` will contain `[..offset_in_pages)` and
    /// the returned mapping will contain `[offset_in_pages..]`
    pub fn split(&mut self, offset_in_pages: u64) -> Self {
        assert!(self.num_pages > offset_in_pages);
        let new_backing = self.backing.split(offset_in_pages);
        let new_len = self.num_pages - offset_in_pages;
        self.num_pages = offset_in_pages;
        Self {
            start: self.start + offset_in_pages,
            num_pages: new_len,
            permissions: self.permissions,
            backing: new_backing,
        }
    }

    /// # Safety
    ///
    /// The mapping must be in the active page table.
    unsafe fn make_executable(&self, page: Page) -> Result<*const [u8; 4096]> {
        if !self.permissions.contains(MemoryPermissions::EXECUTE) {
            // FIXME: Or ACCESS?
            return Err(Error::fault(()));
        }

        // Map the page in.
        let ptr = unsafe { self.make_readable(page)? };

        // Mark it as executable if it isn't already.
        let entry = entry_for_page(page).unwrap();
        if !entry.executable() {
            unsafe {
                add_flags(page, PageTableFlags::EXECUTABLE);
            }
        }

        Ok(ptr)
    }

    /// # Safety
    ///
    /// The mapping must be in the active page table.
    unsafe fn remove_cow(&self, page: Page) -> Result<*mut [u8; 4096]> {
        let ptr = page.start_address().as_mut_ptr::<[u8; 0x1000]>();

        unsafe {
            self.make_readable(page)?;
        }

        let mut current_entry = entry_for_page(page).ok_or(Error::fault(()))?;
        loop {
            if !current_entry.cow() {
                return Ok(ptr);
            }

            if current_entry.writable() {
                todo!();
            }
            let mut content = [0; 0x1000];
            without_smap(|| unsafe {
                core::intrinsics::volatile_copy_nonoverlapping_memory(&mut content, ptr, 1);
            });

            let frame = (&FRAME_ALLOCATOR).allocate_frame().unwrap();
            unsafe {
                copy_into_frame(frame, &content)?;
            }

            let new_entry =
                PresentPageTableEntry::new(frame, current_entry.flags() & !PageTableFlags::COW);

            match unsafe { remap_page(page, current_entry, new_entry) } {
                Ok(_) => return Ok(ptr),
                Err(new_entry) => {
                    current_entry = new_entry;
                    unsafe {
                        (&FRAME_ALLOCATOR).deallocate_frame(frame);
                    }
                }
            }
        }
    }

    /// # Safety
    ///
    /// The mapping must be in the active page table.
    unsafe fn make_writable(&self, page: Page) -> Result<*mut [u8; 4096]> {
        if !self.permissions.contains(MemoryPermissions::WRITE) {
            // FIXME: Or ACCESS?
            return Err(Error::fault(()));
        }

        let ptr = unsafe { self.remove_cow(page)? };

        let entry = entry_for_page(page).unwrap();
        if !entry.writable() {
            unsafe {
                add_flags(page, PageTableFlags::WRITABLE | PageTableFlags::USER);
            }
        }

        Ok(ptr)
    }

    /// # Safety
    ///
    /// The mapping must be in the active page table.
    unsafe fn make_readable(&self, page: Page) -> Result<*const [u8; 4096]> {
        if !self.permissions.contains(MemoryPermissions::READ) {
            // FIXME: Or ACCESS?
            return Err(Error::fault(()));
        }

        let ptr = page.start_address().as_mut_ptr::<[u8; 0x1000]>();

        if entry_for_page(page).is_some() {
            // If the page exists, it's readable.
        } else {
            match &self.backing {
                Backing::File(file_backing) => {
                    let aligned_static_bytes = if let Cow::Borrowed(bytes) = &*file_backing.bytes {
                        let offset =
                            usize::try_from(file_backing.offset + (page - self.start) * 0x1000)
                                .unwrap();
                        let backing_bytes = &bytes[offset..][..0x1000];
                        let backing_addr =
                            VirtAddr::from_ptr(backing_bytes as *const [u8] as *const u8);
                        if backing_addr.is_aligned(0x1000u64) {
                            Some(backing_addr)
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    if let Some(backing_addr) = aligned_static_bytes {
                        let backing_page =
                            Page::<Size4KiB>::from_start_address(backing_addr).unwrap();
                        let backing_entry = entry_for_page(backing_page).unwrap();

                        let mut flags = PageTableFlags::USER;
                        if self.permissions.contains(MemoryPermissions::EXECUTE) {
                            flags |= PageTableFlags::EXECUTABLE;
                        }
                        flags |= PageTableFlags::COW;
                        let new_entry = PresentPageTableEntry::new(backing_entry.frame(), flags);
                        unsafe {
                            map_page(page, new_entry, &mut &FRAME_ALLOCATOR)?;
                        }
                    } else {
                        let frame = (&FRAME_ALLOCATOR).allocate_frame().unwrap();

                        let offset =
                            usize::try_from(file_backing.offset + (page - self.start) * 0x1000)
                                .unwrap();
                        let bytes = &file_backing.bytes[offset..];
                        if bytes.len() >= 0x1000 {
                            let backing_bytes = &bytes[..0x1000];
                            let backing_bytes = <&[u8; 4096]>::try_from(backing_bytes).unwrap();
                            unsafe {
                                copy_into_frame(frame, backing_bytes)?;
                            }
                        } else {
                            let mut buf = [0; 0x1000];
                            buf[..bytes.len()].copy_from_slice(bytes);
                            unsafe {
                                copy_into_frame(frame, &buf)?;
                            }
                        }

                        let mut flags = PageTableFlags::USER;
                        if self.permissions.contains(MemoryPermissions::EXECUTE) {
                            flags |= PageTableFlags::EXECUTABLE;
                        }
                        if self.permissions.contains(MemoryPermissions::WRITE) {
                            flags |= PageTableFlags::WRITABLE;
                        }
                        let new_entry = PresentPageTableEntry::new(frame, flags);
                        unsafe {
                            map_page(page, new_entry, &mut &FRAME_ALLOCATOR)?;
                        }
                    }
                }
                Backing::Zero | Backing::Stack => {
                    // FIXME: We could map a specific zero frame.
                    let frame = (&FRAME_ALLOCATOR).allocate_frame().unwrap();
                    unsafe {
                        // SAFETY: We just allocated the frame, so we can do whatever.
                        zero_frame(frame)?;
                    }

                    let mut flags = PageTableFlags::USER;
                    if self.permissions.contains(MemoryPermissions::WRITE) {
                        flags |= PageTableFlags::WRITABLE;
                    }
                    if self.permissions.contains(MemoryPermissions::EXECUTE) {
                        flags |= PageTableFlags::EXECUTABLE;
                    }
                    let new_entry = PresentPageTableEntry::new(frame, flags);
                    unsafe {
                        map_page(page, new_entry, &mut &FRAME_ALLOCATOR)?;
                    }
                }
            }
        }

        Ok(ptr)
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

#[derive(Clone)]
enum Backing {
    File(FileBacking),
    Zero,
    Stack,
}

impl Backing {
    /// Split the backing into two parts. `self` will contain `[..offset)` and
    /// the returned backing will contain `[offset..]`
    pub fn split(&mut self, offset: u64) -> Self {
        match self {
            Backing::File(file) => Backing::File(file.split(offset)),
            Backing::Zero => Backing::Zero,
            Backing::Stack => Backing::Stack,
        }
    }

    /// In some situations we can't always let the backing provide the frames
    /// for virtual memory e.g. if the mapping isn't page aligned. In those
    /// cases a fresh frame will be allocated and the backing's memory will be
    /// copied into it.
    pub fn copy_initial_memory_to_slice(&self, offset: u64, buf: &mut [u8]) {
        match self {
            Backing::File(backing) => {
                let offset = usize::try_from(backing.offset + offset).unwrap();
                if offset > backing.bytes.len() {
                    buf.fill(0);
                } else {
                    buf.copy_from_slice(&backing.bytes[offset..][..buf.len()]);
                }
            }
            Backing::Zero | Backing::Stack => {
                // The memory in these backings starts out as zero.
                buf.fill(0);
            }
        }
    }
}

#[derive(Clone)]
struct FileBacking {
    offset: u64,
    bytes: FileSnapshot,
}

impl FileBacking {
    pub fn split(&mut self, offset: u64) -> Self {
        Self {
            offset: self.offset + offset,
            bytes: self.bytes.clone(),
        }
    }
}

pub fn without_smap<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    without_interrupts(|| {
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
    })
}

pub fn without_write_protect<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    without_interrupts(|| {
        let cr0 = Cr0::read();
        let changed = cr0.contains(Cr0Flags::WRITE_PROTECT);
        if changed {
            unsafe {
                Cr0::write(cr0 & !Cr0Flags::WRITE_PROTECT);
            }
        }

        let result = f();

        if changed {
            unsafe {
                Cr0::write(cr0 | Cr0Flags::WRITE_PROTECT);
            }
        }

        result
    })
}

#[derive(Clone, Copy)]
pub enum VmSize {
    ThirtyTwo = 32,
    FourtySeven = 47,
}

#[derive(Clone)]
struct Brk {
    _start: VirtAddr,
    end: VirtAddr,
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
        static INVLPGB: Lazy<Invlpgb> =
            Lazy::new(|| Invlpgb::new().expect("invlpgb not supported"));

        unsafe {
            INVLPGB.build().pcid(pcid).flush();
        }

        INVLPGB.tlbsync();

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
