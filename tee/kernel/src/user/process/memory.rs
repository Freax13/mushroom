use core::{
    arch::asm,
    cmp,
    intrinsics::volatile_copy_nonoverlapping_memory,
    iter::Step,
    ops::Deref,
    sync::atomic::{AtomicU16, Ordering},
};

use alloc::{borrow::Cow, ffi::CString, vec::Vec};
use bitflags::bitflags;
use log::debug;
use spin::Mutex;
use x86_64::{
    align_down,
    instructions::{interrupts::without_interrupts, random::RdRand, tlb::Pcid},
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
        frame::DUMB_FRAME_ALLOCATOR,
        pagetable::{
            add_flags, allocate_pml4, entry_for_page, map_page, remap_page, remove_flags,
            PageTableFlags, PresentPageTableEntry,
        },
        temporary::{copy_into_frame, zero_frame},
    },
};

use super::syscall::args::ProtFlags;

pub struct VirtualMemoryActivator(());

impl VirtualMemoryActivator {
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
            Cr3::write_pcid(virtual_memory.pml4, virtual_memory.pcid);
        }
        let mut active_virtual_memory = ActiveVirtualMemory {
            _activator: self,
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
    pcid: Pcid,
}

impl VirtualMemory {
    pub fn new() -> Self {
        // FIXME: Use a more robust pcid allocation algorithm.
        static PCID_COUNTER: AtomicU16 = AtomicU16::new(1);
        let pcid = PCID_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pcid = Pcid::new(pcid).unwrap();

        let pml4 = allocate_pml4().unwrap();

        Self {
            state: Mutex::new(VirtualMemoryState::new()),
            pml4,
            pcid,
        }
    }

    /// # Safety
    ///
    /// The virtual memory must be active.
    pub unsafe fn handle_page_fault(&self, addr: u64, error_code: PageFaultErrorCode) {
        let addr = VirtAddr::new(addr);
        let page = Page::containing_address(addr);

        debug!(target: "kernel::exception", "{addr:?} {error_code:?}");

        let state = self.state.lock();

        let mapping = state
            .mappings
            .iter()
            .find(|mapping| mapping.contains(addr))
            .unwrap();

        match error_code & !PageFaultErrorCode::USER_MODE {
            PageFaultErrorCode::INSTRUCTION_FETCH => unsafe {
                mapping.make_executable(page).unwrap();
            },
            PageFaultErrorCode::CAUSED_BY_WRITE => unsafe {
                mapping.make_writable(page).unwrap();
            },
            a if a
                == PageFaultErrorCode::CAUSED_BY_WRITE
                    | PageFaultErrorCode::PROTECTION_VIOLATION =>
            unsafe {
                mapping.make_writable(page).unwrap();
            },
            error_code if error_code == PageFaultErrorCode::empty() => unsafe {
                mapping.make_readable(page).unwrap();
            },
            error_code => todo!("{addr:#018x} {error_code:?}"),
        }
    }
}

pub struct ActiveVirtualMemory<'a, 'b> {
    _activator: &'a mut VirtualMemoryActivator,
    virtual_memory: &'b VirtualMemory,
}

impl<'a, 'b> ActiveVirtualMemory<'a, 'b> {
    pub fn read(&self, addr: VirtAddr, bytes: &mut [u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }

        let state = self.state.lock();

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
                .find(|mapping| mapping.contains(copy_start))
                .ok_or(Error::fault())?;
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

    pub fn read_cstring(&self, mut addr: VirtAddr, max_length: usize) -> Result<CString> {
        let mut ret = Vec::new();
        loop {
            let mut buf = 0;
            self.read(addr, core::array::from_mut(&mut buf))?;
            if buf == 0 {
                break;
            }
            if ret.len() == max_length {
                return Err(Error::name_too_long());
            }
            addr = Step::forward(addr, 1);
            ret.push(buf);
        }
        let ret = CString::new(ret).unwrap();
        Ok(ret)
    }

    pub fn write(&self, addr: VirtAddr, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }

        let state = self.state.lock();

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
                .find(|mapping| mapping.contains(copy_start))
                .ok_or(Error::fault())?;
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

    pub fn mprotect(&self, addr: VirtAddr, len: u64, prot: ProtFlags) -> Result<()> {
        if len == 0 {
            return Ok(());
        }

        if !addr.is_aligned(0x1000u64) || len % 0x1000 != 0 {
            unimplemented!()
        }

        let mut state = self.state.lock();

        loop {
            let mapping = state
                .mappings
                .iter_mut()
                .find(|m| m.contains(addr))
                .ok_or(Error::fault())?;

            let start_offset = addr - mapping.addr;
            if start_offset > 0 {
                let mut new_mapping = mapping.split(start_offset);
                let new_permissions = MemoryPermissions::from(prot);
                let old_permissions =
                    core::mem::replace(&mut new_mapping.permissions, new_permissions);

                // Check if permissions have been removed.
                let removed_permissions = !new_permissions & old_permissions;
                let flags = PageTableFlags::from(removed_permissions);

                let start = new_mapping.addr;
                let end_inclusive = new_mapping.end() - 1u64;
                let start_page = Page::containing_address(start);
                let end_inclusive_page = Page::containing_address(end_inclusive);

                for page in start_page..=end_inclusive_page {
                    unsafe {
                        remove_flags(page, flags);
                    }
                }

                state.mappings.push(new_mapping);

                continue;
            }

            assert_eq!(mapping.addr, addr);

            let new_mapping = if mapping.len > len {
                Some(mapping.split(len))
            } else {
                None
            };

            let new_permissions = MemoryPermissions::from(prot);
            let old_permissions = core::mem::replace(&mut mapping.permissions, new_permissions);

            // Check if permissions have been removed.
            let removed_permissions = !new_permissions & old_permissions;
            let flags = PageTableFlags::from(removed_permissions);

            let start = mapping.addr;
            let end_inclusive = mapping.end() - 1u64;
            let start_page = Page::containing_address(start);
            let end_inclusive_page = Page::containing_address(end_inclusive);

            for page in start_page..=end_inclusive_page {
                unsafe {
                    remove_flags(page, flags);
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
        let mut state = self.state.lock();

        let addr = addr.unwrap_or_else(|| state.find_free_address(len));
        let end = addr + len;

        debug!(
            "adding mapping {:?}-{:?} {:?}",
            addr,
            addr + len,
            permissions
        );

        let mapping = Mapping {
            addr,
            len,
            permissions,
            backing,
        };

        fn ensure_page_is_mapped(page: Page, permissions: MemoryPermissions) -> Result<(), Error> {
            let entry = entry_for_page(page);
            if entry.is_some() {
                return Ok(());
            }

            let frame = (&DUMB_FRAME_ALLOCATOR)
                .allocate_frame()
                .ok_or(Error::no_mem())?;
            unsafe {
                zero_frame(frame)?;
            }
            let entry = PresentPageTableEntry::new(
                frame,
                PageTableFlags::USER | PageTableFlags::from(permissions),
            );
            unsafe { map_page(page, entry, &mut &DUMB_FRAME_ALLOCATOR) }
        }

        fn copy_unaligned_start_and_end(start: VirtAddr, end: VirtAddr, backing: &Backing) {
            // Collect the unaligned part into a buffer.
            let mut buffer = [0; 0x1000];
            let start_idx = start.as_u64() as usize % 0x1000;
            let end_idx = end.as_u64() as usize % 0x1000;
            let buffer = &mut buffer[start_idx..end_idx];
            backing.copy_initial_memory_to_slice(0, buffer);

            // Copy the unaligned part into the page.
            without_smap(|| {
                without_write_protect(|| unsafe {
                    volatile_copy_nonoverlapping_memory(
                        start.as_mut_ptr(),
                        buffer.as_ptr(),
                        buffer.len(),
                    );
                })
            });
        }

        fn copy_unaligned_start(start: VirtAddr, backing: &Backing) {
            // Collect the unaligned part into a buffer.
            let mut buffer = [0; 0x1000];
            let start_idx = start.as_u64() as usize % 0x1000;
            let buffer = &mut buffer[start_idx..];
            backing.copy_initial_memory_to_slice(0, buffer);

            // Copy the unaligned part into the page.
            without_smap(|| {
                without_write_protect(|| unsafe {
                    volatile_copy_nonoverlapping_memory(
                        start.as_mut_ptr(),
                        buffer.as_ptr(),
                        buffer.len(),
                    );
                })
            });
        }

        fn copy_unaligned_end(end: VirtAddr, backing: &Backing, total_len: u64) {
            // Collect the unaligned part into a buffer.
            let mut buffer = [0; 0x1000];
            let buffer_len_as_u64 = end.as_u64() % 0x1000;
            let end_idx = buffer_len_as_u64 as usize;
            let buffer = &mut buffer[..end_idx];
            backing.copy_initial_memory_to_slice(total_len - buffer_len_as_u64, buffer);

            // Copy the unaligned part into the page.
            without_smap(|| {
                without_write_protect(|| unsafe {
                    volatile_copy_nonoverlapping_memory(
                        end.as_mut_ptr::<u8>().sub(end_idx),
                        buffer.as_ptr(),
                        buffer.len(),
                    );
                })
            });
        }

        // If the mapping isn't page aligned, immediately map pages for the unaligned start and end.
        match (addr.is_aligned(0x1000u64), end.is_aligned(0x1000u64)) {
            (false, false) => {
                let start_page = Page::containing_address(addr);
                let end_page = Page::containing_address(end);
                if start_page == end_page {
                    ensure_page_is_mapped(start_page, permissions)?;
                    copy_unaligned_start_and_end(addr, end, &mapping.backing);
                } else {
                    ensure_page_is_mapped(start_page, permissions)?;
                    copy_unaligned_start(addr, &mapping.backing);
                    ensure_page_is_mapped(end_page, permissions)?;
                    copy_unaligned_end(end, &mapping.backing, len);
                }
            }
            (false, true) => {
                let start_page = Page::containing_address(addr);
                ensure_page_is_mapped(start_page, permissions)?;
                copy_unaligned_start(addr, &mapping.backing);
            }
            (true, false) => {
                let end_page = Page::containing_address(end);
                ensure_page_is_mapped(end_page, permissions)?;
                copy_unaligned_end(end, &mapping.backing, len);
            }
            (true, true) => {}
        }

        let addr = mapping.addr;

        state.mappings.push(mapping);

        Ok(addr)
    }
}

impl Deref for ActiveVirtualMemory<'_, '_> {
    type Target = VirtualMemory;

    fn deref(&self) -> &Self::Target {
        self.virtual_memory
    }
}

struct VirtualMemoryState {
    mappings: Vec<Mapping>,
}

impl VirtualMemoryState {
    pub fn new() -> Self {
        Self {
            mappings: Vec::new(),
        }
    }

    fn find_free_address(&self, size: u64) -> VirtAddr {
        let rdrand = RdRand::new().unwrap();
        const MAX_ATTEMPTS: usize = 64;
        (0..MAX_ATTEMPTS)
            .find_map(|_| {
                let candidate = rdrand.get_u64()?;
                let candidate = candidate & 0x7fff_ffff_ffff;
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
}

pub struct Mapping {
    addr: VirtAddr,
    len: u64,
    permissions: MemoryPermissions,
    backing: Backing,
}

impl Mapping {
    pub fn end(&self) -> VirtAddr {
        self.addr + self.len
    }

    pub fn contains(&self, addr: VirtAddr) -> bool {
        (self.addr..self.addr + self.len).contains(&addr)
    }

    pub fn contains_range(&self, addr: VirtAddr, size: u64) -> bool {
        let Some(sizem1) = size.checked_sub(1) else { return false; };
        let end = addr + sizem1;

        self.contains(addr)
            || self.contains(end)
            || (addr..=end).contains(&self.addr)
            || (addr..=end).contains(&(self.end() - 1u64))
    }

    /// Split the mapping into two parts. `self` will contain `[..offset)` and
    /// the returned mapping will contain `[offset..]`
    pub fn split(&mut self, offset: u64) -> Self {
        assert!(self.len > offset);
        let new_backing = self.backing.split(offset);
        let new_len = self.len - offset;
        self.len = offset;
        Self {
            addr: self.addr + offset,
            len: new_len,
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
            return Err(Error::fault());
        }

        if let Some(entry) = entry_for_page(page) {
            if !entry.executable() {
                unsafe {
                    add_flags(page, PageTableFlags::EXECUTABLE);
                }
            }
        } else {
            let Backing::File(file_backing) = &self.backing else { todo!(); };

            match *file_backing.bytes {
                Cow::Borrowed(bytes) => {
                    // FIXME: Get rid of as_u64
                    let offset =
                        usize::try_from(file_backing.offset + (page.start_address() - self.addr))
                            .unwrap();
                    let backing_bytes = &bytes[offset..][..0x1000];
                    let backing_addr =
                        VirtAddr::from_ptr(backing_bytes as *const [u8] as *const u8);
                    let backing_page = Page::<Size4KiB>::from_start_address(backing_addr).unwrap();
                    let backing_entry = entry_for_page(backing_page).unwrap();

                    let new_entry = PresentPageTableEntry::new(
                        backing_entry.frame(),
                        PageTableFlags::USER | PageTableFlags::EXECUTABLE | PageTableFlags::COW,
                    );
                    unsafe {
                        map_page(page, new_entry, &mut &DUMB_FRAME_ALLOCATOR)?;
                    }
                }
                Cow::Owned(_) => todo!(),
            }
        }

        let ptr = page.start_address().as_mut_ptr::<[u8; 0x1000]>();
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

        let mut current_entry = entry_for_page(page).ok_or(Error::fault())?;
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

            let frame = (&DUMB_FRAME_ALLOCATOR).allocate_frame().unwrap();
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
                        (&DUMB_FRAME_ALLOCATOR).deallocate_frame(frame);
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
            return Err(Error::fault());
        }

        let ptr = page.start_address().as_mut_ptr::<[u8; 0x1000]>();

        if let Some(entry) = entry_for_page(page) {
            if !entry.writable() {
                // Check if we have to copy the page.
                if entry.cow() {
                    unsafe {
                        self.remove_cow(page)?;
                    }
                }

                unsafe {
                    add_flags(page, PageTableFlags::WRITABLE | PageTableFlags::USER);
                }
            }
        } else {
            match &self.backing {
                Backing::File(file_backing) => {
                    match *file_backing.bytes {
                        Cow::Borrowed(bytes) => {
                            // FIXME: Get rid of as_u64
                            let offset = usize::try_from(
                                file_backing.offset + (page.start_address() - self.addr),
                            )
                            .unwrap();
                            let backing_bytes = &bytes[offset..][..0x1000];
                            let backing_bytes: &[u8; 0x1000] = backing_bytes.try_into().unwrap();

                            let frame = (&DUMB_FRAME_ALLOCATOR).allocate_frame().unwrap();

                            // Fill the frame.
                            unsafe {
                                // SAFETY: We just allocated the frame, so we can do whatever.
                                copy_into_frame(frame, backing_bytes)?;
                            }

                            // Map the page.
                            let mut flags = PageTableFlags::USER | PageTableFlags::WRITABLE;
                            if self.permissions.contains(MemoryPermissions::EXECUTE) {
                                flags |= PageTableFlags::EXECUTABLE;
                            }
                            let new_entry = PresentPageTableEntry::new(frame, flags);
                            unsafe {
                                map_page(page, new_entry, &mut &DUMB_FRAME_ALLOCATOR)?;
                            }
                        }
                        Cow::Owned(_) => todo!(),
                    }
                }
                Backing::Zero | Backing::Stack => {
                    let frame = (&DUMB_FRAME_ALLOCATOR).allocate_frame().unwrap();

                    unsafe {
                        // SAFETY: We just allocated the frame, so we can do whatever.
                        zero_frame(frame)?;
                    }

                    let mut flags = PageTableFlags::USER | PageTableFlags::WRITABLE;
                    if self.permissions.contains(MemoryPermissions::EXECUTE) {
                        flags |= PageTableFlags::EXECUTABLE;
                    }
                    let new_entry = PresentPageTableEntry::new(frame, flags);
                    unsafe {
                        map_page(page, new_entry, &mut &DUMB_FRAME_ALLOCATOR)?;
                    }
                }
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
            return Err(Error::fault());
        }

        let ptr = page.start_address().as_mut_ptr::<[u8; 0x1000]>();

        if entry_for_page(page).is_some() {
            // If the page exists, it's readable.
        } else {
            match &self.backing {
                Backing::File(file_backing) => {
                    match *file_backing.bytes {
                        Cow::Borrowed(bytes) => {
                            // FIXME: Get rid of as_u64
                            let offset = usize::try_from(
                                file_backing.offset + (page.start_address() - self.addr),
                            )
                            .unwrap();
                            let backing_bytes = &bytes[offset..][..0x1000];
                            let backing_addr =
                                VirtAddr::from_ptr(backing_bytes as *const [u8] as *const u8);
                            let backing_page =
                                Page::<Size4KiB>::from_start_address(backing_addr).unwrap();
                            let backing_entry = entry_for_page(backing_page).unwrap();

                            let mut flags = PageTableFlags::USER;
                            if self.permissions.contains(MemoryPermissions::EXECUTE) {
                                flags |= PageTableFlags::EXECUTABLE;
                            }
                            flags |= PageTableFlags::COW;
                            let new_entry =
                                PresentPageTableEntry::new(backing_entry.frame(), flags);
                            unsafe {
                                map_page(page, new_entry, &mut &DUMB_FRAME_ALLOCATOR)?;
                            }
                        }
                        Cow::Owned(_) => todo!(),
                    }
                }
                Backing::Zero | Backing::Stack => {
                    // FIXME: We could map a specific zero frame.
                    let frame = (&DUMB_FRAME_ALLOCATOR).allocate_frame().unwrap();
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
                        map_page(page, new_entry, &mut &DUMB_FRAME_ALLOCATOR)?;
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
    /// for virtual memory e.g. when two mappings with different backings
    /// overlap. In those cases a fresh frame will be allocated and the
    /// backing's memory will be copied into it.
    pub fn copy_initial_memory_to_slice(&self, offset: u64, buf: &mut [u8]) {
        match self {
            Backing::File(backing) => {
                let offset = usize::try_from(backing.offset + offset).unwrap();
                buf.copy_from_slice(&backing.bytes[offset..][..buf.len()]);
            }
            Backing::Zero | Backing::Stack => {
                // The memory in these backings starts out as zero.
                buf.fill(0);
            }
        }
    }
}

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
