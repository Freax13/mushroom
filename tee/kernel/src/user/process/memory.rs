use core::{arch::asm, cmp, iter::Step};

use alloc::vec::Vec;
use bitflags::bitflags;
use log::debug;
use x86_64::{
    align_down,
    instructions::random::RdRand,
    registers::{
        control::{Cr0, Cr0Flags},
        rflags::{self, RFlags},
    },
    structures::{
        idt::PageFaultErrorCode,
        paging::{FrameAllocator, FrameDeallocator, Page, Size4KiB},
    },
    VirtAddr,
};

use crate::{
    error::{Error, Result},
    fs::node::FileSnapshot,
    memory::{
        frame::DUMB_FRAME_ALLOCATOR,
        pagetable::{
            add_flags, entry_for_page, map_page, remap_page, remove_flags, PageTableFlags,
            PresentPageTableEntry,
        },
        temporary::{copy_into_frame, zero_frame},
    },
};

use super::syscall::args::ProtFlags;

pub struct VirtualMemory {
    mappings: Vec<Mapping>,
}

impl VirtualMemory {
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

    pub fn mprotect(&mut self, addr: VirtAddr, len: u64, prot: ProtFlags) -> Result<()> {
        while len > 0 {
            let mapping = self
                .mappings
                .iter_mut()
                .find(|m| m.contains(addr))
                .ok_or(Error::Fault)?;

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

                self.mappings.push(new_mapping);

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
                self.mappings.push(new_mapping);
            }

            break;
        }

        Ok(())
    }

    pub fn allocate_stack(&mut self, addr: Option<VirtAddr>, len: u64) -> Result<VirtAddr> {
        let addr = self.add_mapping(
            addr,
            len,
            MemoryPermissions::READ | MemoryPermissions::WRITE,
            Backing::Stack,
        )?;
        Ok(addr)
    }

    pub fn mmap_into(
        &mut self,
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
        &mut self,
        addr: Option<VirtAddr>,
        len: u64,
        permissions: MemoryPermissions,
    ) -> Result<VirtAddr> {
        self.add_mapping(addr, len, permissions, Backing::Zero)
    }

    fn add_mapping(
        &mut self,
        addr: Option<VirtAddr>,
        len: u64,
        permissions: MemoryPermissions,
        backing: Backing,
    ) -> Result<VirtAddr> {
        let addr = addr.unwrap_or_else(|| self.find_free_address(len));

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

        for m in self.mappings.iter() {
            if let Some(overlapping_page) = m.page_overlaps(&mapping)? {
                match (&m.backing, &mapping.backing) {
                    (Backing::File(_), Backing::File(_)) => todo!(),
                    (_, Backing::Zero) => {
                        let ptr = m.remove_cow(overlapping_page)?;
                        let zero_start = cmp::max(overlapping_page.start_address(), mapping.addr);
                        let zero_end =
                            cmp::min((overlapping_page + 1).start_address(), mapping.end());

                        let zero_start_offset = usize::from(zero_start.page_offset());
                        let zero_end_offset = usize::from((zero_end - 1u64).page_offset()) + 1;
                        let zero_len = zero_end_offset - zero_start_offset;

                        without_smap(|| {
                            without_write_protect(|| unsafe {
                                let copy_ptr =
                                    ptr.cast::<u8>().add(usize::from(zero_start.page_offset()));
                                core::intrinsics::volatile_set_memory(copy_ptr, 0, zero_len);
                            });
                        });
                    }
                    (Backing::File(_), Backing::Stack) => todo!(),
                    (Backing::Zero, Backing::File(_)) => todo!(),
                    (Backing::Zero, Backing::Stack) => todo!(),
                    (Backing::Stack, Backing::File(_)) => todo!(),
                    (Backing::Stack, Backing::Stack) => todo!(),
                }
            }
        }

        let addr = mapping.addr;

        self.mappings.push(mapping);

        Ok(addr)
    }

    pub fn read(&self, addr: VirtAddr, bytes: &mut [u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }

        let start = addr;
        let end_inclusive = addr + (bytes.len() - 1);

        let start_page = Page::<Size4KiB>::containing_address(start);
        let end_inclusive_page = Page::<Size4KiB>::containing_address(end_inclusive);

        for page in Page::range_inclusive(start_page, end_inclusive_page) {
            let copy_start = cmp::max(page.start_address(), start);
            let copy_end_inclusive = cmp::min(page.start_address() + 0xfffu64, end_inclusive);

            let mapping = self
                .mappings
                .iter()
                .find(|mapping| mapping.contains(copy_start))
                .ok_or(Error::Fault)?;
            let ptr = mapping.make_readable(page)?;

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

    pub fn read_cstring(&self, mut addr: VirtAddr, max_length: usize) -> Result<Vec<u8>> {
        let mut ret = Vec::new();
        loop {
            let mut buf = 0;
            self.read(addr, core::array::from_mut(&mut buf));
            if buf == 0 {
                break;
            }
            if ret.len() == max_length {
                return Err(Error::NameTooLong);
            }
            addr = Step::forward(addr, 1);
            ret.push(buf);
        }
        Ok(ret)
    }

    pub fn write(&self, addr: VirtAddr, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }

        let start = addr;
        let end_inclusive = addr + (bytes.len() - 1);

        let start_page = Page::<Size4KiB>::containing_address(start);
        let end_inclusive_page = Page::<Size4KiB>::containing_address(end_inclusive);

        for page in Page::range_inclusive(start_page, end_inclusive_page) {
            let copy_start = cmp::max(page.start_address(), start);
            let copy_end_inclusive = cmp::min(page.start_address() + 0xfffu64, end_inclusive);

            let mapping = self
                .mappings
                .iter()
                .find(|mapping| mapping.contains(copy_start))
                .ok_or(Error::Fault)?;
            let ptr = mapping.make_writable(page)?;

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

    pub fn handle_page_fault(&self, addr: u64, error_code: PageFaultErrorCode) {
        let addr = VirtAddr::new(addr);
        let page = Page::containing_address(addr);

        debug!(target: "kernel::exception", "{addr:?} {error_code:?}");

        let mapping = self
            .mappings
            .iter()
            .find(|mapping| mapping.contains(addr))
            .unwrap();

        match error_code & !PageFaultErrorCode::USER_MODE {
            PageFaultErrorCode::INSTRUCTION_FETCH => {
                mapping.make_executable(page).unwrap();
            }
            PageFaultErrorCode::CAUSED_BY_WRITE => {
                mapping.make_writable(page).unwrap();
            }
            a if a
                == PageFaultErrorCode::CAUSED_BY_WRITE
                    | PageFaultErrorCode::PROTECTION_VIOLATION =>
            {
                mapping.make_writable(page).unwrap();
            }
            error_code if error_code == PageFaultErrorCode::empty() => {
                mapping.make_readable(page).unwrap();
            }
            error_code => todo!("{addr:#018x} {error_code:?}"),
        }
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

    /// Check if the two mappings are mapped to the same page.
    ///
    /// Returns an error if the mappings overlap.
    pub fn page_overlaps(&self, mapping: &Self) -> Result<Option<Page>> {
        if self.contains(mapping.addr)
            || self.contains(mapping.end() - 1u64)
            || mapping.contains(self.addr)
            || mapping.contains(self.end() - 1u64)
        {
            return Err(Error::Inval);
        }

        let self_start_page = Page::<Size4KiB>::containing_address(self.addr);
        let self_end_page = Page::<Size4KiB>::containing_address(self.addr + (self.len - 1));
        let other_start_page = Page::<Size4KiB>::containing_address(mapping.addr);
        let other_end_page = Page::<Size4KiB>::containing_address(mapping.addr + (mapping.len - 1));

        if (self_start_page..=self_end_page).contains(&other_start_page) {
            Ok(Some(other_start_page))
        } else if (self_start_page..=self_end_page).contains(&other_end_page) {
            Ok(Some(other_end_page))
        } else if (other_start_page..=other_end_page).contains(&self_start_page) {
            Ok(Some(self_start_page))
        } else if (other_start_page..=other_end_page).contains(&self_end_page) {
            Ok(Some(self_end_page))
        } else {
            Ok(None)
        }
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

    fn make_executable(&self, page: Page) -> Result<*const [u8; 4096]> {
        assert!(self.contains(page.start_address()));

        if !self.permissions.contains(MemoryPermissions::EXECUTE) {
            // FIXME: Or ACCESS?
            return Err(Error::Fault);
        }

        let Backing::File(file_backing) = &self.backing else { todo!(); };

        match file_backing.bytes {
            FileSnapshot::Static(bytes) => {
                // FIXME: Get rid of as_u64
                let offset =
                    usize::try_from(file_backing.offset + (page.start_address() - self.addr))
                        .unwrap();
                let backing_bytes = &bytes[offset..][..0x1000];
                let backing_addr = VirtAddr::from_ptr(backing_bytes as *const [u8] as *const u8);
                let backing_page = Page::<Size4KiB>::from_start_address(backing_addr).unwrap();
                let backing_entry = entry_for_page(backing_page).unwrap();

                let new_entry = PresentPageTableEntry::new(
                    backing_entry.frame(),
                    PageTableFlags::USER | PageTableFlags::EXECUTABLE | PageTableFlags::COW,
                );
                unsafe {
                    map_page(page, new_entry, &mut &DUMB_FRAME_ALLOCATOR);
                }
            }
            FileSnapshot::Dynamic(_) => todo!(),
        }

        let ptr = page.start_address().as_mut_ptr::<[u8; 0x1000]>();
        Ok(ptr)
    }

    fn remove_cow(&self, page: Page) -> Result<*mut [u8; 4096]> {
        let ptr = page.start_address().as_mut_ptr::<[u8; 0x1000]>();

        self.make_readable(page)?;

        let mut current_entry = entry_for_page(page).ok_or(Error::Fault)?;
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
                copy_into_frame(frame, &content);
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

    fn make_writable(&self, page: Page) -> Result<*mut [u8; 4096]> {
        assert!(self.contains(page.start_address()));

        if !self.permissions.contains(MemoryPermissions::WRITE) {
            // FIXME: Or ACCESS?
            return Err(Error::Fault);
        }

        let ptr = page.start_address().as_mut_ptr::<[u8; 0x1000]>();

        if let Some(entry) = entry_for_page(page) {
            if !entry.writable() {
                // Check if we have to copy the page.
                if entry.cow() {
                    self.remove_cow(page)?;
                }

                unsafe {
                    add_flags(page, PageTableFlags::WRITABLE | PageTableFlags::USER);
                }
            }
        } else {
            match &self.backing {
                Backing::File(file_backing) => {
                    match file_backing.bytes {
                        FileSnapshot::Static(bytes) => {
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
                                copy_into_frame(frame, backing_bytes);
                            }

                            // Map the page.
                            let mut flags = PageTableFlags::USER | PageTableFlags::WRITABLE;
                            if self.permissions.contains(MemoryPermissions::EXECUTE) {
                                flags |= PageTableFlags::EXECUTABLE;
                            }
                            let new_entry = PresentPageTableEntry::new(frame, flags);
                            unsafe {
                                map_page(page, new_entry, &mut &DUMB_FRAME_ALLOCATOR);
                            }
                        }
                        FileSnapshot::Dynamic(_) => todo!(),
                    }
                }
                Backing::Zero | Backing::Stack => {
                    let frame = (&DUMB_FRAME_ALLOCATOR).allocate_frame().unwrap();

                    unsafe {
                        // SAFETY: We just allocated the frame, so we can do whatever.
                        zero_frame(frame);
                    }

                    let mut flags = PageTableFlags::USER | PageTableFlags::WRITABLE;
                    if self.permissions.contains(MemoryPermissions::EXECUTE) {
                        flags |= PageTableFlags::EXECUTABLE;
                    }
                    let new_entry = PresentPageTableEntry::new(frame, flags);
                    unsafe {
                        map_page(page, new_entry, &mut &DUMB_FRAME_ALLOCATOR);
                    }
                }
            }
        }

        Ok(ptr)
    }

    fn make_readable(&self, page: Page) -> Result<*const [u8; 4096]> {
        assert!(self.contains(page.start_address()));

        if !self.permissions.contains(MemoryPermissions::READ) {
            // FIXME: Or ACCESS?
            return Err(Error::Fault);
        }

        let ptr = page.start_address().as_mut_ptr::<[u8; 0x1000]>();

        if entry_for_page(page).is_some() {
            // If the page exists, it's readable.
        } else {
            match &self.backing {
                Backing::File(file_backing) => {
                    match file_backing.bytes {
                        FileSnapshot::Static(bytes) => {
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
                                map_page(page, new_entry, &mut &DUMB_FRAME_ALLOCATOR);
                            }
                        }
                        FileSnapshot::Dynamic(_) => todo!(),
                    }
                }
                Backing::Zero | Backing::Stack => {
                    // FIXME: We could map a specific zero frame.
                    let frame = (&DUMB_FRAME_ALLOCATOR).allocate_frame().unwrap();
                    unsafe {
                        // SAFETY: We just allocated the frame, so we can do whatever.
                        zero_frame(frame);
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
                        map_page(page, new_entry, &mut &DUMB_FRAME_ALLOCATOR);
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

pub fn without_write_protect<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
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
}
