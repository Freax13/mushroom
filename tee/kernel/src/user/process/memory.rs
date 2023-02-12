use core::{arch::asm, cmp, panic::PanicInfo};

use alloc::vec::Vec;
use bitflags::bitflags;
use log::debug;
use x86_64::{
    registers::{
        control::{Cr0, Cr0Flags},
        rflags::{self, RFlags},
    },
    structures::{
        idt::PageFaultErrorCode,
        paging::{FrameAllocator, Page, Size4KiB},
    },
    VirtAddr,
};

use crate::{
    error::{Error, Result},
    fs::node::FileSnapshot,
    memory::{
        frame::DUMB_FRAME_ALLOCATOR,
        pagetable::{add_flags, map_page, page_to_frame, unmap_page, PageTableFlags},
    },
};

use super::Process;

pub struct MemoryManager {
    mappings: Vec<Mapping>,
}

impl MemoryManager {
    pub fn new() -> Self {
        Self {
            mappings: Vec::new(),
        }
    }
}

impl Process {
    pub fn allocate_stack(&self, addr: VirtAddr, len: u64) -> Result<VirtAddr> {
        self.add_mapping(Mapping {
            addr,
            len,
            permissions: MemoryPermissions::READ | MemoryPermissions::WRITE,
            backing: Backing::Stack,
        })?;

        Ok(addr + len)
    }

    pub fn mmap_into(
        &self,
        addr: VirtAddr,
        len: u64,
        offset: u64,
        bytes: FileSnapshot,
        permissions: MemoryPermissions,
    ) -> Result<()> {
        self.add_mapping(Mapping {
            addr,
            len,
            permissions,
            backing: Backing::File(FileBacking { offset, bytes }),
        })
    }

    pub fn mmap_zero(
        &self,
        addr: VirtAddr,
        len: u64,
        permissions: MemoryPermissions,
    ) -> Result<()> {
        self.add_mapping(Mapping {
            addr,
            len,
            permissions,
            backing: Backing::Zero,
        })
    }

    pub fn add_mapping(&self, mapping: Mapping) -> Result<()> {
        debug!(
            "adding mapping {:?}-{:?} {:?}",
            mapping.addr,
            mapping.end(),
            mapping.permissions
        );

        let mut guard = self.memory_manager.lock();

        for m in guard.mappings.iter() {
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

        guard.mappings.push(mapping);

        Ok(())
    }

    pub fn load(&self) {
        // FIXME: Load the page table.
    }

    pub fn read(&self, addr: VirtAddr, bytes: &mut [u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }

        let start = addr;
        let end_inclusive = addr + (bytes.len() - 1);

        let start_page = Page::<Size4KiB>::containing_address(start);
        let end_inclusive_page = Page::<Size4KiB>::containing_address(end_inclusive);

        let guard = self.memory_manager.lock();
        for page in Page::range_inclusive(start_page, end_inclusive_page) {
            let copy_start = cmp::max(page.start_address(), start);
            let copy_end_inclusive = cmp::min(page.start_address() + 0xfffu64, end_inclusive);

            let mapping = guard
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

    pub fn write(&self, addr: VirtAddr, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }

        let start = addr;
        let end_inclusive = addr + (bytes.len() - 1);

        let start_page = Page::<Size4KiB>::containing_address(start);
        let end_inclusive_page = Page::<Size4KiB>::containing_address(end_inclusive);

        let guard = self.memory_manager.lock();
        for page in Page::range_inclusive(start_page, end_inclusive_page) {
            let copy_start = cmp::max(page.start_address(), start);
            let copy_end_inclusive = cmp::min(page.start_address() + 0xfffu64, end_inclusive);

            let mapping = guard
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

        let guard = self.memory_manager.lock();
        let mapping = guard
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
                let (backing_frame, _) =
                    page_to_frame(backing_page, PageTableFlags::GLOBAL).unwrap();

                let mut flags = PageTableFlags::USER | PageTableFlags::EXECUTABLE;
                flags |= PageTableFlags::COW;

                unsafe {
                    map_page(page, backing_frame, flags, &mut &DUMB_FRAME_ALLOCATOR);
                }
            }
            FileSnapshot::Owned(_) => todo!(),
        }

        let ptr = page.start_address().as_mut_ptr::<[u8; 0x1000]>();
        Ok(ptr)
    }

    fn remove_cow(&self, page: Page) -> Result<*mut [u8; 4096]> {
        let ptr = page.start_address().as_mut_ptr::<[u8; 0x1000]>();

        self.make_readable(page)?;

        let (_, flags) = page_to_frame(page, PageTableFlags::USER).ok_or(Error::Fault)?;

        if !flags.contains(PageTableFlags::COW) {
            return Ok(ptr);
        }

        let frame = (&DUMB_FRAME_ALLOCATOR).allocate_frame().unwrap();
        let new_flags = flags & !PageTableFlags::COW;

        let mut content = [0; 0x1000];
        without_smap(|| unsafe {
            core::intrinsics::volatile_copy_nonoverlapping_memory(&mut content, ptr, 1);
        });

        unsafe {
            unmap_page(page, PageTableFlags::USER);
            // FIXME: We should copy the content before mapping the frame into userspace.
            // FIXME: We should do the remap atomically.
            map_page(page, frame, new_flags, &mut &DUMB_FRAME_ALLOCATOR);
        }

        without_smap(|| {
            without_write_protect(|| unsafe {
                core::intrinsics::volatile_copy_nonoverlapping_memory(ptr, &content, 1);
            })
        });

        Ok(ptr)
    }

    fn make_writable(&self, page: Page) -> Result<*mut [u8; 4096]> {
        assert!(self.contains(page.start_address()));

        if !self.permissions.contains(MemoryPermissions::WRITE) {
            // FIXME: Or ACCESS?
            return Err(Error::Fault);
        }

        let ptr = page.start_address().as_mut_ptr::<[u8; 0x1000]>();

        if let Some((_, flags)) = page_to_frame(page, PageTableFlags::USER) {
            if !flags.contains(PageTableFlags::WRITABLE) {
                // Check if we have to copy the page.
                if flags.contains(PageTableFlags::COW) {
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

                            let frame = (&DUMB_FRAME_ALLOCATOR).allocate_frame().unwrap();

                            let mut flags = PageTableFlags::USER | PageTableFlags::WRITABLE;
                            if self.permissions.contains(MemoryPermissions::EXECUTE) {
                                flags |= PageTableFlags::EXECUTABLE;
                            }

                            unsafe {
                                map_page(page, frame, flags, &mut &DUMB_FRAME_ALLOCATOR);
                            }

                            // FIXME: We shouldn't expose the unwritten page to userspace.
                            without_smap(|| unsafe {
                                core::intrinsics::volatile_copy_nonoverlapping_memory(
                                    ptr,
                                    backing_bytes.as_ptr().cast(),
                                    1,
                                );
                            });
                        }
                        FileSnapshot::Owned(_) => todo!(),
                    }
                }
                Backing::Zero | Backing::Stack => {
                    let frame = (&DUMB_FRAME_ALLOCATOR).allocate_frame().unwrap();

                    let mut flags = PageTableFlags::USER | PageTableFlags::WRITABLE;
                    if self.permissions.contains(MemoryPermissions::EXECUTE) {
                        flags |= PageTableFlags::EXECUTABLE;
                    }
                    unsafe {
                        map_page(page, frame, flags, &mut &DUMB_FRAME_ALLOCATOR);
                    }

                    // FIXME: We shouldn't expose the unzeroed page to userspace.
                    without_smap(|| unsafe {
                        core::intrinsics::volatile_set_memory(ptr, 0, 1);
                    });
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

        if page_to_frame(page, PageTableFlags::USER).is_some() {
            // FIXME: Double check that the page is writable.
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
                            let (backing_frame, _) =
                                page_to_frame(backing_page, PageTableFlags::GLOBAL).unwrap();

                            let mut flags = PageTableFlags::USER;
                            if self.permissions.contains(MemoryPermissions::EXECUTE) {
                                flags |= PageTableFlags::EXECUTABLE;
                            }
                            flags |= PageTableFlags::COW;
                            unsafe {
                                map_page(page, backing_frame, flags, &mut &DUMB_FRAME_ALLOCATOR);
                            }
                        }
                        FileSnapshot::Owned(_) => todo!(),
                    }
                }
                Backing::Zero => {
                    // FIXME: We could map a specific zero frame.
                    let frame = (&DUMB_FRAME_ALLOCATOR).allocate_frame().unwrap();

                    let mut flags = PageTableFlags::USER;
                    if self.permissions.contains(MemoryPermissions::WRITE) {
                        flags |= PageTableFlags::WRITABLE;
                    }
                    if self.permissions.contains(MemoryPermissions::EXECUTE) {
                        flags |= PageTableFlags::EXECUTABLE;
                    }
                    unsafe {
                        map_page(page, frame, flags, &mut &DUMB_FRAME_ALLOCATOR);
                    }

                    // FIXME: We shouldn't expose the unzeroed page to userspace.
                    without_smap(|| {
                        without_write_protect(|| unsafe {
                            core::intrinsics::volatile_set_memory(ptr, 0, 1);
                        })
                    });
                }
                _ => todo!(),
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

enum Backing {
    File(FileBacking),
    Zero,
    Stack,
}

struct FileBacking {
    offset: u64,
    bytes: FileSnapshot,
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
