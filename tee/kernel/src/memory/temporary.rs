use core::{
    arch::asm,
    cell::{RefCell, RefMut},
};

use crate::spin::{lazy::Lazy, mutex::Mutex};
use constants::{physical_address::DYNAMIC, virtual_address::TEMPORARY};
use x86_64::structures::paging::{page::PageRangeInclusive, Page, PhysFrame, Size4KiB};

use crate::{
    error::Result,
    memory::pagetable::{map_page, PresentPageTableEntry},
    per_cpu::PerCpu,
};

use super::pagetable::{unmap_page, PageTableFlags};

/// We have a physical mapping of `DYNAMIC` at `0xffff_8080_0000_0000`. Using
/// this mapping is a lot faster than creating and destroying a temporary
/// mapping.
#[inline(always)]
fn get_fast_mapping(frame: PhysFrame) -> Option<*mut [u8; 4096]> {
    (DYNAMIC.start.start_address()..DYNAMIC.end.start_address())
        .contains(&frame.start_address())
        .then(|| {
            (frame.start_address().as_u64() - DYNAMIC.start.start_address().as_u64()
                + 0xffff_8080_0000_0000) as *mut _
        })
}

/// Copy bytes into a frame.
///
/// # Safety
///
/// Writing to the frame must be safe.
#[inline(always)]
pub unsafe fn copy_into_frame(frame: PhysFrame, bytes: &[u8; 0x1000]) -> Result<()> {
    if let Some(dst) = get_fast_mapping(frame) {
        unsafe { copy_into_page_direct(bytes, dst) };
        Ok(())
    } else {
        unsafe { copy_into_frame_slow(frame, bytes) }
    }
}

#[inline(never)]
#[cold]
pub unsafe fn copy_into_frame_slow(frame: PhysFrame, bytes: &[u8; 0x1000]) -> Result<()> {
    let mut mapping = TemporaryMapping::new(frame)?;
    unsafe {
        copy_into_page_direct(bytes.as_ptr().cast(), mapping.as_mut_ptr());
    }
    Ok(())
}

#[inline(always)]
unsafe fn copy_into_page_direct(src: *const [u8; 4096], dst: *mut [u8; 4096]) {
    assert!(dst.is_aligned_to(32));

    if src.is_aligned_to(32) {
        unsafe {
            asm! {
                "66:",
                "vmovdqa ymm0, [{src}]",
                "vmovdqa [{dst}], ymm0",
                "add {src}, 32",
                "add {dst}, 32",
                "loop 66b",
                src = inout(reg) src => _,
                dst = inout(reg) dst => _,
                inout("ecx") 4096 / 32 => _,
                options(nostack),
            }
        }
    } else {
        unsafe {
            asm! {
                "66:",
                "vmovdqu ymm0, [{src}]",
                "vmovdqa [{dst}], ymm0",
                "add {src}, 32",
                "add {dst}, 32",
                "loop 66b",
                src = inout(reg) src => _,
                dst = inout(reg) dst => _,
                inout("ecx") 4096 / 32 => _,
                options(nostack),
            }
        }
    }
}

struct TemporaryMapping {
    page: RefMut<'static, Page>,
}

impl TemporaryMapping {
    pub fn new(frame: PhysFrame) -> Result<Self> {
        static PAGES: Lazy<Mutex<PageRangeInclusive<Size4KiB>>> =
            Lazy::new(|| Mutex::new(TEMPORARY.into_iter()));

        let per_cpu = PerCpu::get()
            .temporary_mapping
            .get_or_init(|| RefCell::new(PAGES.lock().next().unwrap()));

        let page = per_cpu.borrow_mut();
        let entry =
            PresentPageTableEntry::new(frame, PageTableFlags::WRITABLE | PageTableFlags::GLOBAL);
        unsafe {
            map_page(*page, entry)?;
        }

        Ok(Self { page })
    }

    pub fn as_mut_ptr(&mut self) -> *mut [u8; 4096] {
        self.page.start_address().as_mut_ptr()
    }
}

impl Drop for TemporaryMapping {
    fn drop(&mut self) {
        unsafe {
            unmap_page(*self.page);
        }
    }
}
