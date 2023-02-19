use core::cell::{RefCell, RefMut};

use constants::virtual_address::TEMPORARY;
use spin::{Lazy, Mutex};
use x86_64::structures::paging::{page::PageRangeInclusive, Page, PhysFrame, Size4KiB};

use crate::{
    memory::{frame::DUMB_FRAME_ALLOCATOR, pagetable::map_page},
    per_cpu::PerCpu,
};

use super::pagetable::{unmap_page, PageTableFlags};

/// Fill a frame with zeros.
///
/// # Safety
///
/// Writing to the frame must be safe.
pub unsafe fn zero_frame(frame: PhysFrame) {
    let mut mapping = TemporaryMapping::new(frame);
    unsafe {
        core::intrinsics::volatile_set_memory(mapping.as_mut_ptr(), 0, 1);
    }
}

/// Copy bytes into a frame.
///
/// # Safety
///
/// Writing to the frame must be safe.
pub unsafe fn copy_into_frame(frame: PhysFrame, bytes: &[u8; 0x1000]) {
    let mut mapping = TemporaryMapping::new(frame);
    unsafe {
        core::intrinsics::volatile_copy_nonoverlapping_memory(mapping.as_mut_ptr(), bytes, 1);
    }
}

struct TemporaryMapping {
    page: RefMut<'static, Page>,
}

impl TemporaryMapping {
    pub fn new(frame: PhysFrame) -> Self {
        static PAGES: Lazy<Mutex<PageRangeInclusive<Size4KiB>>> =
            Lazy::new(|| Mutex::new(TEMPORARY.into_iter()));

        let per_cpu = PerCpu::get()
            .temporary_mapping
            .get_or_init(|| RefCell::new(PAGES.lock().next().unwrap()));

        let page = per_cpu.borrow_mut();

        unsafe {
            map_page(
                *page,
                frame,
                PageTableFlags::WRITABLE | PageTableFlags::GLOBAL,
                &mut (&DUMB_FRAME_ALLOCATOR),
            );
        }

        Self { page }
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
