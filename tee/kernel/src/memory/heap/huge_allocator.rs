use core::{
    alloc::{AllocError, Allocator, Layout},
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};

use usize_conversions::FromUsize;
use x86_64::{
    structures::paging::{Page, Size4KiB},
    VirtAddr,
};

use crate::memory::{
    frame::{allocate_frame, deallocate_frame},
    pagetable::{map_page, unmap_page, PageTableFlags, PresentPageTableEntry},
};

pub struct HugeAllocator {
    bump_addr: AtomicU64,
}

impl HugeAllocator {
    pub const fn new() -> Self {
        Self {
            bump_addr: AtomicU64::new(0xffff_c000_0000_0000),
        }
    }
}

unsafe impl Allocator for HugeAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        #[cfg(not(sanitize = "address"))]
        let min_size = 0x1000;
        #[cfg(sanitize = "address")]
        let min_size = crate::sanitize::MIN_ALLOCATION_SIZE;

        let units = layout.size().div_ceil(min_size);
        let pages = units * (min_size / 0x1000);

        if pages > 0x10000 {
            return Err(AllocError);
        }

        let size = pages * 0x1000;
        let len = u64::from_usize(size);
        let addr = if layout.align() <= min_size {
            self.bump_addr.fetch_add(len, Ordering::SeqCst)
        } else {
            let align = u64::from_usize(layout.align());
            let addr = self
                .bump_addr
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |addr| {
                    let addr = addr.next_multiple_of(align);
                    Some(addr + len)
                })
                .unwrap();
            addr.next_multiple_of(align)
        };

        let addr = VirtAddr::new(addr);
        let base = Page::<Size4KiB>::from_start_address(addr).unwrap();

        for page in (base..).take(pages) {
            let frame = allocate_frame();
            let entry = PresentPageTableEntry::new(
                frame,
                PageTableFlags::WRITABLE | PageTableFlags::GLOBAL,
            );
            let res = unsafe { map_page(page, entry) };
            res.unwrap();
        }

        #[cfg(sanitize = "address")]
        crate::sanitize::map_shadow(addr.as_mut_ptr(), size);

        Ok(NonNull::new(core::ptr::slice_from_raw_parts_mut(addr.as_mut_ptr(), size)).unwrap())
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        #[cfg(sanitize = "address")]
        crate::sanitize::unmap_shadow(
            ptr.as_ptr().cast_const().cast(),
            layout
                .size()
                .next_multiple_of(crate::sanitize::MIN_ALLOCATION_SIZE),
        );

        let pages = layout.size().div_ceil(0x1000);

        let addr = VirtAddr::from_ptr(ptr.as_ptr());
        let base = Page::<Size4KiB>::from_start_address(addr).unwrap();

        for page in (base..).take(pages) {
            let entry = unsafe { unmap_page(page) };
            let frame = entry.frame();
            unsafe {
                deallocate_frame(frame);
            }
        }
    }
}
