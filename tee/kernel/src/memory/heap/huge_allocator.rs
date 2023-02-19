use core::{
    alloc::{AllocError, Allocator, Layout},
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};

use constants::virtual_address::HEAP;
use spin::Mutex;
use x86_64::{
    structures::paging::{FrameAllocator, FrameDeallocator, Page, Size4KiB},
    VirtAddr,
};

use crate::memory::pagetable::{map_page, unmap_page, PageTableFlags, PresentPageTableEntry};

pub struct HugeAllocator<A> {
    allocator: Mutex<A>,
    bump_addr: AtomicU64,
}

impl<A> HugeAllocator<A> {
    pub const fn new(allocator: A) -> Self {
        Self {
            allocator: Mutex::new(allocator),
            bump_addr: AtomicU64::new(HEAP.start()),
        }
    }
}

unsafe impl<A> Allocator for HugeAllocator<A>
where
    A: FrameAllocator<Size4KiB> + FrameDeallocator<Size4KiB>,
{
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let pages = layout.size().div_ceil(0x1000);

        let size = pages * 0x1000;
        let len = u64::try_from(size).map_err(|_| AllocError)?;
        let addr = if layout.align() <= 0x1000 {
            self.bump_addr.fetch_add(len, Ordering::SeqCst)
        } else {
            let align = u64::try_from(layout.align()).unwrap();
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

        let mut allocator = self.allocator.lock();
        for page in (base..).take(pages) {
            let frame = allocator.allocate_frame().unwrap();
            let entry = PresentPageTableEntry::new(
                frame,
                PageTableFlags::WRITABLE | PageTableFlags::GLOBAL,
            );
            let res = unsafe { map_page(page, entry, &mut *allocator) };
            res.unwrap();
        }
        drop(allocator);

        Ok(NonNull::new(core::ptr::slice_from_raw_parts_mut(addr.as_mut_ptr(), size)).unwrap())
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        let pages = layout.size().div_ceil(0x1000);

        let addr = VirtAddr::from_ptr(ptr.as_ptr());
        let base = Page::<Size4KiB>::from_start_address(addr).unwrap();

        let mut allocator = self.allocator.lock();

        for page in (base..).take(pages) {
            let frame = unsafe { unmap_page(page) };
            unsafe {
                allocator.deallocate_frame(frame);
            }
        }
    }
}
