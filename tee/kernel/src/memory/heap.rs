use core::{
    alloc::{Allocator, GlobalAlloc, Layout},
    sync::atomic::AtomicU64,
};

use self::{combined_allocator::Combined, huge_allocator::HugeAllocator};

use super::frame::{DumbFrameAllocator, DUMB_FRAME_ALLOCATOR};

mod combined_allocator;
mod fallback_allocator;
mod fixed_size_allocator;
mod huge_allocator;

static HUGE_ALLOCATOR: HugeAllocator<&DumbFrameAllocator> =
    HugeAllocator::new(&DUMB_FRAME_ALLOCATOR);

#[global_allocator]
static GLOBAL: Combined<&HugeAllocator<&DumbFrameAllocator>> = Combined::new(&HUGE_ALLOCATOR);

struct BumpAllocator {
    current_addr: AtomicU64,
}

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        todo!("{layout:?}")
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[alloc_error_handler]
fn alloc_error_handler(layout: Layout) -> ! {
    panic!("failed to allocate {layout:?}")
}
