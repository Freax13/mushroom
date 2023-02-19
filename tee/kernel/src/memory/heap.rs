use core::alloc::Layout;

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

#[alloc_error_handler]
fn alloc_error_handler(layout: Layout) -> ! {
    panic!("failed to allocate {layout:?}")
}
