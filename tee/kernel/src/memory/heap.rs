use core::alloc::Layout;

use self::{combined_allocator::Combined, huge_allocator::HugeAllocator};

use super::frame::{BitmapFrameAllocator, FRAME_ALLOCATOR};

mod combined_allocator;
mod fallback_allocator;
mod fixed_size_allocator;
mod huge_allocator;

static HUGE_ALLOCATOR: HugeAllocator<&BitmapFrameAllocator> = HugeAllocator::new(&FRAME_ALLOCATOR);

#[global_allocator]
static GLOBAL: Combined<&HugeAllocator<&BitmapFrameAllocator>> = Combined::new(&HUGE_ALLOCATOR);

#[alloc_error_handler]
fn alloc_error_handler(layout: Layout) -> ! {
    panic!("failed to allocate {layout:?}")
}
