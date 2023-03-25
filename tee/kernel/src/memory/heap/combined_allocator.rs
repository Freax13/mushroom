use core::{
    alloc::{Allocator, GlobalAlloc, Layout},
    ptr::{null_mut, NonNull},
};

use super::{fallback_allocator::FallbackAllocator, fixed_size_allocator::FixedSizeAllocator};

type CombinedAllocator<A> = FallbackAllocator<
    FallbackAllocator<
        FallbackAllocator<
            FixedSizeAllocator<A, 8>,
            FallbackAllocator<
                FixedSizeAllocator<A, 16>,
                FallbackAllocator<
                    FixedSizeAllocator<A, 24>,
                    FallbackAllocator<
                        FixedSizeAllocator<A, 32>,
                        FallbackAllocator<FixedSizeAllocator<A, 48>, FixedSizeAllocator<A, 64>>,
                    >,
                >,
            >,
        >,
        FixedSizeAllocator<A, 1024>,
    >,
    A,
>;

#[allow(clippy::type_complexity)]
pub struct Combined<A>
where
    A: Allocator,
{
    allocator: CombinedAllocator<A>,
}

impl<A> Combined<A>
where
    A: Allocator,
{
    // FIXME: This should just take `A` where `A: Copy`. https://github.com/rust-lang/rust-clippy/issues/10535
    pub const fn new(allocator: &'static A) -> Combined<&'static A> {
        let small8 = FixedSizeAllocator::<_, 8>::new(allocator);
        let small16 = FixedSizeAllocator::<_, 16>::new(allocator);
        let small24 = FixedSizeAllocator::<_, 24>::new(allocator);
        let small32 = FixedSizeAllocator::<_, 32>::new(allocator);
        let small48 = FixedSizeAllocator::<_, 48>::new(allocator);
        let small64 = FixedSizeAllocator::<_, 64>::new(allocator);

        let fallback = FallbackAllocator::new(small48, small64);
        let fallback = FallbackAllocator::new(small32, fallback);
        let fallback = FallbackAllocator::new(small24, fallback);
        let fallback = FallbackAllocator::new(small16, fallback);
        let small_allocators = FallbackAllocator::new(small8, fallback);

        let big = FixedSizeAllocator::<_, 1024>::new(allocator);
        let big_allocators = big;

        let huge_allocator = allocator;

        let allocator = FallbackAllocator::new(small_allocators, big_allocators);
        let allocator = FallbackAllocator::new(allocator, huge_allocator);

        Combined { allocator }
    }
}

unsafe impl<A> GlobalAlloc for Combined<A>
where
    A: Allocator,
{
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let res = self.allocator.allocate(layout);
        res.map_or(null_mut(), |ptr| ptr.as_ptr().cast())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let ptr = unsafe { NonNull::new_unchecked(ptr) };
        unsafe { self.allocator.deallocate(ptr, layout) }
    }
}
