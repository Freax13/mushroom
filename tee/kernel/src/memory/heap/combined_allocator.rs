use core::{
    alloc::{Allocator, GlobalAlloc, Layout},
    cmp::Ordering,
    ptr::{null_mut, NonNull},
};

use super::{fallback_allocator::FallbackAllocator, fixed_size_allocator::FixedSizeAllocator};

macro_rules! with_buckets {
    ($macro:ident) => {
        $macro!(8, 16, 24, 32, 40, 48, 64, 96, 128, 256, 512, 1024)
    };
}

macro_rules! bucket_type {
    ($last:expr) => {
        FallbackAllocator<FixedSizeAllocator<A, $last>, A>
    };
    ($first:expr, $($next:expr),*) => {
        FallbackAllocator<FixedSizeAllocator<A, $first>, bucket_type!($($next),*)>
    };
}

type CombinedAllocator<A> = with_buckets!(bucket_type);

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
        macro_rules! new {
            ($last:expr) => {
                FallbackAllocator::new(FixedSizeAllocator::<_, $last>::new(allocator), allocator)
            };
            ($first:expr, $($next:expr),*) => {
                FallbackAllocator::new(FixedSizeAllocator::<_, $first>::new(allocator), new!($($next),*))
            };
        }

        let allocator = with_buckets!(new);

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

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return null_mut();
        };

        match layout.size().cmp(&new_size) {
            Ordering::Less => unsafe {
                self.allocator
                    .grow(NonNull::new_unchecked(ptr), layout, new_layout)
                    .map_or_else(|_| null_mut(), NonNull::as_mut_ptr)
            },
            Ordering::Equal => unreachable!(),
            Ordering::Greater => unsafe {
                self.allocator
                    .shrink(NonNull::new_unchecked(ptr), layout, new_layout)
                    .map_or_else(|_| null_mut(), NonNull::as_mut_ptr)
            },
        }
    }
}
