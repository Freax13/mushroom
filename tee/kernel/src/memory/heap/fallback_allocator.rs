use core::{
    alloc::{AllocError, Allocator, Layout},
    ptr::NonNull,
};

pub struct FallbackAllocator<T, U> {
    first_choice: T,
    fallback: U,
}

impl<T, U> FallbackAllocator<T, U> {
    pub const fn new(first_choice: T, fallback: U) -> Self {
        Self {
            first_choice,
            fallback,
        }
    }
}

unsafe impl<T, U> Allocator for FallbackAllocator<T, U>
where
    T: LimitedAllocator,
    U: Allocator,
{
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        if self.first_choice.can_allocate(layout) {
            self.first_choice.allocate(layout)
        } else {
            self.fallback.allocate(layout)
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        if self.first_choice.can_allocate(layout) {
            unsafe { self.first_choice.deallocate(ptr, layout) }
        } else {
            unsafe { self.fallback.deallocate(ptr, layout) }
        }
    }
}

unsafe impl<T, U> LimitedAllocator for FallbackAllocator<T, U>
where
    T: LimitedAllocator,
    U: LimitedAllocator,
{
    fn can_allocate(&self, layout: Layout) -> bool {
        self.first_choice.can_allocate(layout) || self.fallback.can_allocate(layout)
    }
}

/// # Safety
///
/// `can_allocate` must always return the same result for the same input.
pub unsafe trait LimitedAllocator: Allocator {
    fn can_allocate(&self, layout: Layout) -> bool;
}
