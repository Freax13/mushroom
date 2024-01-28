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

    unsafe fn grow(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        match (
            self.first_choice.can_allocate(old_layout),
            self.first_choice.can_allocate(new_layout),
        ) {
            (true, true) => {
                // Stay with first choice.
                unsafe { self.first_choice.grow(ptr, old_layout, new_layout) }
            }
            (true, false) => {
                // Move from first choice to fallback.
                let new_ptr = self.fallback.allocate(new_layout)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        ptr.as_ptr(),
                        new_ptr.as_mut_ptr(),
                        old_layout.size(),
                    );
                }
                unsafe {
                    self.first_choice.deallocate(ptr, old_layout);
                }
                Ok(new_ptr)
            }
            (false, true) => {
                // Move from fallback to first choice.
                let new_ptr = self.first_choice.allocate(new_layout)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        ptr.as_ptr(),
                        new_ptr.as_mut_ptr(),
                        old_layout.size(),
                    );
                }
                unsafe {
                    self.fallback.deallocate(ptr, old_layout);
                }
                Ok(new_ptr)
            }
            (false, false) => {
                // Stay with first fallback.
                unsafe { self.fallback.grow(ptr, old_layout, new_layout) }
            }
        }
    }

    unsafe fn grow_zeroed(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        match (
            self.first_choice.can_allocate(old_layout),
            self.first_choice.can_allocate(new_layout),
        ) {
            (true, true) => {
                // Stay with first choice.
                unsafe { self.first_choice.grow_zeroed(ptr, old_layout, new_layout) }
            }
            (true, false) => {
                // Move from first choice to fallback.
                let new_ptr = self.fallback.allocate_zeroed(new_layout)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        ptr.as_ptr(),
                        new_ptr.as_mut_ptr(),
                        old_layout.size(),
                    );
                }
                unsafe {
                    self.first_choice.deallocate(ptr, old_layout);
                }
                Ok(new_ptr)
            }
            (false, true) => {
                // Move from fallback to first choice.
                let new_ptr = self.first_choice.allocate(new_layout)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        ptr.as_ptr(),
                        new_ptr.as_mut_ptr(),
                        old_layout.size(),
                    );
                }
                unsafe {
                    self.fallback.deallocate(ptr, old_layout);
                }
                Ok(new_ptr)
            }
            (false, false) => {
                // Stay with first fallback.
                unsafe { self.fallback.grow_zeroed(ptr, old_layout, new_layout) }
            }
        }
    }

    unsafe fn shrink(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        match (
            self.first_choice.can_allocate(old_layout),
            self.first_choice.can_allocate(new_layout),
        ) {
            (true, true) => {
                // Stay with first choice.
                unsafe { self.first_choice.shrink(ptr, old_layout, new_layout) }
            }
            (true, false) => {
                // Move from first choice to fallback.
                let new_ptr = self.fallback.allocate(new_layout)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        ptr.as_ptr(),
                        new_ptr.as_mut_ptr(),
                        new_layout.size(),
                    );
                }
                unsafe {
                    self.first_choice.deallocate(ptr, old_layout);
                }
                Ok(new_ptr)
            }
            (false, true) => {
                // Move from fallback to first choice.
                let new_ptr = self.first_choice.allocate(new_layout)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        ptr.as_ptr(),
                        new_ptr.as_mut_ptr(),
                        new_layout.size(),
                    );
                }
                unsafe {
                    self.fallback.deallocate(ptr, old_layout);
                }
                Ok(new_ptr)
            }
            (false, false) => {
                // Stay with first fallback.
                unsafe { self.fallback.shrink(ptr, old_layout, new_layout) }
            }
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
