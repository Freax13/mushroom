use core::{
    alloc::Layout,
    ops::{Bound, RangeBounds},
    ptr::{copy_nonoverlapping, slice_from_raw_parts_mut, NonNull},
    sync::atomic::{AtomicU64, Ordering},
};

use alloc::alloc::{alloc, alloc_zeroed, dealloc};
use constants::physical_address::DYNAMIC;
use x86_64::structures::paging::PhysFrame;

use crate::{
    error::{err, Result},
    spin::lazy::Lazy,
};

static ZERO: Lazy<KernelPage> = Lazy::new(|| {
    let content = unsafe { alloc_zeroed(Layout::new::<PageContent>()) };
    let content = NonNull::new(content.cast()).unwrap();

    KernelPage {
        content,
        reference_count: None,
    }
});

/// A smart pointer for a 4KiB chunk of memory. This type supports CoW.
pub struct KernelPage {
    content: NonNull<PageContent>,
    reference_count: Option<NonNull<AtomicU64>>,
}

impl KernelPage {
    /// Return a `KernelPage` whose content is zero.
    pub fn zeroed() -> Self {
        Self {
            content: ZERO.content,
            reference_count: None,
        }
    }

    fn is_zero_page(&self) -> bool {
        // The ZERO page is special because we never assign it a reference
        // count -> If `self` has a reference count it's not the zero page.
        if self.reference_count.is_some() {
            return false;
        }

        let zero = unsafe {
            // Safety: The only constructor for `KernelPage` always initializes
            // `ZERO`. We know that the constructor has been called at least
            // once because `self` exists.
            ZERO.get_unchecked()
        };
        self.content == zero.content
    }

    /// Create a shallow copy of the page.
    pub fn clone(&mut self) -> Result<Self> {
        if self.is_zero_page() {
            // Don't increase the reference count for the zero page.
        } else {
            let reference_count = if let Some(reference_count) = self.reference_count {
                reference_count
            } else {
                // Initialize the reference count.
                let reference_count = unsafe { alloc(Layout::new::<AtomicU64>()) };
                let reference_count = NonNull::new(reference_count).ok_or(err!(NoMem))?;
                let reference_count = reference_count.cast::<AtomicU64>();
                unsafe {
                    reference_count.as_ptr().write(AtomicU64::new(1));
                }
                self.reference_count = Some(reference_count);
                reference_count
            };

            // Increase the reference count.
            let reference_count = unsafe { reference_count.as_ref() };
            reference_count.fetch_add(1, Ordering::SeqCst);
        }

        Ok(Self {
            content: self.content,
            reference_count: self.reference_count,
        })
    }

    /// Returns whether page's content may be modified.
    pub fn mutable(&self, shared: bool) -> bool {
        if self.is_zero_page() {
            // The zero page should never be modified.
            return false;
        }

        self.reference_count.is_none() || shared
    }

    /// Ensure that this `KernelPage` is mutable. Shared memory is always
    /// mutable (except for the zero page).
    pub fn make_mut(&mut self, shared: bool) -> Result<()> {
        // Fast-path check to see if we already have unique ownership over
        // `content`.
        if !self.is_zero_page() {
            if shared {
                return Ok(());
            }

            let Some(reference_count) = self.reference_count.take() else {
                // If there is no reference count, we don't need to do anything.
                return Ok(());
            };

            let rc = {
                let reference_count = unsafe { reference_count.as_ref() };
                reference_count.load(Ordering::SeqCst)
            };
            if rc == 1 {
                // If the reference count is one, we can take ownership of the memory.

                // Deallocate the reference count.
                unsafe {
                    dealloc(reference_count.as_ptr().cast(), Layout::new::<AtomicU64>());
                }

                return Ok(());
            }

            // The fast path didn't work. Restore the reference count.
            self.reference_count = Some(reference_count);
        }

        let content = unsafe { alloc(Layout::new::<PageContent>()) };
        let content = NonNull::new(content.cast::<PageContent>()).ok_or(err!(NoMem))?;
        // Copy the memory to the new allocation.
        unsafe {
            copy_nonoverlapping(self.content.as_ptr(), content.as_ptr(), 1);
        }

        // Replace self with the new allocation.
        *self = Self {
            content,
            reference_count: None,
        };

        Ok(())
    }

    #[track_caller]
    pub fn index(&self, range: impl RangeBounds<usize>) -> NonNull<[u8]> {
        let start = match range.start_bound() {
            Bound::Included(&idx) => idx,
            Bound::Excluded(&idx) => idx + 1,
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(&idx) => idx + 1,
            Bound::Excluded(&idx) => idx,
            Bound::Unbounded => 0x1000,
        };
        assert!(start <= 0x1000, "{start} is out of range");
        assert!(end <= 0x1000, "{end} is out of range");

        let len = end.saturating_sub(start);

        let base = self.content.as_ptr().cast::<u8>();
        let data = unsafe { base.add(start) };
        let offset = slice_from_raw_parts_mut(data, len);
        unsafe { NonNull::new_unchecked(offset) }
    }

    pub fn frame(&self) -> PhysFrame {
        let vaddr = self.content.as_ptr() as u64;
        let paddr = DYNAMIC.start.start_address() + (vaddr - 0xffff_8080_0000_0000);
        PhysFrame::from_start_address(paddr).unwrap()
    }

    /// Zero the bytes in the specified range.
    pub fn zero_range(&mut self, range: impl RangeBounds<usize>, shared: bool) -> Result<()> {
        // Check if `range` is empty.
        let start = match range.start_bound() {
            Bound::Included(&start) => start,
            Bound::Excluded(&start) => start + 1,
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(&end) => end + 1,
            Bound::Excluded(&end) => end,
            Bound::Unbounded => 0x1000,
        };
        let len = end.saturating_sub(start);
        if len == 0 {
            return Ok(());
        }

        // We don't need to do anything for the zero page.
        if self.is_zero_page() {
            return Ok(());
        }

        self.make_mut(shared)?;
        let content = self.index(range);
        unsafe {
            core::intrinsics::volatile_set_memory(content.as_mut_ptr(), 0, content.len());
        }

        Ok(())
    }
}

unsafe impl Send for KernelPage {}
unsafe impl Sync for KernelPage {}

impl Drop for KernelPage {
    fn drop(&mut self) {
        if self.is_zero_page() {
            // We don't need to do any memory management for the zero page.
            return;
        }

        if let Some(reference_count) = self.reference_count {
            // Decrease the reference count.
            let rc = {
                let reference_count = unsafe { reference_count.as_ref() };
                reference_count.fetch_sub(1, Ordering::SeqCst)
            };

            // Don't free any memory if the reference count didn't hit 0.
            if rc != 1 {
                return;
            }

            // Free the reference count.
            unsafe {
                dealloc(reference_count.as_ptr().cast(), Layout::new::<AtomicU64>());
            }
        }

        // Free the page's memory.
        unsafe {
            dealloc(self.content.as_ptr().cast(), Layout::new::<PageContent>());
        }
    }
}

#[repr(C, align(4096))]
pub(super) struct PageContent(pub [u8; 4096]);
