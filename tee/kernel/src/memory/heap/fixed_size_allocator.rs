use core::{
    alloc::{AllocError, Allocator, Layout},
    mem::size_of,
    ptr::NonNull,
};

use alloc::vec::Vec;
use constants::physical_address::DYNAMIC;
use x86_64::{
    align_down,
    structures::paging::{FrameAllocator, FrameDeallocator, PageSize, PhysFrame, Size2MiB},
};

use crate::{spin::mutex::Mutex, supervisor};

use super::fallback_allocator::LimitedAllocator;

pub struct FixedSizeAllocator<A, const N: usize>
where
    A: Allocator,
{
    state: Mutex<FixedSizeAllocatorState<A, N>>,
}

/// The mutable state of a `FixedSizeAllocator`.
struct FixedSizeAllocatorState<A, const N: usize>
where
    A: Allocator,
{
    /// A sorted list of chunks.
    chunks: Vec<NonNull<ChunkHeader<N>>, A>,
    /// This field contains a hint for a chunk that may have more allocation
    /// slots available.
    last_idx: usize,
    /// This field contains a hint for a chunk that may have more allocation
    /// slots available. The hint is not none, the chunk has to be valid.
    good_chunk: Option<NonNull<ChunkHeader<N>>>,
}

impl<A, const N: usize> FixedSizeAllocator<A, N>
where
    A: Allocator,
{
    pub const fn new(allocator: A) -> Self {
        Self {
            state: Mutex::new(FixedSizeAllocatorState {
                chunks: Vec::new_in(allocator),
                last_idx: 0,
                good_chunk: None,
            }),
        }
    }
}

unsafe impl<A: Send, const N: usize> Send for FixedSizeAllocator<A, N> where A: Allocator {}
unsafe impl<A: Sync, const N: usize> Sync for FixedSizeAllocator<A, N> where A: Allocator {}

unsafe impl<A, const N: usize> LimitedAllocator for FixedSizeAllocator<A, N>
where
    A: Allocator,
{
    fn can_allocate(&self, layout: Layout) -> bool {
        layout.size() <= N && layout.align() <= N
    }
}

unsafe impl<A, const N: usize> Allocator for FixedSizeAllocator<A, N>
where
    A: Allocator,
{
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let mut guard = self.state.lock();

        // Try to allocate from a chunk we suspect may be able to serve the
        // allocation.
        if let Some(chunk) = guard.good_chunk {
            let chunk = unsafe { chunk.as_ref() };
            if let Ok(ptr) = chunk.allocate(layout) {
                return Ok(ptr);
            } else {
                guard.good_chunk = None;
            }
        }

        // Iterate over all chunks starting with `last_idx`, but keep their
        // original indices.
        let chunks = guard
            .chunks
            .iter()
            .map(|chunk| unsafe { chunk.as_ref() })
            .enumerate()
            .cycle()
            .skip(guard.last_idx)
            .take(guard.chunks.len());
        // Try to allocate from existing chunks.
        for (i, chunk) in chunks {
            let Ok(ptr) = chunk.allocate(layout) else {
                continue;
            };
            guard.good_chunk = Some(NonNull::from(chunk));
            guard.last_idx = i;
            return Ok(ptr);
        }

        // We'll have to create a new chunk.

        // Allocate a new chunk.
        let chunk = ChunkHeader::<N>::new()?;

        // Store the chunk in the correct position.
        let idx = guard.chunks.binary_search(&chunk).unwrap_err();
        guard.chunks.insert(idx, chunk);

        // Update hints.
        guard.last_idx = idx;
        guard.good_chunk = Some(chunk);

        // Allocate from the chunk.
        let chunk_ref = unsafe { chunk.as_ref() };
        let ptr = chunk_ref.allocate(layout).unwrap();
        Ok(ptr)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // Do some pointer match to get a pointer to the chunk that was used to
        // allocate `ptr`.
        let chunk_header = align_down(ptr.as_ptr() as u64, Size2MiB::SIZE);
        let chunk_header = unsafe { &*(chunk_header as *const ChunkHeader<N>) };
        // Deallocate the memory.
        let now_unused = unsafe { chunk_header.deallocate(ptr, layout) };

        if now_unused {
            // The chunk is completly unused. Try to release it.

            let ptr = NonNull::from(chunk_header);

            // Take an allocator-wide lock to prevent racing try_free.
            let mut guard = self.state.lock();
            let idx = guard.chunks.binary_search(&ptr).unwrap();

            let res = unsafe { ChunkHeader::try_free(ptr.as_ptr()) };
            if res.is_ok() {
                // Deallocation succeeded.

                guard.chunks.remove(idx);

                // Make sure we don't recommend allocating from this chunk
                // anymore.
                if guard.good_chunk == Some(ptr) {
                    guard.good_chunk = None;
                }
            } else {
                // Deallocation failed. It's now a good candidate for future
                // allocations because it has plenty of available spots.
                guard.last_idx = idx;
                guard.good_chunk = Some(ptr);
            }
        }
    }

    unsafe fn grow(
        &self,
        ptr: NonNull<u8>,
        _old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        // Fail if the new layout exceeds the size.
        if new_layout.size() > N || new_layout.align() > N {
            return Err(AllocError);
        }

        Ok(unsafe { NonNull::new_unchecked(core::ptr::slice_from_raw_parts_mut(ptr.as_ptr(), N)) })
    }

    unsafe fn grow_zeroed(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        // Fail if the new layout exceeds the size.
        if new_layout.size() > N || new_layout.align() > N {
            return Err(AllocError);
        }

        unsafe {
            core::ptr::write_bytes(
                ptr.as_ptr().add(old_layout.size()),
                0,
                N - old_layout.size(),
            );
        }
        Ok(unsafe { NonNull::new_unchecked(core::ptr::slice_from_raw_parts_mut(ptr.as_ptr(), N)) })
    }

    unsafe fn shrink(
        &self,
        ptr: NonNull<u8>,
        _old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        if new_layout.align() > N {
            return Err(AllocError);
        }
        Ok(unsafe { NonNull::new_unchecked(core::ptr::slice_from_raw_parts_mut(ptr.as_ptr(), N)) })
    }
}

impl<A, const N: usize> Drop for FixedSizeAllocator<A, N>
where
    A: Allocator,
{
    fn drop(&mut self) {
        unimplemented!()
    }
}

#[repr(align(64))]
struct ChunkHeader<const N: usize> {
    state: Mutex<ChunkHeaderState<N>>,
    frame: PhysFrame<Size2MiB>,
}

impl<const N: usize> ChunkHeader<N> {
    pub fn new() -> Result<NonNull<Self>, AllocError> {
        // Allocate physical memory.
        let frame = (&supervisor::ALLOCATOR)
            .allocate_frame()
            .ok_or(AllocError)?;

        // Get a pointer in the mapping of all dynamic memory.
        let addr = frame.start_address().as_u64() - DYNAMIC.start.start_address().as_u64()
            + 0xffff_8080_0000_0000;

        // Map shadow memory for the chunk.
        #[cfg(sanitize = "address")]
        crate::sanitize::map_shadow(addr as *mut _, Size2MiB::SIZE as usize);
        // Forbid accessing the entries.
        #[cfg(sanitize = "address")]
        unsafe {
            crate::sanitize::mark(
                (addr as usize + Self::first_offset()) as *mut _,
                Size2MiB::SIZE as usize - Self::first_offset(),
                false,
            );
        }

        // Initialize the header.
        let ptr = unsafe { NonNull::new_unchecked(addr as *mut Self) };
        unsafe {
            ptr.as_ptr().write(Self {
                state: Mutex::new(ChunkHeaderState {
                    init: 0,
                    next_entry: None,
                    used: 0,
                }),
                frame,
            })
        };
        Ok(ptr)
    }

    /// Returns the offset of the first allocation in a chunk.
    const fn first_offset() -> usize {
        size_of::<ChunkHeader<N>>().next_multiple_of(N)
    }

    /// Returns the number of allocations that can fit in a chunk.
    const fn capacity() -> usize {
        let size = 512 * 4096;
        let usable_size = size - Self::first_offset();
        usable_size / N
    }

    /// Release the chunk.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that this function isn't called concurrently
    /// for the same chunk.
    unsafe fn try_free(ptr: *const Self) -> Result<(), ()> {
        let this = unsafe { &*ptr };

        {
            // Double-check that the chunk can be released.
            let guard = this.state.lock();
            if guard.used > 0 {
                return Err(());
            }
        }

        // Get the frame.
        let frame = this.frame;

        // Unmap shadow memory for the chunk.
        #[cfg(sanitize = "address")]
        crate::sanitize::unmap_shadow(ptr as *mut _, Size2MiB::SIZE as usize);

        // Release the physical memory.
        unsafe {
            (&supervisor::ALLOCATOR).deallocate_frame(frame);
        }

        Ok(())
    }

    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        if layout.size() > N || layout.align() > N {
            return Err(AllocError);
        }

        let mut guard = self.state.lock();
        let entry = if let Some(pointer) = guard.next_entry {
            // Pop and entry from the free list.
            let entry = unsafe { pointer.as_ref() };

            // Allow accessing the entry.
            #[cfg(sanitize = "address")]
            unsafe {
                crate::sanitize::mark(entry as *const _ as *mut _, N, true);
            }

            guard.next_entry = unsafe { entry.next };
            entry
        } else if guard.init < Self::capacity() {
            // Use up an uninitialized entry.

            // Get a pointer to the next entry.
            let pointer = (self as *const Self)
                .wrapping_byte_add(Self::first_offset())
                .cast::<Entry<N>>()
                .wrapping_add(guard.init);

            // Allow accessing the entry.
            #[cfg(sanitize = "address")]
            unsafe {
                crate::sanitize::mark(pointer as *mut _, N, true);
            }

            guard.init += 1;
            unsafe { &*pointer }
        } else {
            return Err(AllocError);
        };
        guard.used += 1;
        drop(guard);

        Ok(NonNull::from(unsafe { &entry.bytes }))
    }

    /// Returns `true` if the chunk is completly unused.
    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) -> bool {
        let entry = unsafe { ptr.cast::<Entry<N>>().as_mut() };

        let mut guard = self.state.lock();
        // Push the entry onto the free list.
        entry.next = guard.next_entry;

        // Forbid accessing the entry.
        #[cfg(sanitize = "address")]
        unsafe {
            crate::sanitize::mark(entry as *const _ as *mut _, N, false);
        }

        guard.next_entry = Some(NonNull::from(entry));
        guard.used -= 1;
        guard.used == 0
    }
}

struct ChunkHeaderState<const N: usize> {
    /// Counts how many `Entry`s have been initialized. Starts out as `0` and
    /// increases over time as the first allocations are served.
    init: usize,
    /// An intrusive singly-linked free list.
    next_entry: Option<NonNull<Entry<N>>>,
    /// Counts the number of allocations currently in use.
    used: usize,
}

#[repr(C)]
union Entry<const N: usize> {
    next: Option<NonNull<Entry<N>>>,
    bytes: [u8; N],
}
