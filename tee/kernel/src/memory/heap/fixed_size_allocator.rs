use core::{
    alloc::{AllocError, Allocator, Layout},
    cell::Cell,
    mem::{align_of, size_of},
    ptr::{addr_of_mut, NonNull},
};

use spin::Mutex;

use super::fallback_allocator::LimitedAllocator;

pub struct FixedSizeAllocator<A, const N: usize> {
    allocator: A,
    block: Mutex<Option<NonNull<Block<N>>>>,
}

impl<A, const N: usize> FixedSizeAllocator<A, N> {
    pub const fn new(allocator: A) -> Self {
        Self {
            allocator,
            block: Mutex::new(None),
        }
    }
}

unsafe impl<A, const N: usize> LimitedAllocator for FixedSizeAllocator<A, N>
where
    A: Allocator,
{
    fn can_allocate(&self, layout: Layout) -> bool {
        layout.size() <= N && layout.align() <= align_of::<Entry<N>>()
    }
}

unsafe impl<A, const N: usize> Allocator for FixedSizeAllocator<A, N>
where
    A: Allocator,
{
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        if !self.can_allocate(layout) {
            return Err(AllocError);
        }

        let mut guard = self.block.lock();

        let block = if let Some(block) = &mut *guard {
            block
        } else {
            guard.insert(Block::new(&self.allocator)?)
        };

        let mut block = unsafe { block.as_mut() };
        loop {
            let res = block.allocate(layout);
            if let Ok(res) = res {
                break Ok(res);
            } else {
                block = block.make_mut(&self.allocator)?;
            }
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        let guard = self.block.lock();

        let mut first_block = guard.unwrap();
        let mut block = unsafe { first_block.as_mut() };
        loop {
            if block.contains(ptr) {
                unsafe {
                    block.deallocate(ptr, layout);
                }
                return;
            }
            block = block.next().unwrap();
        }
    }
}

unsafe impl<A, const N: usize> Send for FixedSizeAllocator<A, N> {}

unsafe impl<A, const N: usize> Sync for FixedSizeAllocator<A, N> {}

struct Block<const N: usize> {
    next: Option<NonNull<Self>>,
    memory: NonNull<[u8]>,
    free_list: Cell<Option<NonNull<Entry<N>>>>,
}

impl<const N: usize> Block<N> {
    pub fn new<A>(allocator: &A) -> Result<NonNull<Self>, AllocError>
    where
        A: Allocator,
    {
        const MIN_ENTRIES: usize = 128;

        let block_layout = Layout::new::<Self>();
        let entries_layout = Layout::array::<Entry<N>>(MIN_ENTRIES).unwrap();
        let (combined, entries_offset) = block_layout.extend(entries_layout).unwrap();

        let ptr = allocator.allocate(combined)?;
        let total_len = ptr.len();
        let len_for_entries = total_len - entries_offset;
        let num_entries = len_for_entries / size_of::<Entry<N>>();

        let block_ptr = ptr.as_ptr().cast::<Self>();
        let entry_ptr = unsafe { ptr.as_ptr().cast::<Entry<N>>().byte_add(entries_offset) };

        let mut prev = None;
        for i in 0..num_entries {
            let entry_ptr = unsafe { entry_ptr.add(i) };
            let entry_ptr = unsafe { NonNull::new_unchecked(entry_ptr) };
            let entry = Entry { next: prev };
            unsafe {
                entry_ptr.as_ptr().write(entry);
            }
            prev = Some(entry_ptr);
        }

        let block = Block {
            next: None,
            memory: ptr,
            free_list: Cell::new(prev),
        };
        unsafe {
            block_ptr.write(block);
        }

        Ok(unsafe { NonNull::new_unchecked(block_ptr) })
    }

    pub fn next(&mut self) -> Option<&mut Self> {
        let mut ptr = self.next?;
        Some(unsafe { ptr.as_mut() })
    }

    pub fn make_mut<A>(&mut self, allocator: &A) -> Result<&mut Self, AllocError>
    where
        A: Allocator,
    {
        let ptr = self.next;
        if let Some(mut ptr) = ptr {
            return Ok(unsafe { ptr.as_mut() });
        }

        let mut ptr = Self::new(allocator)?;
        self.next = Some(ptr);
        Ok(unsafe { ptr.as_mut() })
    }

    pub fn contains(&self, ptr: NonNull<u8>) -> bool {
        let start_ptr = self.memory.as_ptr().cast::<u8>();
        let end_ptr = unsafe { start_ptr.add(self.memory.len()) };
        (start_ptr..end_ptr).contains(&ptr.as_ptr())
    }
}

unsafe impl<const N: usize> Allocator for Block<N> {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        assert!(layout.size() <= N);
        assert!(layout.align() <= align_of::<Entry<N>>());

        let ptr = self.free_list.get().ok_or(AllocError)?;
        let next_ptr = unsafe { (*ptr.as_ptr()).next };
        self.free_list.set(next_ptr);

        #[cfg(sanitize = "address")]
        unsafe {
            crate::sanitize::mark(ptr.as_ptr().cast_const().cast::<_>(), N, true);
        }

        let ptr = core::ptr::slice_from_raw_parts_mut(ptr.as_ptr().cast::<u8>(), N);
        Ok(NonNull::new(ptr).unwrap())
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        #[cfg(sanitize = "address")]
        unsafe {
            crate::sanitize::mark(
                ptr.as_ptr().byte_add(8).cast_const().cast::<_>(),
                N - 8,
                false,
            );
        }

        let entry = ptr.cast::<Entry<N>>();

        let current_free_list = self.free_list.get();

        let next_ptr = addr_of_mut!((*entry.as_ptr()).next);
        unsafe {
            next_ptr.write(current_free_list);
        }

        self.free_list.set(Some(entry));
    }
}

#[repr(C, align(8))]
union Entry<const N: usize> {
    next: Option<NonNull<Self>>,
    raw: [u8; N],
}
