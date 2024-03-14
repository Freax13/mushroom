use core::{
    mem::size_of,
    ops::{Index, IndexMut},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::spin::mutex::Mutex;
use alloc::vec::Vec;
use arrayvec::ArrayVec;
use bit_field::BitArray;
use log::{debug, warn};
use usize_conversions::usize_from;
use x86_64::structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size2MiB, Size4KiB};

use crate::supervisor;

pub static FRAME_ALLOCATOR: BitmapFrameAllocator = BitmapFrameAllocator::new();

pub struct BitmapFrameAllocator {
    is_donating: AtomicBool,
    state: Mutex<BitmapFrameAllocatorState>,
}

impl BitmapFrameAllocator {
    const fn new() -> Self {
        Self {
            is_donating: AtomicBool::new(false),
            state: Mutex::new(BitmapFrameAllocatorState {
                r#static: ArrayVec::new_const(),
                dynamic: Vec::new(),
            }),
        }
    }
}

struct BitmapFrameAllocatorState {
    r#static: ArrayVec<Bitmap, 1>,
    dynamic: Vec<Bitmap>,
}

impl BitmapFrameAllocatorState {
    fn bitmaps(&mut self) -> impl Iterator<Item = &mut Bitmap> + '_ {
        self.r#static.iter_mut().chain(self.dynamic.iter_mut())
    }

    fn add_bitmap(&mut self, bitmap: Bitmap) {
        // Try pushing into the statically sized vector...
        match self.r#static.try_push(bitmap) {
            Ok(_) => {}
            Err(err) => {
                // ...or fall back to pushing into the dynamic vector.
                self.dynamic.push(err.element());
            }
        }
    }

    fn swap_remove(&mut self, idx: usize) {
        if idx < self.r#static.len() {
            self.r#static.swap_remove(idx);
        } else {
            self.dynamic.swap_remove(idx - self.r#static.len());
        }
    }

    /// Return's true when a donation is needed to grow the dynamic buffer.
    fn needs_donation(&self) -> Option<usize> {
        if self.dynamic.capacity() == 0 {
            // Make sure to request at least a page worth of capacity.
            return Some(4096usize.div_ceil(size_of::<Bitmap>()).next_power_of_two());
        }

        if self.dynamic.len() * 4 > self.dynamic.capacity() * 3 {
            return Some(self.dynamic.capacity() * 2);
        }

        None
    }

    /// Donate the capacity of a vector.
    fn donate_dynamic_vector(&mut self, dynamic: &mut Vec<Bitmap>) {
        assert!(dynamic.is_empty());

        // Check if the donated vector has more capacity.
        if self.dynamic.capacity() >= dynamic.capacity() {
            warn!("rejecting donation");
            return;
        }

        // Swap the vectors and move the elements over.
        core::mem::swap(&mut self.dynamic, dynamic);
        self.dynamic.append(dynamic);
    }
}

impl Index<usize> for BitmapFrameAllocatorState {
    type Output = Bitmap;

    fn index(&self, idx: usize) -> &Self::Output {
        if idx < self.r#static.len() {
            &self.r#static[idx]
        } else {
            &self.dynamic[idx - self.r#static.len()]
        }
    }
}

impl IndexMut<usize> for BitmapFrameAllocatorState {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        if idx < self.r#static.len() {
            &mut self.r#static[idx]
        } else {
            &mut self.dynamic[idx - self.r#static.len()]
        }
    }
}

unsafe impl FrameAllocator<Size4KiB> for &BitmapFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let mut state = loop {
            let mut state = self.state.lock();

            if let Some(cap) = state.needs_donation() {
                let res = self.is_donating.compare_exchange(
                    false,
                    true,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                if res.is_ok() {
                    // We acquired the rights to donate.
                    debug!("preparing to donate with capacity {cap}");

                    // Drop the mutex, so that we can allocate on the heap.
                    drop(state);

                    // Allocate a vector.
                    let mut donation = Vec::with_capacity(cap);

                    // Donate the vector.
                    state = self.state.lock();
                    state.donate_dynamic_vector(&mut donation);

                    // Drop the mutex again to release the previous allocation.
                    drop(state);
                    drop(donation);

                    self.is_donating.store(false, Ordering::SeqCst);

                    continue;
                }
            }

            break state;
        };

        // Try to allocate from the existing bitmaps.
        if let Some(frame) = state.bitmaps().find_map(|bitmap| bitmap.allocate()) {
            return Some(frame);
        }

        // Create a new bitmap and allocate from it.
        let mut bitmap = Bitmap::new()?;
        let frame = bitmap.allocate().unwrap();
        state.add_bitmap(bitmap);

        Some(frame)
    }
}

impl FrameDeallocator<Size4KiB> for &BitmapFrameAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame) {
        let mut state = self.state.lock();
        let mut i = 0;
        loop {
            let bitmap = &mut state[i];
            if !bitmap.contains(frame) {
                i += 1;
                continue;
            }

            unsafe {
                bitmap.deallocate(frame);
            }
            if bitmap.used == 0 {
                state.swap_remove(i);
            }

            return;
        }
    }
}

struct Bitmap {
    base: PhysFrame<Size2MiB>,
    used: u16,
    bitmap: [u8; 64],
}

impl Bitmap {
    pub fn new() -> Option<Self> {
        let base = (&supervisor::ALLOCATOR).allocate_frame()?;
        Some(Self {
            base,
            used: 0,
            bitmap: [0; 64],
        })
    }

    pub fn allocate(&mut self) -> Option<PhysFrame> {
        if self.used >= 512 {
            return None;
        }

        self.used += 1;

        let idx = (0..512u16)
            .find(|&i| !self.bitmap.get_bit(usize::from(i)))
            .unwrap();
        self.bitmap.set_bit(usize::from(idx), true);

        let base_addr = self.base.start_address();
        let base_frame = PhysFrame::containing_address(base_addr);
        Some(base_frame + u64::from(idx))
    }

    pub fn contains(&self, frame: PhysFrame) -> bool {
        let base_addr = self.base.start_address();
        let start_frame = PhysFrame::containing_address(base_addr);
        let end_frame = start_frame + 511;
        (start_frame..=end_frame).contains(&frame)
    }

    pub unsafe fn deallocate(&mut self, frame: PhysFrame) {
        let base_addr = self.base.start_address();
        let base_frame = PhysFrame::containing_address(base_addr);

        let offset = frame - base_frame;
        let offset = usize_from(offset);
        self.bitmap.set_bit(offset, false);

        self.used -= 1;
    }
}

impl Drop for Bitmap {
    fn drop(&mut self) {
        assert_eq!(self.used, 0);
        unsafe {
            (&supervisor::ALLOCATOR).deallocate_frame(self.base);
        }
    }
}
