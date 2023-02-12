use arrayvec::ArrayVec;
use bit_field::BitArray;
use spin::Mutex;
use x86_64::structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size2MiB, Size4KiB};

use crate::supervisor::Allocator;

const CAP: usize = 1 << 15;

pub static DUMB_FRAME_ALLOCATOR: DumbFrameAllocator = DumbFrameAllocator::new();

/// This is one huge giant FIXME.
pub struct DumbFrameAllocator {
    metadata: Mutex<ArrayVec<Metadata, CAP>>,
}

impl DumbFrameAllocator {
    pub const fn new() -> Self {
        Self {
            metadata: Mutex::new(ArrayVec::new_const()),
        }
    }
}

unsafe impl FrameAllocator<Size4KiB> for &DumbFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let mut guard = self.metadata.lock();

        if let Some(frame) = guard.iter_mut().find_map(|metadata| metadata.allocate()) {
            return Some(frame);
        }

        let mut metadata = Metadata::new()?;
        let frame = metadata.allocate().unwrap();
        guard.push(metadata);
        Some(frame)
    }
}

impl FrameDeallocator<Size4KiB> for &DumbFrameAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let mut guard = self.metadata.lock();
        let idx = guard
            .iter_mut()
            .position(|metadata| metadata.contains(frame))
            .unwrap();

        let metadata = &mut guard[idx];
        unsafe {
            metadata.deallocate(frame);
        }

        if metadata.used == 0 {
            guard.swap_remove(idx);
        }
    }
}

struct Metadata {
    base: PhysFrame<Size2MiB>,
    used: u16,
    bitmap: [u8; 64],
}

impl Metadata {
    pub fn new() -> Option<Self> {
        let base = Allocator.allocate_frame()?;
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
        let offset = usize::try_from(offset).unwrap();
        self.bitmap.set_bit(offset, false);

        self.used -= 1;
    }
}

impl Drop for Metadata {
    fn drop(&mut self) {
        assert_eq!(self.used, 0);
        unsafe {
            Allocator.deallocate_frame(self.base);
        }
    }
}
