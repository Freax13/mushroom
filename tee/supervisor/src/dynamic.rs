//! FIXME: This performs really poorly, fix this.

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use bit_field::BitField;
use constants::{physical_address::DYNAMIC, MEMORY_PORT};
use x86_64::{
    structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size2MiB},
    PhysAddr,
};

use crate::{ghcb::ioio_write, pagetable::TEMPORARY_MAPPER};

const SLOTS: usize = 1 << 15;
const BITMAP_SIZE: usize = SLOTS / 8;

pub static HOST_ALLOCTOR: HostAllocator = HostAllocator::new();

/// An allocator for dynamically allocating 2MiB frames from the host.
///
/// Allocated frames are automatically validated and zeroed.
///
/// Deallocated frames are automatically invalidated and the permissions for
/// lower VMPL's cleared.
pub struct HostAllocator {
    bitmap: [AtomicU8; BITMAP_SIZE],
    /// The byte index of the previous allocation. Chances are the bits
    /// directly following this are free.
    start_offset: AtomicUsize,
}

impl HostAllocator {
    const fn new() -> Self {
        Self {
            bitmap: [const { AtomicU8::new(0) }; BITMAP_SIZE],
            start_offset: AtomicUsize::new(0),
        }
    }

    fn allocate_slot_id(&self) -> Option<u16> {
        let start_index = self.start_offset.load(Ordering::SeqCst);

        self.bitmap
            .iter()
            .enumerate()
            .skip(start_index)
            .chain(self.bitmap.iter().enumerate().take(start_index))
            .find_map(|(i, bitmap)| {
                let mut byte = bitmap.load(Ordering::SeqCst);
                loop {
                    // Find an unset bit.
                    let bit = (0..8).find(|&i| !byte.get_bit(i))?;

                    // Set the bit.
                    byte = bitmap.fetch_or(1 << bit, Ordering::SeqCst);

                    // Check if the bit was just set by another core.
                    if byte.get_bit(bit) {
                        continue;
                    }

                    // Success!
                    self.start_offset.store(i, Ordering::SeqCst);
                    return Some(u16::try_from(i * 8 + bit).unwrap());
                }
            })
    }

    unsafe fn deallocate_slot_id(&self, slot_id: u16) {
        let byte_idx = usize::from(slot_id / 8);
        let bit_idx = usize::from(slot_id % 8);

        let mut mask = !0;
        mask.set_bit(bit_idx, false);

        let prev = self.bitmap[byte_idx].fetch_and(mask, Ordering::SeqCst);
        assert!(prev.get_bit(bit_idx));
    }
}

unsafe impl FrameAllocator<Size2MiB> for &'_ HostAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        // Allocate a slot id.
        let slot_id = self.allocate_slot_id()?;

        let base = PhysFrame::<Size2MiB>::containing_address(PhysAddr::new(DYNAMIC.start()));
        let frame = base + u64::from(slot_id);

        // Tell the host to enable the slot.
        unsafe {
            update_slot_status(slot_id, true);
        }

        // Create a temporary mapping.
        let mut mapper = TEMPORARY_MAPPER.borrow_mut();
        let mapping = mapper.create_temporary_mapping_2mib(frame, true);

        // Validate the memory.
        unsafe {
            mapping.pvalidate(true);
        }

        Some(frame)
    }
}

impl FrameDeallocator<Size2MiB> for &'_ HostAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size2MiB>) {
        assert!(DYNAMIC.contains(frame.start_address().as_u64()));
        let base = PhysFrame::<Size2MiB>::containing_address(PhysAddr::new(DYNAMIC.start()));
        let slot_id = u16::try_from(frame - base).unwrap();

        // Create a temporary mapping.
        let mut mapper = TEMPORARY_MAPPER.borrow_mut();
        let mapping = mapper.create_temporary_mapping_2mib(frame, false);

        // Validate the memory.
        unsafe {
            mapping.pvalidate(false);
        }

        // Tell the host to disable the slot.
        update_slot_status(slot_id, false);

        // Deallocate a slot id.
        self.deallocate_slot_id(slot_id);
    }
}

unsafe fn update_slot_status(slot_id: u16, enabled: bool) {
    let mut request: u32 = 0;
    request.set_bits(0..15, u32::from(slot_id));
    request.set_bit(15, enabled);
    ioio_write(MEMORY_PORT, request);
}
