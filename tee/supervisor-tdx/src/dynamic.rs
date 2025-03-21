use bit_field::BitField;
use constants::{MEMORY_PORT, physical_address::DYNAMIC_2MIB};
use spin::Mutex;
use supervisor_services::SlotIndex;
use tdx_types::tdcall::GpaAttr;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::tdcall::{Tdcall, Vmcall};

const SLOTS: usize = 1 << 15;
const BITMAP_SIZE: usize = SLOTS / 8;

static HOST_ALLOCATOR: Mutex<HostAllocator> = Mutex::new(HostAllocator::new());

pub fn allocate_memory() -> SlotIndex {
    HOST_ALLOCATOR.lock().allocate_frame().unwrap()
}

pub fn deallocate_memory(slot_idx: SlotIndex) {
    HOST_ALLOCATOR.lock().deallocate_frame(slot_idx);
}

/// An allocator for dynamically allocating 2MiB frames from the host.
///
/// Allocated frames are automatically validated and zeroed.
///
/// Deallocated frames are automatically invalidated and the permissions for
/// lower VMPL's cleared.
pub struct HostAllocator {
    bitmap: [u8; BITMAP_SIZE],
    /// The byte index of the previous allocation. Chances are the bits
    /// directly following this are free.
    start_offset: usize,
}

impl HostAllocator {
    pub const fn new() -> Self {
        Self {
            bitmap: [0; BITMAP_SIZE],
            start_offset: 0,
        }
    }

    fn allocate_slot_idx(&mut self) -> Option<SlotIndex> {
        let start_index = self.start_offset;
        let (first, second) = self.bitmap.split_at_mut(start_index);

        second
            .iter_mut()
            .zip(start_index..)
            .chain(first.iter_mut().zip(0..))
            .find_map(|(bitmap, i)| {
                // Find an unset bit.
                let bit = (0..8).find(|&i| !bitmap.get_bit(i))?;

                // Set the bit.
                bitmap.set_bit(bit, true);

                // Success!
                self.start_offset = i;
                Some(SlotIndex::new(u16::try_from(i * 8 + bit).unwrap()))
            })
    }

    unsafe fn deallocate_slot_id(&mut self, slot_idx: SlotIndex) {
        let slot_idx = slot_idx.get();
        let byte_idx = usize::from(slot_idx / 8);
        let bit_idx = usize::from(slot_idx % 8);
        assert!(self.bitmap[byte_idx].get_bit(bit_idx));
        self.bitmap[byte_idx].set_bit(bit_idx, false);
    }

    pub fn allocate_frame(&mut self) -> Option<SlotIndex> {
        // Allocate a slot id.
        let slot_idx = self.allocate_slot_idx()?;

        // Tell the host to enable the slot.
        unsafe {
            update_slot_status(slot_idx, true);
        }

        // Validate the memory.
        let gpa = DYNAMIC_2MIB.start + u64::from(slot_idx.get());
        unsafe {
            Tdcall::mem_page_accept(gpa);
        }

        // Make the frame accessible to the L2 VM.
        let start = PhysFrame::<Size4KiB>::from_start_address(gpa.start_address()).unwrap();
        let end = start + 511;
        for frame in PhysFrame::range_inclusive(start, end) {
            unsafe {
                Tdcall::mem_page_attr_wr(
                    frame,
                    GpaAttr::READ | GpaAttr::WRITE | GpaAttr::EXECUTE_USER | GpaAttr::VALID,
                    GpaAttr::READ | GpaAttr::WRITE | GpaAttr::EXECUTE_USER,
                    true,
                );
            }
        }

        Some(slot_idx)
    }

    pub fn deallocate_frame(&mut self, slot_idx: SlotIndex) {
        // Make the frame inaccessible to the L2 VM.
        let gpa = DYNAMIC_2MIB.start + u64::from(slot_idx.get());
        let start = PhysFrame::<Size4KiB>::from_start_address(gpa.start_address()).unwrap();
        let end = start + 511;
        for frame in PhysFrame::range_inclusive(start, end) {
            unsafe {
                Tdcall::mem_page_attr_wr(
                    frame,
                    GpaAttr::VALID,
                    GpaAttr::READ | GpaAttr::WRITE | GpaAttr::EXECUTE_USER,
                    true,
                );
            }
        }

        // Tell the host to disable the slot.
        unsafe {
            update_slot_status(slot_idx, false);
        }

        // Deallocate a slot id.
        unsafe {
            self.deallocate_slot_id(slot_idx);
        }
    }
}

unsafe fn update_slot_status(slot_idx: SlotIndex, enabled: bool) {
    let mut request: u32 = 0;
    request.set_bits(0..15, u32::from(slot_idx.get()));
    request.set_bit(15, enabled);

    Vmcall::instruction_io_write32(MEMORY_PORT, request);
}
