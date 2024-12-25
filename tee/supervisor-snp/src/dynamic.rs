use bit_field::BitField;
use constants::MEMORY_PORT;
use snp_types::VmplPermissions;
use spin::Mutex;
use supervisor_services::SlotIndex;
use x86_64::{
    structures::paging::{Page, PageSize, Size2MiB},
    VirtAddr,
};

use crate::{
    ghcb::ioio_write,
    rmp::{pvalidate_2mib, rmpadjust_2mib},
};

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
        let base = Page::<Size2MiB>::from_start_address(VirtAddr::new(0x200000000000)).unwrap();
        let page = base + u64::from(slot_idx.get());
        unsafe {
            pvalidate_2mib(page, true);
        }

        // Zero out the memory.
        unsafe {
            core::ptr::write_bytes(
                page.start_address().as_mut_ptr::<u8>(),
                0,
                Size2MiB::SIZE as usize,
            );
        }

        // Make the frame accessible to VMPL 1.
        unsafe {
            rmpadjust_2mib(
                page,
                1,
                VmplPermissions::READ | VmplPermissions::WRITE | VmplPermissions::EXECUTE_USER,
                false,
            );
        }

        Some(slot_idx)
    }

    pub fn deallocate_frame(&mut self, slot_idx: SlotIndex) {
        // Create a temporary mapping.
        let base = Page::<Size2MiB>::from_start_address(VirtAddr::new(0x200000000000)).unwrap();
        let page = base + u64::from(slot_idx.get());

        // Invalidate the memory.
        unsafe {
            pvalidate_2mib(page, false);
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
    ioio_write(MEMORY_PORT, request);
}
