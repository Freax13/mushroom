//! A buffer to store physical memory for the guest to use.
//!
//! In order to make allocations fast, the [`AllocationBuffer`] contains
//! multiple allocations ready to be used by the kernel when it requires them.
//! When the allocations run out, the kernel can ask the supervisor to refill
//! the buffer by issuing the [`AllocateMemory`](crate::command_buffer::AllocateMemory)
//! command.

use core::sync::atomic::{AtomicU16, Ordering};

use bytemuck::{Pod, Zeroable};

const ALLOCATIONS: usize = 32;

#[repr(C, align(64))]
pub struct AllocationBuffer {
    /// An array of `SlotIndex`
    allocations: [AtomicU16; ALLOCATIONS],
}

impl AllocationBuffer {
    #[cfg(feature = "kernel")]
    pub(crate) const fn new() -> Self {
        Self {
            allocations: [const { AtomicU16::new(SlotIndex::EMPTY.0) }; ALLOCATIONS],
        }
    }

    #[cfg(feature = "kernel")]
    pub fn pop_allocation(&self) -> Option<SlotIndex> {
        self.allocations
            .iter()
            .map(|allocation| allocation.swap(SlotIndex::EMPTY.0, Ordering::SeqCst))
            .map(SlotIndex)
            .find(|slot| *slot != SlotIndex::EMPTY)
    }

    #[cfg(feature = "supervisor")]
    pub fn find_free_entry(&self) -> Option<AllocationBufferEntry<'_>> {
        self.allocations
            .iter()
            .find(|slot| slot.load(Ordering::SeqCst) == SlotIndex::EMPTY.0)
            .map(|slot| AllocationBufferEntry { slot })
    }
}

#[cfg(feature = "supervisor")]
pub struct AllocationBufferEntry<'a> {
    slot: &'a AtomicU16,
}

#[cfg(feature = "supervisor")]
impl AllocationBufferEntry<'_> {
    pub fn set(self, slot_idx: SlotIndex) {
        self.slot.store(slot_idx.0, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Pod, Zeroable, PartialEq, Eq)]
#[repr(transparent)]
pub struct SlotIndex(u16);

impl SlotIndex {
    pub const EMPTY: Self = Self(0xffff);

    pub fn new(value: u16) -> Self {
        assert!(value < u16::MAX / 2);
        Self(value)
    }

    pub const fn get(&self) -> u16 {
        assert!(self.0 < u16::MAX / 2);
        self.0
    }
}
