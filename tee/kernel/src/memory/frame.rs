//! A fast concurrent physical memory allocator. The design is heavily inspired
//! by LLFree.

use core::{
    hint::unreachable_unchecked,
    mem::size_of,
    ops::{Bound, Range, RangeBounds},
    sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering},
};

use bit_field::BitField;
use constants::physical_address::{DYNAMIC_2MIB, NUM_DYNAMIC_SLOTS};
use crossbeam_utils::atomic::AtomicCell;
use usize_conversions::{FromUsize, usize_from};
use x86_64::structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size2MiB};

use crate::{
    limited_index::LimitedIndex,
    per_cpu::{PerCpu, PerCpuSync},
    supervisor,
};

// The dynamic physical memory space is organized into a hierachy:
// Level 0 (L0): A "chunk" is a 2MiB array of 4KiB pages that fit.
// Level 1 (L1): Multiple chunks form a "group". A group can have an owning
//               thread and only the owning thread is allowed to allocate from
//               the group (deallocation is always allowed).
// Level 2 (L2): The array of all groups is called the "super-group".
//
// Dynamic physical memory is lazily hot-plugged. The supervisor allows us to
// hot-plug 2MiB "slots" of memory at an address of its choosing. We assign a
// chunk a slot by storing it in `PHYSICAL_ADDRESSES`.

const SLOTS_ORDER: usize = NUM_DYNAMIC_SLOTS.next_power_of_two().ilog2() as usize;
const CHUNK_ORDER: usize = 9;
const GROUP_ORDER: usize = 3;
const SUPER_GROUP_ORDER: usize = SLOTS_ORDER - GROUP_ORDER;

const SLOTS: usize = 1 << SLOTS_ORDER;
const CHUNK_SIZE: usize = 1 << CHUNK_ORDER;
const GROUP_SIZE: usize = 1 << GROUP_ORDER;
const SUPER_GROUP_SIZE: usize = 1 << SUPER_GROUP_ORDER;

// Information about which frames are used and which are free is stored in
// three levels:
/// L0 just contains a single bit for every frame.
static L0: L0SuperGroup = L0SuperGroup::new();
/// L1 contains the number of free bits for every chunk.
static L1: L1SuperGroup = L1SuperGroup::new();
/// L2 contains the number of free bits for every group as well as whether the
/// group is owned by a thread.
static L2: L2SuperGroup = L2SuperGroup::new();

/// This contains a slot index (physical address) for every chunk.
static PHYSICAL_ADDRESSES: PhysicalAddressSuperGroup = PhysicalAddressSuperGroup::new();
/// This contains the chunk and group index for every for every slot.
static REVERSE_MAP: ReverseMap = ReverseMap::new();

/// Allocate a 4KiB frame.
pub fn allocate_frame() -> PhysFrame {
    PerCpuSync::get().interrupt_data.check_max_interrupt(None);

    let mut guard = PerCpu::get().private_allocator_state.borrow_mut();

    loop {
        let state = guard.get_or_insert_with(|| L2.claim());

        loop {
            if let Some(new_l2_free) = state.free.checked_sub(1) {
                // Try to find an available frame.
                for chunk_idx in ChunkIndex::ALL {
                    let free = &mut state.l1_metadata[chunk_idx];
                    if let Some(new_free) = free.checked_sub(1) {
                        let chunk = &L0.groups[state.group_idx].chunks[chunk_idx];
                        let frame_idx = unsafe { chunk.find_free() };
                        *free = new_free;

                        let slot_idx = state.physical_addresses[chunk_idx];
                        let base = PhysFrame::from(slot_idx);
                        let address = PhysFrame::containing_address(base.start_address())
                            + u64::from_usize(frame_idx.get());
                        state.free = new_l2_free;
                        return address;
                    }
                }
            }

            // Immediately try again if the global metadata contained some
            // recently freed frames.
            if state.refresh() {
                continue;
            }

            // Hot-plug more memory.
            if let Some(chunk_idx) = state.allocated_bitmask.find_zero() {
                let address = (&supervisor::ALLOCATOR).allocate_frame().unwrap();
                let slot_idx = SlotIndex::from(address);
                state.physical_addresses[chunk_idx] = slot_idx;
                state.allocated_bitmask.set(chunk_idx, true);
                state.l1_metadata[chunk_idx] = CHUNK_SIZE as u16;
                REVERSE_MAP.set(slot_idx, state.group_idx, chunk_idx);
                state.free += CHUNK_SIZE as u32;
            } else {
                // Abort and drop ownership of the group. We'll have to use a
                // new group.
                guard.take();
                break;
            }
        }
    }
}

/// Deallocate a 4KiB frame.
///
/// # Safety
///
/// The caller has to ensure that the frame was originally allocated using
/// [`allocate_frame`] and that it is no longer in use.
pub unsafe fn deallocate_frame(frame: PhysFrame) {
    PerCpuSync::get().interrupt_data.check_max_interrupt(None);

    // Get the group, chunk and frame indices.
    let frame_2mib = PhysFrame::containing_address(frame.start_address());
    let slot_idx = SlotIndex::from(frame_2mib);
    let (group_idx, chunk_idx) = REVERSE_MAP.get(slot_idx);
    let frame_idx = frame - PhysFrame::containing_address(frame_2mib.start_address());
    let frame_idx = FrameIndex::new(usize_from(frame_idx));

    let chunk = &L0.groups[group_idx].chunks[chunk_idx];
    unsafe {
        chunk.deallocate(frame_idx);
    }

    let mut guard = PerCpu::get().private_allocator_state.borrow_mut();
    if let Some(state) = guard.as_mut().filter(|state| group_idx == state.group_idx) {
        state.l1_metadata[chunk_idx] += 1;
        state.free += 1;
    } else {
        let free = L1.groups[group_idx].chunks[chunk_idx]
            .free
            .fetch_add(1, Ordering::SeqCst);
        unsafe {
            L2.groups[group_idx].deallocate();
        }

        // If the chunk is now completly unused, try to take ownership of the
        // group, so that the chunk can be released.
        if usize::from(free) + 1 == CHUNK_SIZE
            && let Ok((free, allocated_bitmask)) = L2.groups[group_idx].claim(|_| true)
        {
            drop(unsafe { PrivateState::new(group_idx, free, allocated_bitmask) });
        }
    }
}

/// Release private state owned by the thread. This function should be called
/// before the thread is halted.
pub fn release_private() {
    PerCpu::get().private_allocator_state.borrow_mut().take();
}

struct L0Chunk {
    /// A bitfield for each frame in the chunk:
    /// 0 -> the frame is not in use, 1 -> the frame is in use
    free: [AtomicU64; 8],
}

const _: () = assert!(size_of::<L0Chunk>() * 8 == CHUNK_SIZE);

impl L0Chunk {
    const fn new() -> Self {
        Self {
            free: [const { AtomicU64::new(0) }; 8],
        }
    }

    /// # Safety
    ///
    /// The caller has to ensure that the chunk is owned and that at least one
    /// bit is free.
    unsafe fn find_free(&self) -> FrameIndex {
        for (idx, bits) in self.free.iter().enumerate() {
            let value = bits.load(Ordering::SeqCst);
            let trailing_ones = value.trailing_ones();
            if trailing_ones >= 64 {
                continue;
            }
            bits.fetch_or(1 << trailing_ones, Ordering::SeqCst);
            let full_idx = idx * 64 + usize_from(trailing_ones);
            return FrameIndex::new(full_idx);
        }

        unsafe { unreachable_unchecked() }
    }

    /// Mark a frame as no longer being in use.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that the frame is no longer in use.
    unsafe fn deallocate(&self, frame_idx: FrameIndex) {
        let idx = frame_idx.get() / 64;
        self.free[idx].fetch_and(!(1 << (frame_idx.get() % 64)), Ordering::SeqCst);
    }
}

struct L0Group {
    chunks: ChunkArray<L0Chunk>,
}

impl L0Group {
    const fn new() -> Self {
        Self {
            chunks: [const { L0Chunk::new() }; GROUP_SIZE],
        }
    }
}

#[repr(align(64))]
struct L0SuperGroup {
    groups: GroupArray<L0Group>,
}

impl L0SuperGroup {
    const fn new() -> Self {
        Self {
            groups: [const { L0Group::new() }; SUPER_GROUP_SIZE],
        }
    }
}

struct L1ChunkMetadata {
    // The number of free bits in the chunk
    free: AtomicU16,
}

impl L1ChunkMetadata {
    const fn new() -> Self {
        Self {
            free: AtomicU16::new(0),
        }
    }
}

struct L1GroupMetadata {
    chunks: ChunkArray<L1ChunkMetadata>,
    _padding: [u8; 48],
}

impl L1GroupMetadata {
    const fn new() -> Self {
        // Make sure the group fits in a cacheline.
        const _: () = assert!(size_of::<L1GroupMetadata>() == 64);

        Self {
            chunks: [const { L1ChunkMetadata::new() }; GROUP_SIZE],
            _padding: [0; 48],
        }
    }
}

#[repr(align(64))]
struct L1SuperGroup {
    groups: GroupArray<L1GroupMetadata>,
}

impl L1SuperGroup {
    const fn new() -> Self {
        Self {
            groups: [const { L1GroupMetadata::new() }; SUPER_GROUP_SIZE],
        }
    }
}

struct L2GroupMetadata {
    bits: AtomicU32,
}

impl L2GroupMetadata {
    /// Contains the number of free bits in all chunks.
    const FREE_BITS: Range<usize> = 0..CHUNK_ORDER + GROUP_ORDER + 1;
    /// Contains a bool indicating whether this group is owned by a CPU.
    const OWNED_BIT: usize = Self::FREE_BITS.end;
    /// Contains one bit for each chunk indicating whether a physical memory
    /// has been been hot-swapped in.
    const L1_ALLOCATED_BITS: Range<usize> = Self::OWNED_BIT + 1..Self::OWNED_BIT + 1 + GROUP_SIZE;

    const fn new() -> Self {
        Self {
            bits: AtomicU32::new(0),
        }
    }

    const TOTAL: u32 = (CHUNK_SIZE * GROUP_SIZE) as u32;
    const FREE_LIMIT: u32 = Self::TOTAL * 7 / 8;
    const ALLOCATED_LIMIT: u32 = Self::TOTAL / 8;

    pub fn is_free(available: u32) -> bool {
        (Bound::Excluded(Self::FREE_LIMIT), Bound::Unbounded).contains(&available)
    }

    pub fn is_allocated(available: u32) -> bool {
        (Bound::Unbounded, Bound::Excluded(Self::ALLOCATED_LIMIT)).contains(&available)
    }

    pub fn is_partial(available: u32) -> bool {
        !Self::is_free(available) && !Self::is_allocated(available)
    }

    pub fn is_not_completly_used(available: u32) -> bool {
        available != 0
    }

    /// Inspect a group and optionally try to take ownership of the group. The
    /// `check` function is called with the number of available frames, so that
    /// the caller can decide whether they want to take ownership of the group.
    pub fn claim(&self, mut check: impl FnMut(u32) -> bool) -> Result<(u32, ChunkBitmask), ()> {
        let mut bits = self.bits.load(Ordering::SeqCst);
        loop {
            // Make sure the metadata doesn't already have an owner.
            let has_owner = bits.get_bit(Self::OWNED_BIT);
            if has_owner {
                return Err(());
            }

            // Calculate the number of free bits. Chunks that don't yet have
            // memory swapped in are considered "potentially available".
            let allocated_bitmask = ChunkBitmask::new(bits.get_bits(Self::L1_ALLOCATED_BITS) as u8);
            let free = bits.get_bits(Self::FREE_BITS);
            let available = free + allocated_bitmask.count_zeros() * CHUNK_SIZE as u32;
            // Make sure the caller is fine with the number of available frames.
            if !check(available) {
                return Err(());
            }

            let mut new_bits = bits;
            new_bits.set_bits(Self::FREE_BITS, 0);
            new_bits.set_bit(Self::OWNED_BIT, true);
            match self
                .bits
                .compare_exchange(bits, new_bits, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break Ok((free, allocated_bitmask)),
                Err(new_bits) => bits = new_bits,
            }
        }
    }

    /// Deallocate a frame in the group.
    pub unsafe fn deallocate(&self) {
        self.bits
            .fetch_add(1 << Self::FREE_BITS.start, Ordering::SeqCst);
    }
}

#[repr(align(64))]
struct L2SuperGroup {
    groups: GroupArray<L2GroupMetadata>,
}

impl L2SuperGroup {
    const fn new() -> Self {
        Self {
            groups: [const { L2GroupMetadata::new() }; SUPER_GROUP_SIZE],
        }
    }

    fn claim(&self) -> PrivateState {
        // Prefer partially used groups over free groups.
        for check_fn in [L2GroupMetadata::is_partial, L2GroupMetadata::is_free] {
            for idx in GroupIndex::ALL {
                let group = &self.groups[idx];
                if let Ok((free, allocated_bitmask)) = group.claim(check_fn) {
                    return unsafe { PrivateState::new(idx, free, allocated_bitmask) };
                }
            }
        }

        // Fall back to any non-owned group.
        loop {
            for idx in GroupIndex::ALL {
                let group = &self.groups[idx];
                if let Ok((free, allocated_bitmask)) =
                    group.claim(L2GroupMetadata::is_not_completly_used)
                {
                    return unsafe { PrivateState::new(idx, free, allocated_bitmask) };
                }
            }
        }
    }
}

/// The index of a frame inside a chunk.
type FrameIndex = LimitedIndex<CHUNK_SIZE>;
/// An array of chunks (also called a group).
type ChunkArray<T> = [T; GROUP_SIZE];
/// The index of a chunk in a group.
type ChunkIndex = LimitedIndex<GROUP_SIZE>;
/// An array of groups (also called a super-group).
type GroupArray<T> = [T; SUPER_GROUP_SIZE];
/// The index of a group in a super-group.
type GroupIndex = LimitedIndex<SUPER_GROUP_SIZE>;

/// Contains a bit for each chunk.
#[derive(Debug, Clone, Copy)]
struct ChunkBitmask {
    bits: u8,
}

impl ChunkBitmask {
    fn new(bits: u8) -> Self {
        const _: () = assert!(u8::BITS >= GROUP_SIZE as u32);
        Self { bits }
    }

    fn count_zeros(self) -> u32 {
        self.bits.count_zeros() - (u8::BITS - GROUP_SIZE as u32)
    }

    fn find_zero(self) -> Option<ChunkIndex> {
        ChunkIndex::try_new(usize_from(self.bits.trailing_ones()))
    }

    fn set(&mut self, idx: ChunkIndex, value: bool) {
        self.bits.set_bit(idx.get(), value);
    }
}

type SlotArray<T> = [T; SLOTS];
type SlotIndex = LimitedIndex<SLOTS>;

impl From<PhysFrame<Size2MiB>> for SlotIndex {
    fn from(value: PhysFrame<Size2MiB>) -> Self {
        SlotIndex::new(usize_from(value - DYNAMIC_2MIB.start))
    }
}

impl From<SlotIndex> for PhysFrame<Size2MiB> {
    fn from(value: SlotIndex) -> Self {
        DYNAMIC_2MIB.start + u64::from_usize(value.get())
    }
}

#[derive(Debug)]
pub struct PrivateState {
    group_idx: GroupIndex,
    // private copy of the relevants parts of the l2 metadata
    allocated_bitmask: ChunkBitmask,
    free: u32,
    // private copy of the l1 metadata
    l1_metadata: ChunkArray<u16>,
    // private copy of the physical addresses
    physical_addresses: ChunkArray<SlotIndex>,
}

impl PrivateState {
    /// # Safety
    ///
    /// The caller has to ensure that the group was just allocated by
    /// `try_set_cpu`.
    unsafe fn new(group_idx: GroupIndex, free: u32, allocated_bitmask: ChunkBitmask) -> Self {
        let mut l1_metadata = [0; GROUP_SIZE];
        for chunk_idx in ChunkIndex::ALL {
            l1_metadata[chunk_idx] = L1.groups[group_idx].chunks[chunk_idx]
                .free
                .swap(0, Ordering::SeqCst);
        }

        let mut physical_addresses = [SlotIndex::MIN; GROUP_SIZE];
        for chunk_idx in ChunkIndex::ALL {
            physical_addresses[chunk_idx] = PHYSICAL_ADDRESSES.groups[group_idx].chunks[chunk_idx]
                .slot
                .load();
        }

        Self {
            free,
            group_idx,
            allocated_bitmask,
            l1_metadata,
            physical_addresses,
        }
    }

    /// Refresh the metadata about available resources by looking at the global
    /// data. Returns true if any resources were claimed.
    ///
    /// The main purpose of this function is to take into account frames that
    /// were freed by another thread after the global metadata was copied to
    /// the private state.
    fn refresh(&mut self) -> bool {
        let mut claimed_any = false;

        for idx in ChunkIndex::ALL {
            let claimed = L1.groups[self.group_idx].chunks[idx]
                .free
                .swap(0, Ordering::SeqCst);
            self.l1_metadata[idx] += claimed;
            claimed_any |= claimed != 0;
        }

        let mut mask = !0;
        mask.set_bits(L2GroupMetadata::FREE_BITS, 0);
        let bits = L2.groups[self.group_idx]
            .bits
            .fetch_and(mask, Ordering::SeqCst);
        let claimed = bits.get_bits(L2GroupMetadata::FREE_BITS);
        self.free += claimed;
        claimed_any |= claimed != 0;

        claimed_any
    }
}

impl Drop for PrivateState {
    fn drop(&mut self) {
        self.refresh();

        // Hot-unplug completely unused chunks.
        for i in ChunkIndex::ALL {
            if self.free >= CHUNK_SIZE as u32 && self.l1_metadata[i] == CHUNK_SIZE as u16 {
                self.l1_metadata[i] = 0;
                self.allocated_bitmask.set(i, false);
                let slot_idx = self.physical_addresses[i];
                let frame = PhysFrame::from(slot_idx);
                unsafe {
                    (&supervisor::ALLOCATOR).deallocate_frame(frame);
                }
                self.free -= CHUNK_SIZE as u32;
            }
        }

        // Write back the L1 metadata.
        for i in ChunkIndex::ALL {
            PHYSICAL_ADDRESSES.groups[self.group_idx].chunks[i]
                .slot
                .store(self.physical_addresses[i]);
            L1.groups[self.group_idx].chunks[i]
                .free
                .fetch_add(self.l1_metadata[i], Ordering::SeqCst);
        }

        // Write back the L2 metadata.
        let metadata = &L2.groups[self.group_idx];
        let mut bits = metadata.bits.load(Ordering::SeqCst);
        loop {
            let mut new_bits = bits;
            new_bits.set_bits(
                L2GroupMetadata::FREE_BITS,
                bits.get_bits(L2GroupMetadata::FREE_BITS) + self.free,
            );
            new_bits.set_bit(L2GroupMetadata::OWNED_BIT, false);
            new_bits.set_bits(
                L2GroupMetadata::L1_ALLOCATED_BITS,
                u32::from(self.allocated_bitmask.bits),
            );
            match metadata
                .bits
                .compare_exchange(bits, new_bits, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(new_bits) => bits = new_bits,
            }
        }
    }
}

struct PhysicalAddressChunk {
    slot: AtomicCell<SlotIndex>,
}

impl PhysicalAddressChunk {
    const fn new() -> Self {
        Self {
            slot: AtomicCell::new(SlotIndex::MIN),
        }
    }
}

struct PhysicalAddressGroup {
    chunks: ChunkArray<PhysicalAddressChunk>,
}

impl PhysicalAddressGroup {
    const fn new() -> Self {
        Self {
            chunks: [const { PhysicalAddressChunk::new() }; GROUP_SIZE],
        }
    }
}

#[repr(align(64))]
struct PhysicalAddressSuperGroup {
    groups: GroupArray<PhysicalAddressGroup>,
}

impl PhysicalAddressSuperGroup {
    const fn new() -> Self {
        Self {
            groups: [const { PhysicalAddressGroup::new() }; SUPER_GROUP_SIZE],
        }
    }
}

#[repr(align(64))]
struct ReverseMap {
    slots: SlotArray<AtomicU16>,
}

impl ReverseMap {
    const fn new() -> Self {
        Self {
            slots: [const { AtomicU16::new(0) }; SLOTS],
        }
    }

    fn get(&self, slot_idx: SlotIndex) -> (GroupIndex, ChunkIndex) {
        let bits = self.slots[slot_idx].load(Ordering::SeqCst);
        let chunk_idx = bits.get_bits(0..GROUP_ORDER);
        let group_idx = bits.get_bits(GROUP_ORDER..GROUP_ORDER + SUPER_GROUP_ORDER);
        let chunk_idx = ChunkIndex::new(usize::from(chunk_idx));
        let group_idx = GroupIndex::new(usize::from(group_idx));
        (group_idx, chunk_idx)
    }

    fn set(&self, slot_idx: SlotIndex, group_idx: GroupIndex, chunk_idx: ChunkIndex) {
        let mut bits = 0;
        bits.set_bits(0..GROUP_ORDER, chunk_idx.get() as u16);
        bits.set_bits(
            GROUP_ORDER..GROUP_ORDER + SUPER_GROUP_ORDER,
            group_idx.get() as u16,
        );
        self.slots[slot_idx].store(bits, Ordering::SeqCst);
    }
}
