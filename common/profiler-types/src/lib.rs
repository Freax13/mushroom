#![no_std]

use core::{mem::size_of, sync::atomic::AtomicU8};

use bytemuck::NoUninit;
use constants::MAX_APS_COUNT;

const NOTIFY_BITS: usize = MAX_APS_COUNT as usize;
pub const NOTIFY_BYTES: usize = NOTIFY_BITS.div_ceil(8);

#[repr(C)]
pub struct ProfilerControl {
    /// This is a bit field containing a bit for each AP. Set to `true` by the
    /// kernel after it writes to a header. Set to `false` by the host after
    /// reading and processing the header. This mechanism aims to reduce
    /// contention.
    pub notify_flags: [AtomicU8; NOTIFY_BYTES],
    pub headers: [PerCpuHeader; MAX_APS_COUNT as usize],
    /// The effective frequency in MHz of the guest view of TSC.
    pub tsc_mhz: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct PerCpuHeader {
    /// The start index into the buffer were the first entry was written.
    pub start_idx: usize,
    /// The amount of entries that were written.
    pub len: usize,
    /// Set to `true` if some event have been lost.
    pub lost: bool,
}

const TOTAL_PROFILER_BUFFERS_CAPACITY: usize = 0x40000000;
pub const PROFILER_ENTRIES: usize = {
    let buffer_max_size = TOTAL_PROFILER_BUFFERS_CAPACITY / (MAX_APS_COUNT as usize);
    let max_entries = buffer_max_size / size_of::<Entry>();
    // Align the max_entries down to a multiple of two.
    let entries = 1 << max_entries.ilog2();

    // Make sure `PerCpuEntries` doesnt have padding.
    assert!(entries >= 4, "Profiler buffer capacity is too small");

    entries
};

#[derive(Clone, Copy, NoUninit)]
#[repr(C, align(16))]
pub struct Entry {
    pub time: u64,
    pub event: u64,
}

#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct PerCpuEntries {
    pub entries: [Entry; PROFILER_ENTRIES],
}

pub type AllEntries = [PerCpuEntries; MAX_APS_COUNT as usize];

// This is set so that `LocalHeader`'s (found in the kernel) size is a multiple of a cache line's size.
pub const CALL_STACK_CAPACITY: usize = 62;
