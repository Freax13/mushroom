use core::{
    cell::LazyCell,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{memory::frame::NewAllocator, spin::mutex::Mutex};
use arrayvec::ArrayVec;
use constants::{
    FINISH_OUTPUT_MSR, HALT_PORT, KICK_AP_PORT, MAX_APS_COUNT, MEMORY_MSR, SCHEDULE_PORT,
    UPDATE_OUTPUT_MSR,
};
use x86_64::{
    instructions::port::PortWriteOnly,
    registers::model_specific::Msr,
    structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size2MiB},
    PhysAddr,
};

use crate::{memory::temporary::copy_into_frame, per_cpu::PerCpu};

pub static ALLOCATOR: Allocator = Allocator::new();

pub struct Allocator {
    state: Mutex<AllocatorState>,
}

impl Allocator {
    const fn new() -> Self {
        Self {
            state: Mutex::new(AllocatorState::new()),
        }
    }
}

struct AllocatorState {
    /// A cache for frames. Instead of always freeing, we store a limited
    /// amount of frames for rapid reuse.
    cached: ArrayVec<PhysFrame<Size2MiB>, 8>,
}

impl AllocatorState {
    const fn new() -> Self {
        Self {
            cached: ArrayVec::new_const(),
        }
    }
}

unsafe impl FrameAllocator<Size2MiB> for &'_ Allocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        // Try to reused a cached frame.
        let mut state = self.state.lock();
        if let Some(cached) = state.cached.pop() {
            return Some(cached);
        }
        drop(state);

        // Fall back to allocating a frame.
        let memory_msr = Msr::new(MEMORY_MSR);
        let addr = unsafe { memory_msr.read() };

        if addr == 0 {
            return None;
        }

        let addr = PhysAddr::new(addr);
        let frame = PhysFrame::from_start_address(addr).unwrap();
        Some(frame)
    }
}

impl FrameDeallocator<Size2MiB> for &'_ Allocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size2MiB>) {
        // Try to put the frame in the cache.
        let mut state = self.state.lock();
        let res = state.cached.try_push(frame);
        if res.is_ok() {
            // Success
            return;
        }
        drop(state);

        // Fall back to deallocating the frame.
        let addr = frame.start_address().as_u64();
        let mut memory_msr = Msr::new(MEMORY_MSR);
        unsafe {
            memory_msr.write(addr);
        }
    }
}

static RUNNING_VCPUS: AtomicU64 = AtomicU64::new(1);

/// Halt this vcpu.
#[inline(never)]
pub fn halt() -> Result<(), LastRunningVcpuError> {
    // Ensure that this vCPU isn't the last one running.
    let mut running_vcpus = RUNNING_VCPUS.load(Ordering::SeqCst);
    loop {
        debug_assert_ne!(running_vcpus, 0);
        if running_vcpus == 1 {
            return Err(LastRunningVcpuError);
        }
        let res = RUNNING_VCPUS.compare_exchange(
            running_vcpus,
            running_vcpus - 1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        match res {
            Ok(_) => break,
            Err(new_running_vcpus) => running_vcpus = new_running_vcpus,
        }
    }

    #[cfg(feature = "profiling")]
    crate::profiler::flush();

    unsafe {
        PortWriteOnly::new(HALT_PORT).write(0u32);
    }

    Ok(())
}

/// An error that is returned when the last running vCPU request to be halted.
#[derive(Debug, Clone, Copy)]
pub struct LastRunningVcpuError;

/// Tell the supervisor to schedule another vcpu.
pub fn schedule_vcpu() {
    RUNNING_VCPUS.fetch_add(1, Ordering::SeqCst);

    unsafe {
        PortWriteOnly::new(SCHEDULE_PORT).write(1u32);
    }
}

pub fn launch_next_ap() {
    let idx = PerCpu::get().idx;

    // Check if there are more APs to start.
    let next_idx = idx + 1;
    if next_idx < usize::from(MAX_APS_COUNT) {
        RUNNING_VCPUS.fetch_add(1, Ordering::SeqCst);

        let next_idx = u32::try_from(next_idx).unwrap();
        unsafe {
            PortWriteOnly::new(KICK_AP_PORT).write(next_idx);
        }
    }
}

pub fn output(bytes: &[u8]) {
    static FRAME: Mutex<LazyCell<PhysFrame>> = Mutex::new(LazyCell::new(|| {
        NewAllocator
            .allocate_frame()
            .expect("failed to allocate frame for output")
    }));

    let guard = FRAME.lock();
    let frame = **guard;

    for chunk in bytes.chunks(0x1000) {
        let mut buffer = [0; 0x1000];
        buffer[..chunk.len()].copy_from_slice(chunk);

        unsafe {
            copy_into_frame(frame, &buffer).expect("failed to copy into output frame");
        }

        let command = frame.start_address().as_u64() | (chunk.len() as u64 - 1);
        unsafe {
            Msr::new(UPDATE_OUTPUT_MSR).write(command);
        }
    }
}

/// Tell to supervisor to commit the output and produce and attestation report.
pub fn commit_output() -> ! {
    unsafe {
        Msr::new(FINISH_OUTPUT_MSR).write(1);
    }
    unreachable!();
}

/// Tell the supervisor that something went wrong and to discard the output.
pub fn fail() -> ! {
    unsafe {
        Msr::new(FINISH_OUTPUT_MSR).write(0);
    }
    unreachable!();
}
