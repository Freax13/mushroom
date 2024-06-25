use core::arch::asm;

use crate::spin::mutex::Mutex;
use arrayvec::ArrayVec;
use bit_field::BitField;
use constants::{physical_address::DYNAMIC_2MIB, MAX_APS_COUNT};
use supervisor_services::{
    allocation_buffer::SlotIndex,
    command_buffer::{
        AllocateMemory, Command, CommandBufferWriter, DeallocateMemory, FailOutput, FinishOutput,
        StartNextAp, UpdateOutput,
    },
    SupervisorServices,
};
use x86_64::structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size2MiB};

use crate::per_cpu::PerCpu;

#[link_section = ".supervisor_services"]
static SUPERVISOR_SERVICES: SupervisorServices = SupervisorServices::new();

static WRITER: Mutex<CommandBufferWriter> = Mutex::new(CommandBufferWriter::new(
    &SUPERVISOR_SERVICES.command_buffer,
));

fn try_push_command<C>(command: &C) -> Result<(), ()>
where
    C: Command,
{
    WRITER.lock().push(command).map_err(drop)?;
    Ok(())
}

fn arm() {
    SUPERVISOR_SERVICES
        .notification_buffer
        .arm(PerCpu::get().idx);
}

/// Kick the supervisor thread. If `resume` is true, this method immediately
/// resumes. If `resume` is false, this method waits for the supervisor to kick
/// this thread ([`arm`] should be called before this method; spurios wake ups
/// are possible).
fn kick_supervisor(resume: bool) {
    let mut bits = 0u64;
    bits.set_bit(0, resume);

    unsafe {
        asm!("mov cr8, rax", in("rax") bits);
    }

    x86_64::instructions::hlt();
}

/// Push a command, don't notify the supervisor about it and don't wait for it
/// to complete.
fn push_background_command<C>(command: C)
where
    C: Command,
{
    if try_push_command(&command).is_ok() {
        return;
    }

    loop {
        arm();
        if try_push_command(&command).is_ok() {
            return;
        }

        kick_supervisor(false);
    }
}

/// Push a command, immediatly tell the supervisor about it, but don't wait for
/// it to complete.
fn push_async_command<C>(command: C)
where
    C: Command,
{
    push_background_command(command);
    kick_supervisor(true);
}

pub fn start_next_ap() {
    push_async_command(StartNextAp);
}

fn allocate() -> SlotIndex {
    let allocation = SUPERVISOR_SERVICES.allocation_buffer.pop_allocation();
    if let Some(allocation) = allocation {
        return allocation;
    }

    loop {
        arm();

        let allocation = SUPERVISOR_SERVICES.allocation_buffer.pop_allocation();
        if let Some(allocation) = allocation {
            return allocation;
        }

        let _ = try_push_command(&AllocateMemory);

        kick_supervisor(false);
    }
}

fn deallocate(slot_idx: SlotIndex) {
    push_async_command(DeallocateMemory { slot_idx });
}

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
    cached: ArrayVec<PhysFrame<Size2MiB>, 128>,
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

        let idx = allocate();
        Some(DYNAMIC_2MIB.start + u64::from(idx.get()))
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

        let slot_idx = SlotIndex::new(u16::try_from(frame - DYNAMIC_2MIB.start).unwrap());
        deallocate(slot_idx);
    }
}

/// Halt this vcpu.
#[inline(never)]
pub fn halt() -> Result<(), LastRunningVcpuError> {
    SCHEDULER.halt()?;

    #[cfg(feature = "profiling")]
    crate::profiler::flush();

    kick_supervisor(false);

    SCHEDULER.resume();

    Ok(())
}

/// An error that is returned when the last running vCPU request to be halted.
#[derive(Debug, Clone, Copy)]
pub struct LastRunningVcpuError;

pub static SCHEDULER: Scheduler = Scheduler::new();

pub struct Scheduler(Mutex<SchedulerState>);

struct SchedulerState {
    /// One bit for every vCPU.
    bits: u128,
    /// The number of vCPUs that have finished being launched.
    launched: u8,
    /// Whether a vCPU is being launched right now.
    is_launching: bool,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self(Mutex::new(SchedulerState {
            bits: 1,
            launched: 0,
            is_launching: true,
        }))
    }

    fn pick_any(&self) -> Option<ScheduledCpu> {
        let mut state = self.0.lock();
        let idx = state.bits.trailing_ones() as u8;
        if idx < state.launched {
            state.bits.set_bit(usize::from(idx), true);

            Some(ScheduledCpu::Existing(idx))
        } else {
            if state.is_launching || idx >= MAX_APS_COUNT {
                return None;
            }

            state.is_launching = true;
            state.bits.set_bit(usize::from(idx), true);

            Some(ScheduledCpu::New)
        }
    }

    fn halt(&self) -> Result<(), LastRunningVcpuError> {
        let mut state = self.0.lock();
        let mut new_bits = state.bits;
        new_bits.set_bit(PerCpu::get().idx, false);
        // Ensure that this vCPU isn't the last one running.
        if new_bits == 0 {
            return Err(LastRunningVcpuError);
        }
        state.bits = new_bits;
        Ok(())
    }

    fn resume(&self) {
        let mut state = self.0.lock();
        state.bits.set_bit(PerCpu::get().idx, true);
    }

    pub fn finish_launch(&self) {
        let mut state = self.0.lock();
        assert!(state.is_launching);
        state.is_launching = false;
        state.launched += 1;
    }
}

enum ScheduledCpu {
    Existing(u8),
    New,
}

/// Tell the supervisor to schedule another vcpu.
pub fn schedule_vcpu() {
    let Some(cpu) = SCHEDULER.pick_any() else {
        return;
    };

    match cpu {
        ScheduledCpu::Existing(cpu) => {
            SUPERVISOR_SERVICES
                .notification_buffer
                .arm(usize::from(cpu));
            kick_supervisor(true);
        }
        ScheduledCpu::New => start_next_ap(),
    }
}

pub fn output(bytes: &[u8]) {
    for chunk in bytes.chunks(0x1000) {
        push_background_command(UpdateOutput::new(chunk));
    }
}

/// Tell to supervisor to commit the output and produce and attestation report.
pub fn commit_output() -> ! {
    push_async_command(FinishOutput);

    // Halt.
    loop {
        kick_supervisor(false);
    }
}

/// Tell the supervisor that something went wrong and to discard the output.
pub fn fail() -> ! {
    push_async_command(FailOutput);

    // Halt.
    loop {
        kick_supervisor(false);
    }
}
