use constants::{ApBitmap, ApIndex};
use process::syscall;
use x86_64::instructions::interrupts::without_interrupts;

use crate::{
    exception::TimerInterruptGuard,
    memory::{frame, pagetable::flush},
    per_cpu::PerCpu,
    rt::poll,
    spin::mutex::Mutex,
    supervisor::{self, start_next_ap},
    time::advance_time,
};

pub mod process;

pub fn run() -> ! {
    syscall::init();

    loop {
        while poll() {}

        // Halt the vCPU.

        frame::release_private();

        let res = halt();
        if res.is_err() {
            // We're the last vCPU running.
            // Advance simulated time.
            let res = advance_time();

            if res.is_err() {
                // There are no futures than are ready to be polled.

                // Dump the state of processes to aid with debugging.
                #[cfg(not(feature = "harden"))]
                process::dump();

                panic!("no future is ready");
            }
        }
    }
}

/// Halt this vcpu.
#[inline(never)]
fn halt() -> Result<(), LastRunningVcpuError> {
    SCHEDULER.halt()?;

    #[cfg(feature = "profiling")]
    crate::profiler::flush();

    flush::pre_halt();

    supervisor::halt();

    flush::post_halt();

    SCHEDULER.resume();

    Ok(())
}

/// An error that is returned when the last running vCPU request to be halted.
#[derive(Debug, Clone, Copy)]
struct LastRunningVcpuError;

pub static SCHEDULER: Scheduler = Scheduler::new();

pub struct Scheduler(Mutex<SchedulerState, TimerInterruptGuard>);

struct SchedulerState {
    /// One bit for every vCPU.
    bits: ApBitmap,
    /// The number of vCPUs that have finished being launched.
    launched: u8,
    /// Whether a vCPU is being launched right now.
    is_launching: bool,
}

impl Scheduler {
    pub const fn new() -> Self {
        let mut bits = ApBitmap::empty();
        bits.set(ApIndex::new(0), true);

        Self(Mutex::new(SchedulerState {
            bits,
            launched: 0,
            is_launching: true,
        }))
    }

    fn pick_any(&self) -> Option<ScheduledCpu> {
        without_interrupts(|| {
            let mut state = self.0.try_lock()?;
            let idx = state.bits.first_unset()?;
            if idx.as_u8() < state.launched {
                state.bits.set(idx, true);

                Some(ScheduledCpu::Existing(idx))
            } else {
                if state.is_launching {
                    return None;
                }

                state.is_launching = true;
                state.bits.set(idx, true);

                Some(ScheduledCpu::New)
            }
        })
    }

    fn halt(&self) -> Result<(), LastRunningVcpuError> {
        let mut state = self.0.lock();
        let mut new_bits = state.bits;
        new_bits.set(PerCpu::get().idx, false);
        // Ensure that this vCPU isn't the last one running.
        if new_bits.is_empty() {
            return Err(LastRunningVcpuError);
        }
        state.bits = new_bits;
        Ok(())
    }

    fn resume(&self) {
        let mut state = self.0.lock();
        state.bits.set(PerCpu::get().idx, true);
    }

    pub fn finish_launch(&self) {
        let mut state = self.0.lock();
        assert!(state.is_launching);
        state.is_launching = false;
        state.launched += 1;
    }
}

enum ScheduledCpu {
    Existing(ApIndex),
    New,
}

/// Tell the supervisor to schedule another vcpu.
pub fn schedule_vcpu() {
    let Some(cpu) = SCHEDULER.pick_any() else {
        return;
    };

    match cpu {
        ScheduledCpu::Existing(cpu) => supervisor::kick(cpu),
        ScheduledCpu::New => unsafe { start_next_ap() },
    }
}
