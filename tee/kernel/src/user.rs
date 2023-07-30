use crate::{
    supervisor::halt,
    time::{advance_time, fire_expired_timeout},
};

use self::process::{memory::VirtualMemoryActivator, thread::CHILD_DEATHS};

pub mod process;

pub fn run(vm_activator: &mut VirtualMemoryActivator) -> ! {
    loop {
        let mut should_halt = true;

        let ran = process::thread::run_thread(vm_activator);
        if ran {
            should_halt = false;
        }

        let done = CHILD_DEATHS.process(vm_activator);
        if !done {
            should_halt = false;
        }

        let ran = fire_expired_timeout();
        if ran {
            should_halt = false;
        }

        if !should_halt {
            continue;
        }

        let res = halt();
        if res.is_err() {
            // We're the last vCPU running.
            // Advance simulated time.
            advance_time().unwrap();
        }
    }
}
