use crate::{rt::poll, supervisor::halt, time::advance_time};

use self::process::memory::{do_virtual_memory_op, VirtualMemoryActivator};

pub mod process;

pub fn run(vm_activator: &mut VirtualMemoryActivator) -> ! {
    loop {
        let mut should_halt = true;

        let polled = poll(vm_activator);
        if polled {
            should_halt = false;
        }

        let ran = do_virtual_memory_op(vm_activator);
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
