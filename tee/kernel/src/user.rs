use crate::{memory::frame, rt::poll, supervisor::halt, time::advance_time};

pub mod process;

pub fn run() -> ! {
    loop {
        let mut should_halt = true;

        let polled = poll();
        if polled {
            should_halt = false;
        }

        if !should_halt {
            continue;
        }

        // Halt the vCPU.

        frame::release_private();

        let res = halt();
        if res.is_err() {
            // We're the last vCPU running.
            // Advance simulated time.
            advance_time().unwrap();
        }
    }
}
