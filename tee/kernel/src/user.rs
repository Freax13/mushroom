use crate::{memory::frame, rt::poll, supervisor::halt, time::advance_time};

pub mod process;

pub fn run() -> ! {
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
