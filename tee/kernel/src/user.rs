use crate::supervisor::halt;

use self::process::{memory::VirtualMemoryActivator, thread::CHILD_DEATHS};

pub mod process;

pub fn run(vm_activator: &mut VirtualMemoryActivator) -> ! {
    loop {
        let ran = process::thread::run_thread(vm_activator);
        CHILD_DEATHS.process(vm_activator);
        if !ran {
            halt();
        }
    }
}
