use self::process::memory::VirtualMemoryActivator;

pub mod process;

pub fn run(vm_activator: &mut VirtualMemoryActivator) -> ! {
    loop {
        process::thread::run_thread(vm_activator);
    }
}
