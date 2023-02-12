pub mod process;

pub fn run() -> ! {
    loop {
        process::thread::run_thread();
    }
}
