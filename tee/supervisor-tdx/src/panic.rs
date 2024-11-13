use core::arch::asm;
use core::panic::PanicInfo;

use log::error;

#[panic_handler]
fn panic_handler(info: &PanicInfo) -> ! {
    error!("{info}");
    triple_fault();
}

fn triple_fault() -> ! {
    // We don't have an exception handler for int3 or double faults, so this
    // will cause a triple fault.
    unsafe {
        asm!("int3", options(noreturn));
    }
}
