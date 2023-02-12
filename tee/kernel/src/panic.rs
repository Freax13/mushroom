use core::{
    panic::PanicInfo,
    sync::atomic::{AtomicBool, Ordering},
};

use log::error;
use x86_64::structures::idt::InterruptDescriptorTable;

use crate::host::exit;

#[panic_handler]
fn panic_handler(info: &PanicInfo) -> ! {
    #[cfg(debug_assertions)]
    {
        static IS_PANICKING: AtomicBool = AtomicBool::new(false);
        let is_already_panicking = IS_PANICKING.swap(true, Ordering::SeqCst);

        if is_already_panicking {
            // We messed up bad. Cause a triple fault.
            triple_fault();
        }

        error!("{info}");
    }

    exit(false);
    triple_fault();
}

fn triple_fault() -> ! {
    // Load a IDT without any exception handlers enabled.
    let idt = InterruptDescriptorTable::new();
    unsafe {
        idt.load_unsafe();
    }

    // Halt the processor.
    loop {
        unsafe {
            core::arch::asm!("int3");
        }
    }
}
