use core::panic::PanicInfo;

use x86_64::structures::idt::InterruptDescriptorTable;

use crate::host::exit;

#[panic_handler]
fn panic_handler(info: &PanicInfo) -> ! {
    let _ = info;

    #[cfg(not(feature = "harden"))]
    {
        use core::sync::atomic::{AtomicBool, Ordering};

        use log::error;
        static IS_PANICKING: AtomicBool = AtomicBool::new(false);
        let is_already_panicking = IS_PANICKING.swap(true, Ordering::SeqCst);

        if is_already_panicking {
            // We messed up bad. Cause a triple fault.
            triple_fault();
        }

        error!("{info}");

        print_backtrace();
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

#[cfg(not(feature = "harden"))]
#[inline(always)]
fn walk_frames() -> impl Iterator<Item = u64> {
    use core::arch::asm;
    use core::iter::from_fn;

    let rbp: u64;
    unsafe {
        asm!("mov {}, rbp", out(reg) rbp);
    }

    let mut frame_pointer = rbp;
    from_fn(move || {
        if frame_pointer == 0 {
            return None;
        }

        let copy = frame_pointer;
        frame_pointer = unsafe { (frame_pointer as *const u64).read_volatile() };
        Some(copy)
    })
}

#[cfg(not(feature = "harden"))]
#[inline(always)]
fn print_backtrace() {
    use log::debug;

    debug!("Stack frames:");
    for frame in walk_frames() {
        let rip = unsafe { (frame as *const u64).add(1).read_volatile() };
        debug!("{rip:016x}");
    }
}
