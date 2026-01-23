#![no_std]

use core::{arch::asm, panic::PanicInfo};

#[unsafe(no_mangle)]
#[unsafe(naked)]
#[cfg(target_pointer_width = "32")]
pub extern "C" fn __kernel_vsyscall() {
    core::arch::naked_asm!(
        ".symver __kernel_vsyscall, __kernel_vsyscall@@LINUX_2.5",
        ".cfi_startproc",
        "int 0x80",
        "ret",
        ".cfi_endproc"
    );
}

#[panic_handler]
fn panic_handler(_: &PanicInfo) -> ! {
    unsafe {
        asm!("ud2", options(nomem, nostack, noreturn));
    }
}
