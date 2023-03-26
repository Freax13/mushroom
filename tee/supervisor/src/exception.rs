use core::cell::LazyCell;

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

use crate::FakeSync;

// Register an exception handler for the #HV vector.
pub fn init() {
    static IDT: FakeSync<LazyCell<InterruptDescriptorTable>> = FakeSync::new(LazyCell::new(|| {
        let mut idt = InterruptDescriptorTable::new();

        idt.hv_injection_exception
            .set_handler_fn(hv_injection_exception_handler);

        idt
    }));

    IDT.load();
}

// Do nothing. The actual interrupt will be polled by the main thread.
// The host will nonetheless inject #HV exceptions and we have to handle them
// to prevent a #NP fault which would lead to a double fault which would lead
// to a triple fault shutting down the system.
extern "x86-interrupt" fn hv_injection_exception_handler(_frame: InterruptStackFrame) {
    // This exception handler has to be empty for `FakeSync` to be sound.
    // If we ever want to run some code here `FakeSync` will have to change.
}
