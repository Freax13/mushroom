use core::cell::LazyCell;

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

use crate::FakeSync;

pub fn init() {
    static IDT: FakeSync<LazyCell<InterruptDescriptorTable>> = FakeSync::new(LazyCell::new(|| {
        let mut idt = InterruptDescriptorTable::new();

        idt.hv_injection_exception
            .set_handler_fn(hv_injection_exception_handler);

        idt
    }));

    IDT.load();
}

pub(super) extern "x86-interrupt" fn hv_injection_exception_handler(_frame: InterruptStackFrame) {
    // This exception handler has to be empty for `FakeSync` to be sound.
}
