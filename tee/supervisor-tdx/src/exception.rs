use bit_field::BitField;
use spin::Lazy;
use x86_64::{
    registers::model_specific::Msr,
    structures::idt::{InterruptDescriptorTable, InterruptStackFrame},
};

use crate::{tdcall::Vmcall, tlb::flush_handler};

pub const WAKEUP_VECTOR: u8 = 0x60;
pub const FLUSH_VECTOR: u8 = 0x61;

pub fn setup_idt() {
    IDT.load();
    x86_64::instructions::interrupts::enable();
    Vmcall::instruction_wrmsr(0x80f, 0x1ff);
}

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    idt[WAKEUP_VECTOR].set_handler_fn(wakeup_handler);
    idt[FLUSH_VECTOR].set_handler_fn(flush_handler);
    idt
});

extern "x86-interrupt" fn wakeup_handler(_frame: InterruptStackFrame) {
    // Don't do anything.
    // This handler only exists to move past `hlt`.
    eoi();
}

pub fn eoi() {
    unsafe {
        Msr::new(0x80b).write(0);
    }
}

pub fn send_ipi(destination: u32, vector: u8) {
    let mut bits = 0;
    bits.set_bits(0..8, u64::from(vector));
    bits.set_bits(8..11, 0); // Delivery Mode: Fixed
    bits.set_bit(11, false); // Destination Mode: Physical
    bits.set_bit(14, true); // Level: Assert
    bits.set_bits(18..20, 0b00);
    bits.set_bits(32.., u64::from(destination)); // Destination
    Vmcall::instruction_wrmsr(0x830, bits);
}
