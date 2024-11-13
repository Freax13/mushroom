use core::arch::naked_asm;

use bit_field::BitField;
use constants::AtomicApBitmap;
use spin::Lazy;
use tdx_types::vmexit::VMEXIT_REASON_CPUID_INSTRUCTION;
use x86_64::{
    registers::model_specific::Msr,
    structures::idt::{InterruptDescriptorTable, InterruptStackFrame},
};

use crate::{
    per_cpu::PerCpu,
    tdcall::{Tdcall, Vmcall},
};

pub const WAKEUP_VECTOR: u8 = 0x60;

pub fn setup_idt() {
    IDT.load();
    x86_64::instructions::interrupts::enable();
    Vmcall::instruction_wrmsr(0x80f, 0x1ff);
}

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    idt.virtualization.set_handler_fn(virtualization_handler);
    idt[WAKEUP_VECTOR].set_handler_fn(wakeup_handler);
    idt
});

/// The set of caller-saved registers + rbx.
#[repr(C)]
struct VeStackFrame {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    error_code: u64,
    rip: u64,
}

#[naked]
extern "x86-interrupt" fn virtualization_handler(_frame: InterruptStackFrame) {
    unsafe {
        naked_asm!(
            "endbr64",
            "cld",
            "push r11",
            "push r10",
            "push r9",
            "push r8",
            "push rdi",
            "push rsi",
            "push rdx",
            "push rcx",
            "push rbx",
            "push rax",
            "mov rdi, rsp",
            "sub rsp, 8",
            // TODO: make sure alignment is correct.
            "call {virtualization_handler_impl}",
            "add rsp, 8",
            "pop rax",
            "pop rbx",
            "pop rcx",
            "pop rdx",
            "pop rsi",
            "pop rdi",
            "pop r8",
            "pop r9",
            "pop r10",
            "pop r11",
            "iretq",
            virtualization_handler_impl = sym virtualization_handler_impl,
        );
    }
}

extern "C" fn virtualization_handler_impl(frame: &mut VeStackFrame) {
    let ve_info = Tdcall::vp_veinfo_get();
    match ve_info.exit_reason {
        VMEXIT_REASON_CPUID_INSTRUCTION => {
            // The TDX-module injects a #VE exception for unsupported CPUID
            // leaves. Default to all-zeroes.
            frame.rax = 0;
            frame.rbx = 0;
            frame.rcx = 0;
            frame.rdx = 0;
        }
        reason => unimplemented!("unimplemented #VE reason: {reason}"),
    }
}

pub static WAKEUP_TOKEN: AtomicApBitmap = AtomicApBitmap::empty();

extern "x86-interrupt" fn wakeup_handler(_frame: InterruptStackFrame) {
    WAKEUP_TOKEN.set(PerCpu::current_vcpu_index());
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
