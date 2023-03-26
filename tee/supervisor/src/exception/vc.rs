use core::arch::asm;

use log::error;
use snp_types::intercept::VMEXIT_UNVALIDATED;
use x86_64::{
    registers::{control::Cr2, rflags::RFlags},
    structures::{gdt::SegmentSelector, idt::InterruptStackFrame},
};

use crate::ghcb::exit;

#[derive(Debug)]
#[repr(C)]
struct StackFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub exception_code: u64,
    pub rip: u64,
    pub cs: SegmentSelector,
    pub rflags: RFlags,
    pub rsp: u64,
    pub ss: SegmentSelector,
}

#[naked]
pub(super) extern "x86-interrupt" fn vmm_communication_exception_handler(
    frame: InterruptStackFrame,
    code: u64,
) {
    unsafe {
        asm!(
            // Push the general purpose registers.
            "push rax",
            "push rcx",
            "push rdx",
            "push rbx",
            "push rbp",
            "push rsi",
            "push rdi",
            "push r8",
            "push r9",
            "push r10",
            "push r11",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            // Prepare the parameter for the call to
            // `handle_vmm_communication_exception`.
            "lea rdi, [rsp]",
            // Align the stack.
            "mov rbp, rsp",
            "and rsp, -0x10",
            // Call the exception handler.
            "call {handler}",
            // Restore the stack.
            "mov rsp, rbp",
            // Pop the general purpose registers.
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop r11",
            "pop r10",
            "pop r9",
            "pop r8",
            "pop rdi",
            "pop rsi",
            "pop rbp",
            "pop rbx",
            "pop rdx",
            "pop rcx",
            "pop rax",
            // Pop the exception code.
            "add rsp, 8",
            // Return from the interrupt.
            "iretq",
            handler = sym handle_vmm_communication_exception,
            // struct_size = const size_of::<ExceptionInfo>(),
            options(noreturn),
        );
    }
}

extern "sysv64" fn handle_vmm_communication_exception(frame: &mut StackFrame) {
    match frame.exception_code {
        VMEXIT_UNVALIDATED => {
            let page = Cr2::read();
            error!("{page:?} is not validated");
        }
        _ => error!(
            "#VC exception with unknown code: {:#02x}",
            frame.exception_code
        ),
    }

    let StackFrame {
        r15,
        r14,
        r13,
        r12,
        r11,
        r10,
        r9,
        r8,
        rdi,
        rsi,
        rbp,
        rbx,
        rdx,
        rcx,
        rax,
        exception_code: _,
        rip,
        cs: _,
        rflags: _,
        rsp,
        ss: _,
    } = &frame;

    error!("Registers:");
    error!("rip: {rip:#018x}");
    error!("rax: {rax:#018x} rbx: {rbx:#018x} rcx: {rcx:#018x} rdx: {rdx:#018x}");
    error!("rsi: {rsi:#018x} rdi: {rdi:#018x} rsp: {rsp:#018x} rbp: {rbp:#018x}");
    error!("r8:  {r8:#018x} r9:  {r9:#018x} r10: {r10:#018x} r11: {r11:#018x}");
    error!("r12: {r12:#018x} r13: {r13:#018x} r14: {r14:#018x} r15: {r15:#018x}");

    exit();
}
