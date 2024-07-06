//! This module is responsible for handling CPU exceptions.

use core::mem::offset_of;
use core::{alloc::Layout, arch::asm, ptr::null_mut};

use crate::spin::lazy::Lazy;
use alloc::alloc::alloc;
use log::{debug, error, trace};
use snp_types::intercept::VMEXIT_CPUID;
use x86_64::structures::gdt::SegmentSelector;
use x86_64::{
    instructions::tables::load_tss,
    registers::{
        control::Cr2,
        model_specific::Star,
        segmentation::{Segment, CS, DS, ES, SS},
    },
    structures::{
        gdt::{Descriptor, DescriptorFlags, GlobalDescriptorTable},
        idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode},
        paging::Page,
        tss::TaskStateSegment,
    },
    PrivilegeLevel, VirtAddr,
};

use crate::{memory::pagetable::entry_for_page, per_cpu::PerCpu};

/// Initialize exception handling.
///
/// # Safety
///
/// This function must only be called once by main.
pub unsafe fn init() {
    load_gdt();
    load_idt();
}

pub fn switch_stack(f: extern "C" fn() -> !) -> ! {
    let stack = allocate_stack();

    unsafe {
        asm!(
            "mov rsp, {stack}",
            "call {f}",
            "ud2",
            stack = in(reg) stack.as_u64(),
            f = in(reg) f,
            options(noreturn),
        );
    }
}

fn allocate_stack() -> VirtAddr {
    // FIXME: Guard pages.
    let stack_layout = Layout::from_size_align(0x10000, 16).unwrap();
    let stack = unsafe { alloc(stack_layout) };
    assert_ne!(stack, null_mut());
    let end_of_stack = unsafe { stack.add(stack_layout.size()) };
    VirtAddr::from_ptr(end_of_stack)
}

#[derive(Clone, Copy)]
struct Selectors {
    kernel_cs: SegmentSelector,
    kernel_ds: SegmentSelector,
    _user32_cs: SegmentSelector,
    user_ds: SegmentSelector,
    user_cs: SegmentSelector,
}

static BASE_GDT_WITH_SELECTORS: (GlobalDescriptorTable, Selectors) = {
    let mut gdt = GlobalDescriptorTable::new();
    let kernel_cs = gdt.append(Descriptor::kernel_code_segment());
    let kernel_ds = gdt.append(Descriptor::kernel_data_segment());
    let user32_cs = gdt.append(Descriptor::UserSegment(DescriptorFlags::USER_CODE32.bits()));
    let user_ds = gdt.append(Descriptor::user_data_segment());
    let user_cs = gdt.append(Descriptor::user_code_segment());
    (
        gdt,
        Selectors {
            kernel_cs,
            kernel_ds,
            _user32_cs: user32_cs,
            user_ds,
            user_cs,
        },
    )
};

/// Load a Global Descriptor Table. The old GDT setup by the reset vector is
/// no longer accessible.
pub fn load_early_gdt() {
    let (ref gdt, selectors) = BASE_GDT_WITH_SELECTORS;

    debug!("loading global descriptor table");
    gdt.load();

    unsafe {
        // Safety: kernel_cs points to a 64 bit code segment.
        CS::set_reg(selectors.kernel_cs);
    }
    unsafe {
        // Safety: kernel_ds points to a data segment.
        SS::set_reg(selectors.kernel_ds);
        DS::set_reg(selectors.kernel_ds);
        ES::set_reg(selectors.kernel_ds);
    }

    // Initialize the segment selectors in `Star` msr for `syscall`/`sysret`.
    Star::write(
        selectors.user_cs,
        selectors.user_ds,
        selectors.kernel_cs,
        selectors.kernel_ds,
    )
    .unwrap();
}

/// Load a Global Descriptor Table. The old GDT setup by the reset vector is
/// no longer accessible.
pub fn load_gdt() {
    let per_cpu = PerCpu::get();

    let mut tss = TaskStateSegment::new();
    tss.privilege_stack_table[0] = allocate_stack();
    per_cpu.tss.set(tss).expect("TSS was already initialized");
    let tss = per_cpu.tss.get().unwrap();

    let mut gdt = BASE_GDT_WITH_SELECTORS.0.clone();
    let tss_seg = gdt.append(Descriptor::tss_segment(tss));
    per_cpu.gdt.set(gdt).unwrap();
    let gdt = per_cpu.gdt.get().unwrap();

    debug!("loading global descriptor table");
    gdt.load();

    debug!("loading tss");
    unsafe {
        load_tss(tss_seg);
    }
}

/// Load an IDT.
pub fn load_idt() {
    static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
        let mut idt = InterruptDescriptorTable::new();
        idt.divide_error.set_handler_fn(divide_error_handler);
        idt.double_fault.set_handler_fn(double_fault_handler);
        idt.general_protection_fault
            .set_handler_fn(general_protection_fault_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.vmm_communication_exception.set_handler_fn(vc_handler);

        idt[0x80]
            .set_handler_fn(int0x80_handler)
            .set_privilege_level(PrivilegeLevel::Ring3);
        idt
    });

    debug!("loading interrupt descriptor table");
    IDT.load();
}

#[naked]
#[no_sanitize(address)]
extern "x86-interrupt" fn divide_error_handler(frame: InterruptStackFrame) {
    unsafe {
        asm!(
            // Check whether the exception happened in userspace.
            "test word ptr [rsp+16], 3",
            "je {kernel_divide_error_handler}",

            // Userspace code path:
            "swapgs",
            // Store the error code.
            "mov byte ptr gs:[{VECTOR_OFFSET}], 0x0",
            // Jump to the userspace exit point.
            "jmp gs:[{HANDLER_OFFSET}]",

            kernel_divide_error_handler = sym kernel_divide_error_handler,
            VECTOR_OFFSET = const offset_of!(PerCpu, vector),
            HANDLER_OFFSET = const offset_of!(PerCpu, userspace_exception_exit_point),
            options(noreturn),
        );
    }
}

#[no_sanitize(address)]
extern "x86-interrupt" fn kernel_divide_error_handler(frame: InterruptStackFrame) {
    panic!("divide error {frame:x?}");
}

#[naked]
#[no_sanitize(address)]
extern "x86-interrupt" fn page_fault_handler(
    frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    unsafe {
        asm!(
            // Check whether the exception happened in userspace.
            "test word ptr [rsp+16], 3",
            "je 66f",

            // Userspace code path:
            "swapgs",
            // Store the error code.
            "mov byte ptr gs:[{VECTOR_OFFSET}], 0xe",
            "pop qword ptr gs:[{ERROR_CODE_OFFSET}]",
            // Jump to the userspace exit point.
            "jmp gs:[{HANDLER_OFFSET}]",

            // Kernel code path:
            "66:",
            // Check if we can recover from the exception.
            "push rax",
            "push rbx",
            "push rcx",
            // Loop setup
            "mov rbx, [rsp+8+24]",
            "lea rax, [rip+__recoverable_start]",
            "lea rcx, [rip+__recoverable_end]",
            "sub rcx, rax",
            "shr rcx, 4",
            "test rcx, rcx",
            "je 68f",

            // Loop body.
            "67:",
            "cmp [rax], rbx",
            "je 69f",
            "add rax, 16",
            "loop 67b",

            // We couldn't recover from the exception.
            "68:",
            "pop rcx",
            "pop rbx",
            "pop rax",

            // Jump to the kernel page fault handler.
            "jmp {kernel_page_fault_handler}",

            // Recover from the exception.
            "69:",
            "mov rax, [rax+8]",
            "mov [rsp+8+24], rax",

            "pop rcx",
            "pop rbx",
            "pop rax",

            "mov rdx, 1",
            "add rsp, 8",
            "iretq",

            kernel_page_fault_handler = sym kernel_page_fault_handler,
            VECTOR_OFFSET = const offset_of!(PerCpu, vector),
            ERROR_CODE_OFFSET = const offset_of!(PerCpu, error_code),
            HANDLER_OFFSET = const offset_of!(PerCpu, userspace_exception_exit_point),
            options(noreturn),
        );
    }
}

#[no_sanitize(address)]
extern "x86-interrupt" fn kernel_page_fault_handler(
    frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) -> ! {
    page_fault_handler_impl(frame, error_code);
}

fn page_fault_handler_impl(frame: InterruptStackFrame, error_code: PageFaultErrorCode) -> ! {
    let cr2 = Cr2::read_raw();

    trace!("page fault");

    assert!(!error_code.contains(PageFaultErrorCode::USER_MODE));

    if let Ok(cr2) = VirtAddr::try_new(cr2) {
        if let Some(entry) = entry_for_page(Page::containing_address(cr2)) {
            error!("page is mapped to {entry:?}");
        } else {
            error!("page is not mapped");
        }
    } else {
        error!("cr2 is not a canonical address");
    }

    #[cfg(sanitize = "address")]
    crate::sanitize::page_fault_handler(&frame);

    panic!(
        "page fault {error_code:?} trying to access {cr2:#018x} at ip {:#018x}",
        frame.instruction_pointer
    );
}

#[naked]
#[no_sanitize(address)]
extern "x86-interrupt" fn general_protection_fault_handler(
    frame: InterruptStackFrame,
    error_code: u64,
) {
    unsafe {
        asm!(
            // Check whether the exception happened in userspace.
            "test word ptr [rsp+16], 3",
            "je {kernel_general_protection_fault_handler}",

            // Userspace code path:
            "swapgs",
            // Store the error code.
            "mov byte ptr gs:[{VECTOR_OFFSET}], 0xd",
            "pop qword ptr gs:[{ERROR_CODE_OFFSET}]",
            // Jump to the userspace exit point.
            "jmp gs:[{HANDLER_OFFSET}]",

            kernel_general_protection_fault_handler = sym kernel_general_protection_fault_handler,
            VECTOR_OFFSET = const offset_of!(PerCpu, vector),
            ERROR_CODE_OFFSET = const offset_of!(PerCpu, error_code),
            HANDLER_OFFSET = const offset_of!(PerCpu, userspace_exception_exit_point),
            options(noreturn),
        );
    }
}

#[no_sanitize(address)]
extern "x86-interrupt" fn kernel_general_protection_fault_handler(
    frame: InterruptStackFrame,
    code: u64,
) {
    panic!("general protection fault {frame:x?} {code:x?}");
}

#[no_sanitize(address)]
extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, code: u64) -> ! {
    panic!("double fault {frame:x?} {code:x?}");
}

#[naked]
#[no_sanitize(address)]
extern "x86-interrupt" fn vc_handler(frame: InterruptStackFrame, error_code: u64) {
    unsafe {
        asm!(
            // Check whether the exception happened in userspace.
            "test word ptr [rsp+16], 3",
            "je {kernel_vc_handler}",

            // Userspace code path:
            "swapgs",
            // Store the error code.
            "mov byte ptr gs:[{VECTOR_OFFSET}], 0x1d",
            "pop qword ptr gs:[{ERROR_CODE_OFFSET}]",
            // Jump to the userspace exit point.
            "jmp gs:[{HANDLER_OFFSET}]",

            kernel_vc_handler = sym kernel_vc_handler,
            VECTOR_OFFSET = const offset_of!(PerCpu, vector),
            ERROR_CODE_OFFSET = const offset_of!(PerCpu, error_code),
            HANDLER_OFFSET = const offset_of!(PerCpu, userspace_exception_exit_point),
            options(noreturn),
        );
    }
}

#[no_sanitize(address)]
#[naked]
extern "x86-interrupt" fn kernel_vc_handler(frame: InterruptStackFrame, code: u64) {
    unsafe {
        asm!(
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
            // "sub rsp, 8",
            // TODO: make sure alignment is correct.
            "call {kernel_vc_handler_impl}",
            // "add rsp, 8",
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
            "add rsp, 8", // skip error code.
            "iretq",
            kernel_vc_handler_impl = sym kernel_vc_handler_impl,
            options(noreturn)
        );
    }
}

/// The set of caller-saved registers + rbx.
#[repr(C)]
struct VcStackFrame {
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

pub fn emulate_cpuid(eax: u32, ecx: u32) -> (u32, u32, u32, u32) {
    // These values are based on EPYC Milan.
    // TODO: Add support for other CPU models.
    match (eax, ecx) {
        (0x0000_0000, _) => (0x00000010, 0x68747541, 0x444d4163, 0x69746e65),
        (0x0000_0001, _) => (0x00a00f11, 0x51800800, 0x7eda320b, 0x178bfbff),
        (0x0000_0007, _) => (0x00000000, 0x219c95a9, 0x0040069c, 0x00000000),
        (0x0000_0008..=0x0000_000a, _) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (0x0000_000d, 0x00) => (0x00000207, 0x00000988, 0x00000988, 0x00000000),
        (0x0000_000d, 0x01) => (0x0000000f, 0x00000358, 0x00001800, 0x00000000),
        (0x0000_000d, 0x02) => (0x00000100, 0x00000240, 0x00000000, 0x00000000),
        (0x0000_000d, 0x03) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (0x0000_000d, 0x05) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (0x0000_000d, 0x06) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (0x0000_000d, 0x07) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (0x0000_000d, 0x0b) => (0x00000010, 0x00000000, 0x00000001, 0x00000000),
        (0x0000_000d, 0x0c) => (0x00000018, 0x00000000, 0x00000001, 0x00000000),
        (0x0000_000d, 0x0d..) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (0x0000_0011..=0x0000_ffff, _) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (0x8000_0000, _) => (0x80000023, 0x68747541, 0x444d4163, 0x69746e65),
        (0x8000_0001, _) => (0x00a00f11, 0x40000000, 0x75c237ff, 0x2fd3fbff),
        (0x8000_0007, _) => (0x00000000, 0x0000003b, 0x00000000, 0x00006799),
        (0x8000_0008, _) => (0x00003030, 0x91bef75f, 0x0000707f, 0x00010007),
        (0x8000_000a, _) => (0x00000001, 0x00008000, 0x00000000, 0x119b9cff),
        (0x8000_001d, _) => (0x00004121, 0x01c0003f, 0x0000003f, 0x00000000),
        (0x8000_0024..=0x8000_ffff, _) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (eax, ecx) => todo!("unimplemented CPUID function eax={eax:#x}, ecx={ecx:#x}"),
    }
}

extern "C" fn kernel_vc_handler_impl(registers: &mut VcStackFrame) {
    match registers.error_code {
        VMEXIT_CPUID => {
            let (eax, ebx, ecx, edx): (u32, u32, u32, u32) =
                emulate_cpuid(registers.rax as u32, registers.rcx as u32);
            registers.rax = u64::from(eax);
            registers.rbx = u64::from(ebx);
            registers.rcx = u64::from(ecx);
            registers.rdx = u64::from(edx);

            // skip over the cpuid instruction.
            registers.rip += 2;
        }
        code => todo!("unimplemented VC error code: {code:#x}"),
    }
}

#[no_sanitize(address)]
#[naked]
extern "x86-interrupt" fn int0x80_handler(frame: InterruptStackFrame) {
    // The code that entered userspace stored addresses where execution should
    // continue when userspace exits.
    unsafe {
        asm!(
            "swapgs",
            "mov byte ptr gs:[{VECTOR_OFFSET}], 0x80",
            "jmp gs:[{HANDLER_OFFSET}]",
            VECTOR_OFFSET = const offset_of!(PerCpu, vector),
            HANDLER_OFFSET = const offset_of!(PerCpu, userspace_exception_exit_point),
            options(noreturn)
        );
    }
}
