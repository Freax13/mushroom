//! This module is responsible for handling CPU exceptions.

use core::mem::offset_of;
use core::{
    alloc::Layout,
    arch::{asm, naked_asm},
    ptr::null_mut,
};

use crate::memory::pagetable::flush::tlb_shootdown_handler;
use crate::spin::lazy::Lazy;
use crate::time;
use crate::user::process::syscall::cpu_state::exception_entry;
use alloc::alloc::alloc;
use constants::{TIMER_VECTOR, TLB_VECTOR};
use log::{debug, error, trace};
use x86_64::registers::model_specific::Msr;
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
        idt[TLB_VECTOR].set_handler_fn(tlb_shootdown_handler);
        idt[TIMER_VECTOR].set_handler_fn(timer_handler);

        idt[0x80]
            .set_handler_fn(int0x80_handler)
            .set_privilege_level(PrivilegeLevel::Ring3);
        idt
    });

    debug!("loading interrupt descriptor table");
    IDT.load();
}

#[naked]
extern "x86-interrupt" fn divide_error_handler(frame: InterruptStackFrame) {
    unsafe {
        naked_asm!(
            "cld",
            // Check whether the exception happened in userspace.
            "test word ptr [rsp+8], 3",
            "je {kernel_divide_error_handler}",

            // Userspace code path:
            "swapgs",
            // Store the error code.
            "mov byte ptr gs:[{VECTOR_OFFSET}], 0x0",
            // Jump to the userspace exit point.
            "jmp {exception_entry}",

            kernel_divide_error_handler = sym kernel_divide_error_handler,
            VECTOR_OFFSET = const offset_of!(PerCpu, vector),
            exception_entry = sym exception_entry,
        );
    }
}

extern "x86-interrupt" fn kernel_divide_error_handler(frame: InterruptStackFrame) {
    panic!("divide error {frame:x?}");
}

#[naked]
extern "x86-interrupt" fn page_fault_handler(
    frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    unsafe {
        naked_asm!(
            "cld",
            // Check whether the exception happened in userspace.
            "test word ptr [rsp+16], 3",
            "je 66f",

            // Userspace code path:
            "swapgs",
            // Store the error code.
            "mov byte ptr gs:[{VECTOR_OFFSET}], 0xe",
            "pop qword ptr gs:[{ERROR_CODE_OFFSET}]",
            // Jump to the userspace exit point.
            "jmp {exception_entry}",

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
            exception_entry = sym exception_entry,
        );
    }
}

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
extern "x86-interrupt" fn general_protection_fault_handler(
    frame: InterruptStackFrame,
    error_code: u64,
) {
    unsafe {
        naked_asm!(
            "cld",
            // Check whether the exception happened in userspace.
            "test word ptr [rsp+16], 3",
            "je {kernel_general_protection_fault_handler}",

            // Userspace code path:
            "swapgs",
            // Store the error code.
            "mov byte ptr gs:[{VECTOR_OFFSET}], 0xd",
            "pop qword ptr gs:[{ERROR_CODE_OFFSET}]",
            // Jump to the userspace exit point.
            "jmp {exception_entry}",

            kernel_general_protection_fault_handler = sym kernel_general_protection_fault_handler,
            VECTOR_OFFSET = const offset_of!(PerCpu, vector),
            ERROR_CODE_OFFSET = const offset_of!(PerCpu, error_code),
            exception_entry = sym exception_entry,
        );
    }
}

extern "x86-interrupt" fn kernel_general_protection_fault_handler(
    frame: InterruptStackFrame,
    code: u64,
) {
    panic!("general protection fault {frame:x?} {code:x?}");
}

extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, code: u64) -> ! {
    panic!("double fault {frame:x?} {code:x?}");
}

#[naked]
extern "x86-interrupt" fn timer_handler(frame: InterruptStackFrame) {
    unsafe {
        naked_asm!(
            "cld",
            // Check whether the irq happened in userspace.
            "test word ptr [rsp+8], 3",
            "je {kernel_timer_handler}",

            // Userspace code path:
            "swapgs",
            // Store the error code.
            "mov byte ptr gs:[{VECTOR_OFFSET}], {TIMER_VECTOR}",
            // Jump to the userspace exit point.
            "jmp {exception_entry}",

            kernel_timer_handler = sym kernel_timer_handler,
            VECTOR_OFFSET = const offset_of!(PerCpu, vector),
            TIMER_VECTOR = const TIMER_VECTOR,
            exception_entry = sym exception_entry,
        );
    }
}

extern "x86-interrupt" fn kernel_timer_handler(_: InterruptStackFrame) {
    time::try_fire_clocks();
    eoi();
}

#[naked]
extern "x86-interrupt" fn int0x80_handler(frame: InterruptStackFrame) {
    // The code that entered userspace stored addresses where execution should
    // continue when userspace exits.
    unsafe {
        naked_asm!(
            "cld",
            "swapgs",
            "mov byte ptr gs:[{VECTOR_OFFSET}], 0x80",
            "jmp {exception_entry}",
            VECTOR_OFFSET = const offset_of!(PerCpu, vector),
            exception_entry = sym exception_entry,
        );
    }
}

/// Signal EOI.
pub fn eoi() {
    unsafe {
        Msr::new(0x80b).write(0);
    }
}
