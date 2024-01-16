//! This module is responsible for handling CPU exceptions.

use core::mem::offset_of;
use core::{alloc::Layout, arch::asm, ptr::null_mut};

use crate::spin::lazy::Lazy;
use alloc::alloc::alloc;
use log::{debug, error, trace};
use x86_64::{
    instructions::tables::load_tss,
    registers::{
        control::Cr2,
        model_specific::Star,
        segmentation::{Segment, CS, DS, ES, GS, SS},
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

/// Load a Global Descriptor Table. The old GDT setup by the reset vector is
/// no longer accessible.
pub fn load_gdt() {
    let per_cpu = PerCpu::get();

    let mut tss = TaskStateSegment::new();
    tss.privilege_stack_table[0] = allocate_stack();
    per_cpu.tss.set(tss).expect("TSS was already initialized");
    let tss = per_cpu.tss.get().unwrap();

    let mut gdt = GlobalDescriptorTable::new();
    let kernel_cs = gdt.add_entry(Descriptor::kernel_code_segment());
    let kernel_ds = gdt.add_entry(Descriptor::kernel_data_segment());
    let _user32_cs = gdt.add_entry(Descriptor::UserSegment(DescriptorFlags::USER_CODE32.bits()));
    let user_ds = gdt.add_entry(Descriptor::user_data_segment());
    let user_cs = gdt.add_entry(Descriptor::user_code_segment());
    let tss_seg = gdt.add_entry(Descriptor::tss_segment(tss));
    per_cpu.gdt.set(gdt).unwrap();
    let gdt = per_cpu.gdt.get().unwrap();

    debug!("loading global descriptor table");
    gdt.load();

    debug!("loading tss");
    unsafe {
        load_tss(tss_seg);
    }

    unsafe {
        // Safety: kernel_cs points to a 64 bit code segment.
        CS::set_reg(kernel_cs);
    }
    unsafe {
        // Safety: kernel_ds points to a data segment.
        SS::set_reg(kernel_ds);
        DS::set_reg(kernel_ds);
        ES::set_reg(kernel_ds);
    }

    // Initialize the segment selectors in `Star` msr for `syscall`/`sysret`.
    Star::write(user_cs, user_ds, kernel_cs, kernel_ds).unwrap();
}

/// Load an IDT.
pub fn load_idt() {
    static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
        let mut idt = InterruptDescriptorTable::new();
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.double_fault.set_handler_fn(double_fault_handler);
        idt[0x80]
            .set_handler_fn(int0x80_handler)
            .set_privilege_level(PrivilegeLevel::Ring3);
        idt
    });

    debug!("loading interrupt descriptor table");
    IDT.load();
}

#[naked]
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
) {
    page_fault_handler_impl(frame, error_code);
}

fn page_fault_handler_impl(frame: InterruptStackFrame, error_code: PageFaultErrorCode) {
    let _guard = SwapGsGuard::new(&frame);

    let cr2 = Cr2::read_raw();

    trace!("page fault");

    assert!(error_code.contains(PageFaultErrorCode::USER_MODE));

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

#[no_sanitize(address)]
extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, code: u64) -> ! {
    let _guard = SwapGsGuard::new(&frame);

    panic!("double fault {frame:x?} {code:x?}");
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

struct SwapGsGuard(());

impl SwapGsGuard {
    fn new(frame: &InterruptStackFrame) -> Option<Self> {
        if frame.code_segment & 3 == 0 {
            return None;
        }

        unsafe {
            GS::swap();
        }

        Some(Self(()))
    }
}

impl Drop for SwapGsGuard {
    fn drop(&mut self) {
        unsafe {
            GS::swap();
        }
    }
}
