//! This module is responsible for handling CPU exceptions.

use alloc::alloc::alloc;
use core::{
    alloc::Layout,
    arch::{asm, naked_asm},
    mem::offset_of,
    ptr::null_mut,
    sync::atomic::{AtomicU64, Ordering},
};

use constants::{TIMER_VECTOR, TLB_VECTOR};
use crossbeam_utils::atomic::AtomicCell;
use log::{debug, error, trace};
use x86_64::{
    PrivilegeLevel, VirtAddr,
    instructions::{
        interrupts::{self, without_interrupts},
        tables::load_tss,
    },
    registers::{
        control::{Cr2, Cr8, PriorityClass},
        model_specific::{Msr, Star},
        segmentation::{CS, DS, ES, SS, Segment},
    },
    structures::{
        gdt::{Descriptor, DescriptorFlags, GlobalDescriptorTable, SegmentSelector},
        idt::{ExceptionVector, InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode},
        paging::Page,
        tss::TaskStateSegment,
    },
};

use crate::{
    memory::pagetable::{entry_for_page, flush},
    per_cpu::{PerCpu, PerCpuSync},
    spin::lazy::Lazy,
    time,
    user::syscall::cpu_state::{exception_entry, interrupt_entry},
};

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
    let stack_layout = Layout::from_size_align(0x10_0000, 16).unwrap();
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
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt.general_protection_fault
            .set_handler_fn(general_protection_fault_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.simd_floating_point
            .set_handler_fn(simd_floating_point_handler);
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

#[unsafe(naked)]
extern "x86-interrupt" fn divide_error_handler(frame: InterruptStackFrame) {
    naked_asm!(
        "cld",
        // Check whether the exception happened in userspace.
        "test word ptr [rsp+8], 3",
        "je {kernel_divide_error_handler}",

        // Userspace code path:
        "swapgs",
        // Store the error code.
        "mov byte ptr gs:[{VECTOR_OFFSET}], {VECTOR}",
        // Jump to the userspace exit point.
        "jmp {exception_entry}",

        kernel_divide_error_handler = sym kernel_divide_error_handler,
        VECTOR_OFFSET = const offset_of!(PerCpu, vector),
        VECTOR = const ExceptionVector::Division as u8,
        exception_entry = sym exception_entry,
    );
}

extern "x86-interrupt" fn kernel_divide_error_handler(frame: InterruptStackFrame) {
    panic!("divide error {frame:x?}");
}

#[unsafe(naked)]
extern "x86-interrupt" fn page_fault_handler(
    frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    naked_asm!(
        "cld",
        // Check whether the exception happened in userspace.
        "test word ptr [rsp+16], 3",
        "je 66f",

        // Userspace code path:
        "swapgs",
        // Store the error code.
        "mov byte ptr gs:[{VECTOR_OFFSET}], {VECTOR}",
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
        VECTOR = const ExceptionVector::Page as u8,
        ERROR_CODE_OFFSET = const offset_of!(PerCpu, error_code),
        exception_entry = sym exception_entry,
    );
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

#[unsafe(naked)]
extern "x86-interrupt" fn general_protection_fault_handler(
    frame: InterruptStackFrame,
    error_code: u64,
) {
    naked_asm!(
        "cld",
        // Check whether the exception happened in userspace.
        "test word ptr [rsp+16], 3",
        "je {kernel_general_protection_fault_handler}",

        // Userspace code path:
        "swapgs",
        // Store the error code.
        "mov byte ptr gs:[{VECTOR_OFFSET}], {VECTOR}",
        "pop qword ptr gs:[{ERROR_CODE_OFFSET}]",
        // Jump to the userspace exit point.
        "jmp {exception_entry}",

        kernel_general_protection_fault_handler = sym kernel_general_protection_fault_handler,
        VECTOR_OFFSET = const offset_of!(PerCpu, vector),
        VECTOR = const ExceptionVector::GeneralProtection as u8,
        ERROR_CODE_OFFSET = const offset_of!(PerCpu, error_code),
        exception_entry = sym exception_entry,
    );
}

extern "x86-interrupt" fn kernel_general_protection_fault_handler(
    frame: InterruptStackFrame,
    code: u64,
) {
    panic!("general protection fault {frame:x?} {code:x?}");
}

#[unsafe(naked)]
extern "x86-interrupt" fn simd_floating_point_handler(frame: InterruptStackFrame) {
    naked_asm!(
        "cld",
        // Check whether the exception happened in userspace.
        "test word ptr [rsp+8], 3",
        "je {kernel_simd_floating_point_handler}",

        // Userspace code path:
        "swapgs",
        // Store the error code.
        "mov byte ptr gs:[{VECTOR_OFFSET}], {VECTOR}",
        // Jump to the userspace exit point.
        "jmp {exception_entry}",

        kernel_simd_floating_point_handler = sym kernel_simd_floating_point_handler,
        VECTOR_OFFSET = const offset_of!(PerCpu, vector),
        VECTOR = const ExceptionVector::SimdFloatingPoint as u8,
        exception_entry = sym exception_entry,
    );
}

extern "x86-interrupt" fn kernel_simd_floating_point_handler(frame: InterruptStackFrame) {
    panic!("simd floating point exception {frame:x?}");
}

#[unsafe(naked)]
extern "x86-interrupt" fn invalid_opcode_handler(frame: InterruptStackFrame) {
    naked_asm!(
        "cld",
        // Check whether the exception happened in userspace.
        "test word ptr [rsp+8], 3",
        "je {kernel_invalid_opcode_handler}",

        // Userspace code path:
        "swapgs",
        // Store the error code.
        "mov byte ptr gs:[{VECTOR_OFFSET}], {VECTOR}",
        // Jump to the userspace exit point.
        "jmp {exception_entry}",

        kernel_invalid_opcode_handler = sym kernel_invalid_opcode_handler,
        VECTOR_OFFSET = const offset_of!(PerCpu, vector),
        VECTOR = const ExceptionVector::InvalidOpcode as u8,
        exception_entry = sym exception_entry,
    );
}

extern "x86-interrupt" fn kernel_invalid_opcode_handler(frame: InterruptStackFrame) {
    panic!("invalid opcdode {frame:x?}");
}

extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, code: u64) -> ! {
    if frame.code_segment.rpl() == PrivilegeLevel::Ring3 {
        unsafe {
            asm!("swapgs", options(nostack, preserves_flags));
        }
    }

    panic!("double fault {frame:x?} {code:x?}");
}

#[unsafe(naked)]
extern "x86-interrupt" fn tlb_shootdown_handler(frame: InterruptStackFrame) {
    naked_asm!(
        "cld",

        // swap gs if the irq happened in userspace.
        "test word ptr [rsp+8], 3",
        "je 55f",
        "swapgs",
        "55:",

        // Save registers.
        "push rax",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",

        // Jump to the handler.
        "call {tlb_shootdown_handler}",

        // Restore registers.
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rax",

        // swap gs back if the irq happened in userspace.
        "test word ptr [rsp+8], 3",
        "je 66f",
        "swapgs",
        "66:",

        "iretq",

        tlb_shootdown_handler = sym flush::tlb_shootdown_handler,
    );
}

#[unsafe(naked)]
extern "x86-interrupt" fn timer_handler(frame: InterruptStackFrame) {
    naked_asm!(
        "cld",
        // Check whether the irq happened in userspace.
        "test word ptr [rsp+8], 3",
        "je {kernel_timer_handler}",

        // Userspace code path:
        "swapgs",
        // Store the error code.
        "mov byte ptr gs:[{VECTOR_OFFSET}], {VECTOR}",
        // Jump to the userspace exit point.
        "jmp {interrupt_entry}",

        kernel_timer_handler = sym kernel_timer_handler,
        VECTOR_OFFSET = const offset_of!(PerCpu, vector),
        VECTOR = const TIMER_VECTOR,
        interrupt_entry = sym interrupt_entry,
    );
}

extern "x86-interrupt" fn kernel_timer_handler(_: InterruptStackFrame) {
    debug_assert!(!interrupts::are_enabled());
    interrupts::enable();

    start_interrupt_handler(Interrupt::Timer, time::expire_timers);

    debug_assert!(interrupts::are_enabled());
    interrupts::disable();
}

#[unsafe(naked)]
extern "x86-interrupt" fn int0x80_handler(frame: InterruptStackFrame) {
    // The code that entered userspace stored addresses where execution should
    // continue when userspace exits.
    naked_asm!(
        "cld",
        "swapgs",
        "mov byte ptr gs:[{VECTOR_OFFSET}], 0x80",
        "jmp {exception_entry}",
        VECTOR_OFFSET = const offset_of!(PerCpu, vector),
        exception_entry = sym exception_entry,
    );
}

/// Signal EOI.
pub fn eoi() {
    unsafe {
        Msr::new(0x80b).write(0);
    }
}

const RAW_TIMER_PRIORITY_CLASS: u8 = TIMER_VECTOR >> 4;
const TIMER_PRIORITY_CLASS: PriorityClass = PriorityClass::new(RAW_TIMER_PRIORITY_CLASS).unwrap();

pub struct InterruptData {
    current_interrupt: AtomicCell<Option<Interrupt>>,
    #[expect(dead_code)]
    disable_all_interrupts_counter: AtomicU64,
    disable_timer_interrupt_counter: AtomicU64,
}

impl InterruptData {
    pub const fn new() -> Self {
        Self {
            current_interrupt: AtomicCell::new(None),
            disable_all_interrupts_counter: AtomicU64::new(0),
            disable_timer_interrupt_counter: AtomicU64::new(0),
        }
    }

    pub fn check_max_interrupt(&self, max: Option<Interrupt>) {
        if !cfg!(debug_assertions) {
            return;
        }

        let current = self.current_interrupt.load();
        match (current, max) {
            (None, _) => {}
            (Some(current), None) => {
                panic!(
                    "We shouldn't be in an interrupt handler, but we're currently executing the {current:?} interrupt handler"
                );
            }
            (Some(current), Some(max)) => {
                if current < max {
                    panic!(
                        "We shouldn't be in an interrupt handler with a priority higher than {max:?}, but we're currently executing the {current:?} interrupt handler"
                    );
                }
            }
        }
    }
}

pub fn start_interrupt_handler(interrupt: Interrupt, handler: impl FnOnce()) {
    let prev = PerCpuSync::get()
        .interrupt_data
        .current_interrupt
        .fetch_update(|current| {
            // Fail if the current interrupt has a higher or equal
            // priority.
            if current.is_some_and(|current| current <= interrupt) {
                return None;
            }

            Some(Some(interrupt))
        })
        .unwrap();

    handler();

    without_interrupts(|| {
        let prev = PerCpuSync::get()
            .interrupt_data
            .current_interrupt
            .swap(prev);

        debug_assert_eq!(prev, Some(interrupt));

        eoi();
    });
}

/// A list of interrupts ordered by their priority (highest priority first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Interrupt {
    TlbShootdown,
    Timer,
}

pub trait InterruptGuard {
    fn new() -> Self;
}

/// An interrupt guard that blocks out no interrupts. This can't be used from an interrupt.
pub struct NoInterruptGuard {}

impl InterruptGuard for NoInterruptGuard {
    #[track_caller]
    fn new() -> Self {
        PerCpuSync::get().interrupt_data.check_max_interrupt(None);
        Self {}
    }
}

/// An interrupt guard that blocks out all interrupts.
#[expect(dead_code)]
pub struct DisableAllInterruptsGuard {}

impl InterruptGuard for DisableAllInterruptsGuard {
    fn new() -> Self {
        // Disable interrupts. This does nothing if interrupts are already
        // disabled.
        interrupts::disable();

        // Increase the counter.
        let interrupt_data = &PerCpuSync::get().interrupt_data;
        interrupt_data
            .disable_all_interrupts_counter
            .fetch_add(1, Ordering::Relaxed);

        Self {}
    }
}

impl Drop for DisableAllInterruptsGuard {
    fn drop(&mut self) {
        // Decrease the counter.
        let interrupt_data = &PerCpuSync::get().interrupt_data;
        let prev = interrupt_data
            .disable_all_interrupts_counter
            .fetch_sub(1, Ordering::Relaxed);

        // Enable interrupts if the counter hit 0.
        if prev == 1 {
            interrupts::enable();
        }
    }
}

/// An interrupt guard that blocks out timer interrupts.
pub struct TimerInterruptGuard {}

impl InterruptGuard for TimerInterruptGuard {
    #[track_caller]
    fn new() -> Self {
        PerCpuSync::get()
            .interrupt_data
            .check_max_interrupt(Some(Interrupt::Timer));

        without_interrupts(|| {
            // Run without interrupts enabled to prevent a race condition
            // between the CR8 and counter updates.

            // Update the task priority if timer interrupts are currently allowed.
            let requires_update =
                Cr8::read().is_none_or(|pc| pc as u8 > (RAW_TIMER_PRIORITY_CLASS));
            if requires_update {
                Cr8::write(Some(TIMER_PRIORITY_CLASS));
            }

            // Increase the counter.
            let interrupt_data = &PerCpuSync::get().interrupt_data;
            interrupt_data
                .disable_timer_interrupt_counter
                .fetch_add(1, Ordering::Relaxed);
        });
        Self {}
    }
}

impl Drop for TimerInterruptGuard {
    fn drop(&mut self) {
        without_interrupts(|| {
            // Run without interrupts enabled to prevent a race condition
            // between the CR8 and counter updates.

            // Decrease the counter.
            let interrupt_data = &PerCpuSync::get().interrupt_data;
            let prev = interrupt_data
                .disable_timer_interrupt_counter
                .fetch_sub(1, Ordering::Relaxed);

            // Unmask all external interupts if the counter hit zero. Note that
            // this assumes that we only use CR8 for timer interrupts.
            if prev == 1 {
                Cr8::write(None);
            }
        });
    }
}
