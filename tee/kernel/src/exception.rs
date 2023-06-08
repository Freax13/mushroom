//! This module is responsible for handling CPU exceptions.

use core::{alloc::Layout, arch::asm, ptr::null_mut};

use alloc::alloc::alloc;
use log::{debug, error, trace};
use spin::Lazy;
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
    VirtAddr,
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

    Star::write(user_cs, user_ds, kernel_cs, kernel_ds).unwrap();

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
        idt
    });

    debug!("loading interrupt descriptor table");
    IDT.load();
}

extern "x86-interrupt" fn page_fault_handler(
    frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    let _guard = SwapGsGuard::new(&frame);

    let cr2 = Cr2::read_raw();

    trace!("page fault");

    if error_code.contains(PageFaultErrorCode::USER_MODE) {
        let per_cpu = PerCpu::get();
        let current_virtual_memory = per_cpu.current_virtual_memory.take();
        per_cpu
            .current_virtual_memory
            .set(current_virtual_memory.clone());

        debug!("rip={:?}", frame.instruction_pointer);

        let current_virtual_memory = current_virtual_memory.unwrap();
        unsafe {
            current_virtual_memory.handle_page_fault(cr2, error_code, frame.instruction_pointer);
        }
    } else {
        if let Ok(cr2) = VirtAddr::try_new(cr2) {
            if let Some(entry) = entry_for_page(Page::containing_address(cr2)) {
                error!("page is mapped to {entry:?}");
            } else {
                error!("page is not mapped");
            }
        } else {
            error!("cr2 is not a canonical address");
        }

        panic!(
            "page fault {error_code:?} trying to access {cr2:#018x} at ip {:#018x}",
            frame.instruction_pointer
        );
    }
}

extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, code: u64) -> ! {
    let _guard = SwapGsGuard::new(&frame);

    panic!("double fault {frame:x?} {code:x?}");
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
