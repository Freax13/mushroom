use core::{
    arch::asm,
    num::NonZeroU8,
    ptr::addr_of,
    sync::atomic::{AtomicU8, AtomicU16, Ordering},
};

use bit_field::BitField;
use constants::MAX_APS_COUNT;
use spin::Lazy;
use x86_64::{
    VirtAddr,
    registers::model_specific::Msr,
    structures::idt::{InterruptDescriptorTable, InterruptStackFrame},
};

use crate::{
    ghcb::{set_hv_doorbell_page, write_msr},
    pagetable::Synchronized,
    per_cpu::PerCpu,
    scheduler::TIMER_VECTOR,
    shared,
};

pub fn init() {
    IDT.load();

    // Register a #HV doorbell page.
    set_hv_doorbell_page(
        HV_DOORBELL_PAGES.frame() + u64::from(PerCpu::current_vcpu_index().as_u8()),
    );

    // Enter x2apic mode.
    write_msr(0x1b, 0xfee00d00).unwrap();

    // Enable the x2apic.
    write_msr(0x80f, 0x1ff).unwrap();

    // Enable APIC timer.
    const PERIODIC_TIMER_MODE: u64 = 1 << 17;
    // Initialize APIC Timer Local Vector Table Register.
    write_msr(0x832, u64::from(TIMER_VECTOR) | PERIODIC_TIMER_MODE).unwrap();
    // Initialize Divide Configuration Register. Divide by 1.
    write_msr(0x83e, 0b1011).unwrap();
    // Initialize Timer Initial Count Register.
    let tsc_frequency = unsafe { Msr::new(0xC001_0134).read() } * 1_000_000;
    let timer_hz = 100;
    write_msr(0x838, tsc_frequency / timer_hz).unwrap();
}

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    idt.hv_injection_exception.set_handler_fn(hv_handler);
    idt
});

extern "x86-interrupt" fn hv_handler(mut frame: InterruptStackFrame) {
    PerCpu::get().interrupted.store(true, Ordering::SeqCst);

    // There's some code that needs to run uninterrupted. If we see an #HV
    // exception, don't try to let the code finish, but jump directly to the
    // end.

    extern "C" {
        static __interruptable_start: [VirtAddr; 2];
        static __interruptable_end: [VirtAddr; 2];
    }
    let start = addr_of!(__interruptable_start);
    let end = addr_of!(__interruptable_end);
    let size = unsafe { end.sub_ptr(start) };
    let slice = unsafe { core::slice::from_raw_parts(start, size) };
    if let Some([_, end]) = slice
        .iter()
        .copied()
        .find(|[start, end]| (*start..*end).contains(&frame.instruction_pointer))
    {
        unsafe {
            // Update the return address on the stack.
            frame
                .as_mut()
                .update(|frame| frame.instruction_pointer = end);

            // Update the return address on the shadow stack.
            asm!(
                "rdsspq {ssp}",
                "wrssq [{ssp} + 8], {new_rip}",
                new_rip = in(reg) end.as_u64(),
                ssp = out(reg) _,
                options(nostack, nomem),
            );
        }
    }
}

shared! {
    static HV_DOORBELL_PAGES: [HvDoorbellPage; MAX_APS_COUNT as usize] = [const {HvDoorbellPage::new()}; MAX_APS_COUNT as usize];
}

#[repr(C, align(4096))]
pub struct HvDoorbellPage {
    pending_event: AtomicU16,
    no_eoi_required: AtomicU8,
    padding: [AtomicU8; 4093],
}

impl HvDoorbellPage {
    pub const fn new() -> Self {
        HvDoorbellPage {
            pending_event: AtomicU16::new(0),
            no_eoi_required: AtomicU8::new(0),
            padding: [const { AtomicU8::new(0) }; 4093],
        }
    }
}

unsafe impl Synchronized for HvDoorbellPage {}

pub fn pop_pending_event() -> Option<NonZeroU8> {
    let hv_doorbell_page = &HV_DOORBELL_PAGES[PerCpu::current_vcpu_index()];
    let pending_event = hv_doorbell_page.pending_event.swap(0, Ordering::SeqCst);
    let vector = pending_event.get_bits(0..=7) as u8;
    NonZeroU8::new(vector)
}

pub fn eoi() {
    let hv_doorbell_page = &HV_DOORBELL_PAGES[PerCpu::current_vcpu_index()];

    let no_eoi_required = hv_doorbell_page.no_eoi_required.swap(0, Ordering::SeqCst);
    if no_eoi_required == 0 {
        write_msr(0x80b, 0).unwrap();
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
    write_msr(0x830, bits).unwrap();
}
