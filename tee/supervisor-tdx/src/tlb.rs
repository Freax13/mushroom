use constants::AtomicApBitmap;
use spin::mutex::SpinMutex;
use x86_64::structures::idt::InterruptStackFrame;

use crate::{
    exception::{eoi, send_ipi, FLUSH_VECTOR},
    per_cpu::PerCpu,
};

static GUARD: SpinMutex<()> = SpinMutex::new(());
static COUNTER: AtomicApBitmap = AtomicApBitmap::empty();
static RAN: AtomicApBitmap = AtomicApBitmap::empty();

/// This function must be called before entering the vCPU.
pub fn pre_enter() {
    RAN.set(PerCpu::current_vcpu_index());
}

/// Flush the entire TLB on all vCPUs.
pub fn flush() {
    let _guard = GUARD.lock();
    let mask = RAN.take_all();
    COUNTER.set_all(mask);
    drop(_guard);

    for idx in mask {
        send_ipi(u32::from(idx.as_u8()), FLUSH_VECTOR);
    }

    while !COUNTER.get_all().is_empty() {}
}

pub extern "x86-interrupt" fn flush_handler(_frame: InterruptStackFrame) {
    let vcpu_index = PerCpu::with(|per_cpu| {
        per_cpu.pending_flushes.set(true);
        per_cpu.vcpu_index
    });
    COUNTER.take(vcpu_index);

    eoi();
}
