use core::sync::atomic::{AtomicU64, Ordering};

use bit_field::BitField;
use constants::MAX_APS_COUNT;
use spin::mutex::SpinMutex;
use x86_64::structures::idt::InterruptStackFrame;

use crate::{
    exception::{eoi, send_ipi, FLUSH_VECTOR},
    per_cpu::PerCpu,
};

static GUARD: SpinMutex<()> = SpinMutex::new(());
static COUNTER: AtomicU64 = AtomicU64::new(0);
static RAN: AtomicU64 = AtomicU64::new(0);

/// This function must be called before entering the vCPU.
pub fn pre_enter() {
    RAN.fetch_or(1 << PerCpu::current_vcpu_index(), Ordering::SeqCst);
}

/// Flush the entire TLB on all vCPUs.
pub fn flush() {
    let _guard = GUARD.lock();
    let mask = RAN.swap(0, Ordering::Relaxed);
    COUNTER.fetch_or(mask, Ordering::Relaxed);
    drop(_guard);

    for i in 0..MAX_APS_COUNT {
        if mask.get_bit(usize::from(i)) {
            send_ipi(u32::from(i), FLUSH_VECTOR);
        }
    }

    while COUNTER.load(Ordering::SeqCst) != 0 {}
}

pub extern "x86-interrupt" fn flush_handler(_frame: InterruptStackFrame) {
    let vcpu_index = PerCpu::with(|per_cpu| {
        per_cpu.pending_flushes.set(true);
        per_cpu.vcpu_index
    });
    COUNTER.fetch_and(!(1 << vcpu_index), core::sync::atomic::Ordering::Relaxed);

    eoi();
}
