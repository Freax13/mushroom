use core::sync::atomic::{AtomicUsize, Ordering};

use constants::ApIndex;
use x86_64::instructions::hlt;

use crate::{
    exception::{eoi, pop_pending_event, send_ipi},
    per_cpu::PerCpu,
};

pub const STARTUP_VECTOR: u8 = 0x20;
pub const WAKE_UP_VECTOR: u8 = 0x21;

static READY: AtomicUsize = AtomicUsize::new(0);

pub fn start_next_ap() {
    let next = READY.fetch_add(1, Ordering::Relaxed) + 1;
    let Ok(next) = u8::try_from(next) else { return };
    let Some(ap_index) = ApIndex::try_new(next) else {
        return;
    };
    send_ipi(u32::from(ap_index.as_u8()), STARTUP_VECTOR);
}

/// Wait for the vCPU to be ready.
///
/// We start the vCPUs sequentially. The kernel will tell us when to start the
/// next vCPU.
pub fn wait_for_vcpu_start() {
    loop {
        let ready = READY.load(Ordering::Relaxed);
        if ready == usize::from(PerCpu::current_vcpu_index().as_u8()) {
            break;
        }

        hlt();

        while let Some(vector) = pop_pending_event() {
            match vector.get() {
                STARTUP_VECTOR => eoi(),
                WAKE_UP_VECTOR => eoi(),
                event => unimplemented!("unimplemented event {event}"),
            }
        }
    }
}
