#![no_std]
#![no_main]
#![feature(
    abi_x86_interrupt,
    asm_const,
    core_intrinsics,
    inline_const,
    naked_functions,
    lazy_cell
)]

use core::ops::Deref;

use constants::FIRST_AP;
use log::{debug, info, LevelFilter};
use serial_log::SerialLogger;
use x86_64::instructions::hlt;

use crate::{doorbell::DOORBELL, ghcb::eoi};

mod cpuid;
mod doorbell;
mod dynamic;
mod exception;
mod ghcb;
mod input;
mod pagetable;
mod panic;
mod reset_vector;
mod vcpu;

fn main() {
    exception::init();

    log::set_logger(&SerialLogger).unwrap();
    log::set_max_level(LevelFilter::Trace);
    debug!("initialized logger");

    doorbell::init();

    input::verify_input();

    {
        info!("booting first AP");
        let mut first_vcpu = vcpu::VCPUS[0].borrow_mut();
        first_vcpu.boot(FIRST_AP);
    }

    loop {
        let pending_event = DOORBELL.fetch_pending_event();
        if pending_event.is_empty() {
            hlt();
            continue;
        }

        assert!(!pending_event.nmi());
        assert!(!pending_event.mc());

        let vector = pending_event.vector().unwrap().get();
        let idx = usize::from(vector - FIRST_AP);
        {
            let mut vcpu = vcpu::VCPUS[idx].borrow_mut();
            vcpu.handle_vc();
        }

        if DOORBELL.requires_eoi() {
            eoi().unwrap();
        }
    }
}

/// The supervisor runs singlethreaded, so we don't need statics to be`Sync`.
/// This type can wrap another type and make it `Sync`.
/// If we ever decide to run the supervisor with more than one thread, this
/// type needs to be removed in favor of either a mutex or a thread-local.
// FIXME: exception can be considered a second thread. Is this safe?
pub struct FakeSync<T>(T);

impl<T> FakeSync<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for FakeSync<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

unsafe impl<T> Sync for FakeSync<T> {}
