#![no_std]
#![no_main]
#![feature(
    abi_x86_interrupt,
    asm_const,
    core_intrinsics,
    inline_const,
    layout_for_ptr,
    naked_functions,
    lazy_cell
)]

use core::ops::Deref;

use log::{debug, LevelFilter};
use serial_log::SerialLogger;
use x86_64::instructions::hlt;

use crate::{output::finish, vcpu::run_aps};

mod cpuid;
mod doorbell;
mod dynamic;
mod exception;
mod ghcb;
mod input;
mod output;
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

    run_aps();

    finish();

    loop {
        hlt();
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
