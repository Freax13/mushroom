#![no_std]
#![no_main]
#![feature(
    abi_x86_interrupt,
    asm_const,
    core_intrinsics,
    layout_for_ptr,
    naked_functions,
    pointer_is_aligned_to,
    sync_unsafe_cell
)]
#![allow(internal_features)]

use core::ops::Deref;

use log::{debug, LevelFilter};

use crate::{ap::run_aps, logging::SerialLogger};

mod ap;
mod cpuid;
mod doorbell;
mod dynamic;
mod exception;
mod ghcb;
mod input;
mod logging;
mod output;
mod pagetable;
mod panic;
mod reset_vector;
mod rmp;

fn main() -> ! {
    if cfg!(not(feature = "harden")) {
        log::set_logger(&SerialLogger).unwrap();
        log::set_max_level(LevelFilter::Trace);
        debug!("initialized logger");
    }

    // Setup an IDT and negotiate with the Hypervisor how interrupts are
    // signaled to us.
    exception::init();
    doorbell::init();

    // Fetch the input data for the workload.
    input::verify_and_load();

    // Run the workload.
    run_aps();
}

/// The supervisor runs singlethreaded, so we don't need statics to be `Sync`.
/// This type can wrap another type and make it `Sync`.
/// If we ever decide to run the supervisor with more than one thread, this
/// type needs to be removed in favor of either a mutex or a thread-local.
/// Note that we also don't have any exception handlers that could be
/// considered a second thread.
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
