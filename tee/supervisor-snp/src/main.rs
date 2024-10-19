#![no_std]
#![no_main]
#![feature(
    core_intrinsics,
    naked_functions,
    pointer_is_aligned_to,
    sync_unsafe_cell
)]
#![allow(internal_features)]

use core::ops::Deref;

use log::{debug, info, LevelFilter};

use crate::{ap::start_next_ap, logging::SerialLogger};

mod ap;
mod dynamic;
mod ghcb;
mod input;
mod logging;
mod output;
mod pagetable;
mod panic;
mod reset_vector;
mod rmp;
mod services;

fn main() -> ! {
    if cfg!(not(feature = "harden")) {
        log::set_logger(&SerialLogger).unwrap();
        log::set_max_level(LevelFilter::Trace);
        debug!("initialized logger");
    }

    // Fetch the input data for the workload.
    input::verify_and_load();

    // Run the workload.
    info!("booting first AP");
    start_next_ap();
    services::run();
}

/// A wrapper type to make types `Sync`.
///
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
