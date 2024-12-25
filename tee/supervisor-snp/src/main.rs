#![no_std]
#![no_main]
#![feature(
    abi_x86_interrupt,
    core_intrinsics,
    lazy_get,
    naked_functions,
    pointer_is_aligned_to,
    ptr_sub_ptr,
    sync_unsafe_cell
)]
#![allow(internal_features)]

use log::{debug, LevelFilter};
use per_cpu::PerCpu;
use scheduler::wait_for_vcpu_start;

use crate::{ap::run_vcpu, logging::SerialLogger};

mod ap;
mod dynamic;
mod ghcb;
mod input;
mod logging;
mod output;
mod pagetable;
mod panic;
mod per_cpu;
mod reset_vector;
mod rmp;
mod scheduler;

mod exception;

fn main() -> ! {
    if cfg!(not(feature = "harden")) {
        let res = log::set_logger(&SerialLogger);
        if res.is_ok() {
            log::set_max_level(LevelFilter::Trace);
            debug!("initialized logger");
        }
    }

    exception::init();

    // Fetch the input data for the workload.
    if PerCpu::current_vcpu_index().is_first() {
        input::verify_and_load();
    }

    wait_for_vcpu_start();
    run_vcpu()
}
