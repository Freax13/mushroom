#![no_std]
#![no_main]
#![feature(abi_x86_interrupt, const_mut_refs, core_intrinsics, sync_unsafe_cell)]
#![allow(internal_features)]

use exception::setup_idt;
use log::{debug, LevelFilter};
use per_cpu::PerCpu;
use spin::Once;
use tdx_types::tdcall::Apic;
use vcpu::{init_vcpu, run_vcpu, wait_for_vcpu_start};

use crate::logging::SerialLogger;

mod dynamic;
mod exception;
mod input;
mod logging;
mod output;
mod pagetable;
mod panic;
mod per_cpu;
mod reset_vector;
mod services;
mod tdcall;
mod tlb;
mod vcpu;

fn main() -> ! {
    if cfg!(not(feature = "harden")) {
        static SETUP_LOGGER: Once = Once::new();
        SETUP_LOGGER.call_once(|| {
            log::set_logger(&SerialLogger).unwrap();
            log::set_max_level(LevelFilter::Trace);
            debug!("initialized logger");
        });
    }

    setup_idt();

    if PerCpu::current_vcpu_index() == 0 {
        input::init();
    }

    let mut apic = Apic::default();
    unsafe { init_vcpu(&mut apic) };
    wait_for_vcpu_start();
    run_vcpu()
}
