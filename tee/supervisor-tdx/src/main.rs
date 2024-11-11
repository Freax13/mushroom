#![no_std]
#![no_main]
#![feature(abi_x86_interrupt, core_intrinsics, naked_functions, sync_unsafe_cell)]
#![allow(internal_features)]

use exception::setup_idt;
use log::{debug, LevelFilter};
use per_cpu::PerCpu;
use spin::Once;
use vcpu::{init_vcpu, run_vcpu, wait_for_vcpu_start};
use x86_64::registers::model_specific::Msr;

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

    const IA32_TSC_AUX: u32 = 0xC000_0103;
    unsafe {
        Msr::new(IA32_TSC_AUX).write(PerCpu::current_vcpu_index().as_u8() as u64);
    }

    setup_idt();

    if PerCpu::current_vcpu_index().is_first() {
        input::init();
    }

    init_vcpu();
    wait_for_vcpu_start();
    run_vcpu()
}
