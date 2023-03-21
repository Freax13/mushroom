#![no_std]
#![no_main]
#![feature(
    abi_x86_interrupt,
    allocator_api,
    alloc_error_handler,
    asm_const,
    const_mut_refs,
    const_nonnull_new,
    const_option,
    const_pointer_byte_offsets,
    const_slice_from_raw_parts_mut,
    core_intrinsics,
    drain_filter,
    drain_keep_rest,
    inline_const,
    int_roundings,
    naked_functions,
    once_cell,
    pointer_byte_offsets,
    ptr_sub_ptr,
    step_trait,
    try_trait_v2
)]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use constants::{KICK_AP_PORT, MAX_APS_COUNT};
use exception::switch_stack;
use serial_log::SerialLogger;
use x86_64::instructions::port::PortWriteOnly;

use crate::{per_cpu::PerCpu, user::process::memory::VirtualMemoryActivator};

mod error;
mod exception;
mod fs;
mod host;
mod memory;
mod panic;
mod per_cpu;
mod reset_vector;
mod supervisor;
mod user;

/// # Safety
///
/// This function must only be called once.
unsafe fn main() -> ! {
    #[cfg(debug_assertions)]
    if cfg!(debug_assertions) {
        let _ = log::set_logger(&SerialLogger);
        log::set_max_level(log::LevelFilter::Trace);
    }

    PerCpu::init();

    switch_stack(init)
}

extern "C" fn init() -> ! {
    unsafe {
        // SAFETY: We're the only ones calling these functions and we're only
        // called once.
        exception::init();
    }

    let mut vm_activator = unsafe { VirtualMemoryActivator::new() };

    // The first AP does some extract initialization work.
    if PerCpu::get().idx == 0 {
        fs::init().expect("failed to load input files");
        user::process::start_init_process(&mut vm_activator);
    }

    launch_next_ap();

    user::run(&mut vm_activator)
}

fn launch_next_ap() {
    let idx = PerCpu::get().idx;

    // Check if there are more APs to start.
    let next_idx = idx + 1;
    if next_idx < usize::from(MAX_APS_COUNT) {
        let next_idx = u32::try_from(next_idx).unwrap();
        unsafe {
            PortWriteOnly::new(KICK_AP_PORT).write(next_idx);
        }
    }
}
