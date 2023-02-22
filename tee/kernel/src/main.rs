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

use exception::switch_stack;
use log::info;
use serial_log::SerialLogger;

use crate::per_cpu::PerCpu;

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
    info!("Hello from AP {}", PerCpu::get().idx);

    unsafe {
        // SAFETY: We're the only ones calling these functions and we're only
        // called once.
        exception::init();
    }

    fs::init().expect("failed to load input files");

    user::process::start_init_process();
    user::run()
}
