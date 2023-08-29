#![no_std]
#![no_main]
#![feature(
    abi_x86_interrupt,
    alloc_error_handler,
    allocator_api,
    asm_const,
    async_fn_in_trait,
    cfg_sanitize,
    const_mut_refs,
    const_pointer_byte_offsets,
    core_intrinsics,
    drain_filter,
    drain_keep_rest,
    generic_const_exprs,
    inline_const,
    int_roundings,
    lazy_cell,
    linked_list_cursors,
    maybe_uninit_array_assume_init,
    maybe_uninit_uninit_array,
    naked_functions,
    no_sanitize,
    noop_waker,
    offset_of,
    pointer_byte_offsets,
    pointer_is_aligned,
    ptr_metadata,
    return_type_notation,
    slice_ptr_get,
    step_trait,
    trait_upcasting,
    try_trait_v2
)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(incomplete_features)]

extern crate alloc;

use exception::switch_stack;
use serial_log::SerialLogger;
use supervisor::launch_next_ap;

use crate::{per_cpu::PerCpu, user::process::memory::VirtualMemoryActivator};

mod error;
mod exception;
mod fs;
mod host;
mod memory;
mod panic;
mod per_cpu;
mod reset_vector;
mod rt;
#[cfg(sanitize = "address")]
mod sanitize;
mod supervisor;
mod time;
mod user;

/// # Safety
///
/// This function must only be called once.
unsafe fn main() -> ! {
    if cfg!(not(feature = "harden")) {
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
        user::process::start_init_process(&mut vm_activator);
    }

    launch_next_ap();

    user::run(&mut vm_activator)
}
