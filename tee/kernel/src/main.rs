#![no_std]
#![no_main]
#![feature(
    abi_x86_interrupt,
    alloc_error_handler,
    allocator_api,
    asm_const,
    btree_cursors,
    cfg_sanitize,
    const_mut_refs,
    core_intrinsics,
    drain_keep_rest,
    extract_if,
    generic_const_exprs,
    int_roundings,
    linked_list_cursors,
    maybe_uninit_array_assume_init,
    maybe_uninit_uninit_array,
    naked_functions,
    new_uninit,
    no_sanitize,
    noop_waker,
    pointer_is_aligned_to,
    ptr_metadata,
    return_type_notation,
    slice_ptr_get,
    step_trait,
    sync_unsafe_cell,
    trait_upcasting,
    try_trait_v2
)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(incomplete_features, internal_features)]

#[cfg(all(feature = "harden", feature = "profiling"))]
compiler_error!("Hardened kernels can't be profiled.");

extern crate alloc;

use exception::switch_stack;
use supervisor::launch_next_ap;

use crate::per_cpu::PerCpu;

mod char_dev;
mod error;
mod exception;
mod fs;
mod host;
mod limited_index;
mod logging;
mod memory;
mod panic;
mod per_cpu;
#[cfg(feature = "profiling")]
mod profiler;
mod reset_vector;
mod rt;
#[cfg(sanitize = "address")]
mod sanitize;
mod spin;
mod supervisor;
mod time;
mod user;

/// # Safety
///
/// This function must only be called once.
unsafe fn main() -> ! {
    if cfg!(not(feature = "harden")) {
        let _ = log::set_logger(&logging::FastLogger);
        log::set_max_level(log::LevelFilter::Trace);
    }

    PerCpu::init();

    #[cfg(feature = "profiling")]
    if PerCpu::get().idx == 0 {
        unsafe {
            crate::profiler::init();
        }
    }

    exception::load_early_gdt();
    exception::load_idt();

    switch_stack(init)
}

extern "C" fn init() -> ! {
    unsafe {
        // SAFETY: We're the only ones calling these functions and we're only
        // called once.
        exception::init();
    }

    // The first AP does some extra initialization work.
    if PerCpu::get().idx == 0 {
        user::process::start_init_process();
    }

    launch_next_ap();

    user::run()
}
