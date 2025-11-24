#![no_std]
#![no_main]
#![feature(
    abi_x86_interrupt,
    alloc_error_handler,
    allocator_api,
    arbitrary_self_types,
    btree_cursors,
    cfg_sanitize,
    core_intrinsics,
    drain_keep_rest,
    generic_const_exprs,
    int_roundings,
    ip_as_octets,
    linked_list_cursors,
    maybe_uninit_array_assume_init,
    maybe_uninit_as_bytes,
    maybe_uninit_slice,
    maybe_uninit_uninit_array_transpose,
    pointer_is_aligned_to,
    ptr_metadata,
    slice_ptr_get,
    step_trait,
    sync_unsafe_cell,
    try_trait_v2,
    vec_split_at_spare
)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(incomplete_features, internal_features)]

#[cfg(all(feature = "harden", feature = "profiling"))]
compiler_error!("Hardened kernels can't be profiled.");

extern crate alloc;

use x86_64::instructions::interrupts;

use self::{exception::switch_stack, memory::pagetable::flush, per_cpu::PerCpu, user::SCHEDULER};

mod char_dev;
mod error;
mod exception;
mod fs;
mod limited_index;
mod logging;
mod memory;
mod net;
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
    flush::init();

    #[cfg(feature = "profiling")]
    if PerCpu::get().idx.is_first() {
        unsafe {
            crate::profiler::init();
        }
    }

    exception::load_early_gdt();
    exception::load_idt();
    interrupts::enable();

    switch_stack(init)
}

extern "C" fn init() -> ! {
    exception::load_gdt();

    // The first AP does some extra initialization work.
    if PerCpu::get().idx.is_first() {
        user::process::start_init_process();
    }

    SCHEDULER.finish_launch();

    user::run()
}
