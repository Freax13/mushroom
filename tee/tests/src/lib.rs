#![cfg(test)]
#![feature(asm_const)]

use std::{
    arch::asm,
    ffi::c_void,
    mem::size_of,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

use nix::{
    libc::{siginfo_t, SYS_exit, SYS_vfork},
    sys::{
        mman::{mprotect, ProtFlags},
        signal::{sigaction, SaFlags, SigAction, SigSet},
    },
};

#[test]
fn it_works() {
    let result = 2 + 2;
    assert_eq!(result, 4);
}

#[test]
fn vfork_exit() {
    #[cfg(target_arch = "x86")]
    unsafe {
        asm!(
            "mov eax, {vfork}",
            "int 0x80",
            "test eax, eax",
            "jnz 66f",
            "xor ebx, ebx",
            "mov eax, {exit}",
            "int 0x80",
            "66:",
            vfork = const SYS_vfork,
            exit = const SYS_exit,
        );
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!(
            "mov rax, {vfork}",
            "syscall",
            "test rax, rax",
            "jnz 66f",
            "xor rdi, rdi",
            "mov rax, {exit}",
            "syscall",
            "66:",
            vfork = const SYS_vfork,
            exit = const SYS_exit,
        );
    }
}

#[test]
fn signal_handling() {
    // Some memory for us to mess with.
    #[repr(align(4096))]
    struct Memory {
        value: AtomicU8,
    }
    static SOME_MEMORY: Memory = Memory {
        value: AtomicU8::new(0),
    };

    /// Whether we handled a signal.
    static HANDLED: AtomicBool = AtomicBool::new(false);

    // Take away the write permisssions for SOME_MEMORY.
    unsafe {
        mprotect(
            NonNull::from(&SOME_MEMORY).cast(),
            size_of::<Memory>(),
            ProtFlags::PROT_READ,
        )
        .unwrap();
    }

    extern "C" fn handler(_: i32, _: *mut siginfo_t, _: *mut c_void) {
        // Restore the write permissions.
        unsafe {
            mprotect(
                NonNull::from(&SOME_MEMORY).cast(),
                size_of::<Memory>(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
            .unwrap();
        }

        // Store that we handled a signal.
        HANDLED.store(true, Ordering::SeqCst);
    }
    // Register the signal handler.
    unsafe {
        sigaction(
            nix::sys::signal::Signal::SIGSEGV,
            &SigAction::new(
                nix::sys::signal::SigHandler::SigAction(handler),
                SaFlags::empty(),
                SigSet::empty(),
            ),
        )
        .unwrap();
    }

    assert!(!HANDLED.load(Ordering::SeqCst));

    // Write to SOME_MEMORY to trigger a segfault.
    SOME_MEMORY.value.fetch_add(1, Ordering::SeqCst);

    assert!(HANDLED.load(Ordering::SeqCst));
}
