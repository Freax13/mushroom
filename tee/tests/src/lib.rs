#![cfg(test)]
#![feature(asm_const)]

use std::arch::asm;

use libc::{SYS_exit, SYS_vfork};

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
