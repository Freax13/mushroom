use std::{
    ffi::c_long,
    sync::{Arc, atomic::AtomicU32},
};

use nix::libc::syscall;

#[cfg(target_pointer_width = "32")]
const SYS_ARCH_PRCTL: c_long = 384;
#[cfg(target_pointer_width = "64")]
const SYS_ARCH_PRCTL: c_long = 158;

const ARCH_SET_GS: c_long = 0x1001;
const ARCH_SET_FS: c_long = 0x1002;
const ARCH_GET_FS: c_long = 0x1003;
const ARCH_GET_GS: c_long = 0x1004;

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn set_gs_on_32_bit() {
    let mut old_gs_base = 0u64;
    let res = unsafe { syscall(SYS_ARCH_PRCTL, ARCH_GET_GS, &mut old_gs_base) };
    assert_ne!(res, 0);

    let data = Arc::new(AtomicU32::new(1024));
    let res = unsafe { syscall(SYS_ARCH_PRCTL, ARCH_SET_GS, data.as_ptr()) };
    assert_ne!(res, 0);
}

#[test]
#[cfg_attr(not(target_pointer_width = "64"), ignore = "64-bit only")]
fn set_gs_on_64_bit() {
    let data = Arc::new(AtomicU32::new(1024));

    let mut old_gs_base = 0u64;
    let res = unsafe { syscall(SYS_ARCH_PRCTL, ARCH_GET_GS, &mut old_gs_base) };
    assert_eq!(res, 0);

    let res = unsafe { syscall(SYS_ARCH_PRCTL, ARCH_SET_GS, data.as_ptr()) };
    assert_eq!(res, 0);

    let value: u32;
    unsafe {
        core::arch::asm!("mov {:e}, gs:[0]", out(reg) value);
    }

    assert_eq!(value, 1024);

    let res = unsafe { syscall(SYS_ARCH_PRCTL, ARCH_SET_GS, old_gs_base) };
    assert_eq!(res, 0);
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn set_fs_on_32_bit() {
    let mut old_fs_base = 0u64;
    let res = unsafe { syscall(SYS_ARCH_PRCTL, ARCH_GET_FS, &mut old_fs_base) };
    assert_ne!(res, 0);

    let data = Arc::new(AtomicU32::new(1024));
    let res = unsafe { syscall(SYS_ARCH_PRCTL, ARCH_SET_FS, data.as_ptr()) };
    assert_ne!(res, 0);
}

#[test]
#[cfg_attr(not(target_pointer_width = "64"), ignore = "64-bit only")]
fn set_fs_on_64_bit() {
    let data = Arc::new(AtomicU32::new(1024));

    let mut old_fs_base = 0u64;
    let res = unsafe { syscall(SYS_ARCH_PRCTL, ARCH_GET_FS, &mut old_fs_base) };
    assert_eq!(res, 0);

    let res = unsafe { syscall(SYS_ARCH_PRCTL, ARCH_SET_FS, data.as_ptr()) };
    assert_eq!(res, 0);

    let value: u32;
    unsafe {
        core::arch::asm!("mov {:e}, fs:[0]", out(reg) value);
    }

    assert_eq!(value, 1024);

    let res = unsafe { syscall(SYS_ARCH_PRCTL, ARCH_SET_FS, old_fs_base) };
    assert_eq!(res, 0);
}
