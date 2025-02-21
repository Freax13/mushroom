//! This module implements the address sanitizer interface.

use core::{arch::asm, ffi::c_void};

#[unsafe(export_name = "__asan_report_load_n")]
extern "C" fn report_load_n(addr: *const c_void, size: usize) -> ! {
    panic!("address sanitizer: invalid load of size {size} at {addr:p}");
}

macro_rules! report_load_impl {
    ($($size:expr),*) => {
        $(

            const _: () = {
                #[unsafe(export_name = concat!("__asan_report_load", $size))]
                extern "C" fn report_load(addr: *const c_void) -> ! {
                    report_load_n(addr, $size)
                }
            };
        )*
    };
}
report_load_impl!(1, 2, 4, 8, 16);

#[unsafe(export_name = "__asan_report_store_n")]
extern "C" fn report_store_n(addr: *const c_void, size: usize) -> ! {
    panic!("address sanitizer: invalid store of size {size} at {addr:p}");
}

macro_rules! report_store_impl {
    ($($size:expr),*) => {
        $(

            const _: () = {
                #[unsafe(export_name = concat!("__asan_report_store", $size))]
                extern "C" fn report_store(addr: *const c_void) -> ! {
                    report_store_n(addr, $size)
                }
            };
        )*
    };
}
report_store_impl!(1, 2, 4, 8, 16);

#[unsafe(no_mangle)]
extern "C" fn __asan_handle_no_return() {}

#[inline]
pub unsafe fn set_shadow_n(addr: *mut u8, size: usize, n: u8) {
    unsafe {
        asm! {
            "rep stosb",
            inout("rdi") addr => _,
            inout("rcx") size => _,
            in("al") n,
        }
    }
}

macro_rules! set_shadow_impl {
    ($($name:expr => $value:expr,)*) => {
        $(

            const _: () = {
                #[unsafe(export_name = concat!("__asan_set_shadow_", $name))]
                unsafe extern "C" fn set_shadow(addr: *mut u8, size: usize) {
                    unsafe {
                        set_shadow_n(addr, size, $value)
                    }
                }
            };
        )*
    };
}
set_shadow_impl! {
    "00" => 0x00,
    "01" => 0x01,
    "02" => 0x02,
    "03" => 0x03,
    "04" => 0x04,
    "05" => 0x05,
    "06" => 0x06,
    "07" => 0x07,
    "f1" => 0xf1,
    "f2" => 0xf2,
    "f3" => 0xf3,
    "f5" => 0xf5,
    "f8" => 0xf8,
}
