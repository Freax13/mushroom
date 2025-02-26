use core::arch::asm;

use constants::physical_address::DYNAMIC;
use x86_64::structures::paging::PhysFrame;

/// We have a physical mapping of `DYNAMIC` at `0xffff_8080_0000_0000`. Using
/// this mapping is a lot faster than creating and destroying a temporary
/// mapping.
#[inline(always)]
fn get_fast_mapping(frame: PhysFrame) -> Option<*mut [u8; 4096]> {
    (DYNAMIC.start.start_address()..DYNAMIC.end.start_address())
        .contains(&frame.start_address())
        .then(|| {
            (frame.start_address().as_u64() - DYNAMIC.start.start_address().as_u64()
                + 0xffff_8080_0000_0000) as *mut _
        })
}

/// Copy bytes into a frame.
///
/// # Safety
///
/// Writing to the frame must be safe.
#[inline(always)]
pub unsafe fn copy_into_frame(frame: PhysFrame, bytes: &[u8; 0x1000]) {
    let dst = get_fast_mapping(frame).unwrap();
    unsafe { copy_into_page_direct(bytes, dst) };
}

#[inline(always)]
unsafe fn copy_into_page_direct(src: *const [u8; 4096], dst: *mut [u8; 4096]) {
    assert!(dst.is_aligned_to(32));

    if src.is_aligned_to(32) {
        unsafe {
            asm! {
                "66:",
                "vmovdqa ymm0, [{src}]",
                "vmovdqa [{dst}], ymm0",
                "add {src}, 32",
                "add {dst}, 32",
                "loop 66b",
                src = inout(reg) src => _,
                dst = inout(reg) dst => _,
                inout("ecx") 4096 / 32 => _,
                options(nostack),
            }
        }
    } else {
        unsafe {
            asm! {
                "66:",
                "vmovdqu ymm0, [{src}]",
                "vmovdqa [{dst}], ymm0",
                "add {src}, 32",
                "add {dst}, 32",
                "loop 66b",
                src = inout(reg) src => _,
                dst = inout(reg) dst => _,
                inout("ecx") 4096 / 32 => _,
                options(nostack),
            }
        }
    }
}

/// Fill a frame with zeros.
///
/// # Safety
///
/// Writing to the frame must be safe.
#[inline(always)]
pub unsafe fn zero_frame(frame: PhysFrame) {
    let dst = get_fast_mapping(frame).unwrap();
    unsafe { zero_page_direct(dst) };
}

#[inline(always)]
unsafe fn zero_page_direct(dst: *mut [u8; 4096]) {
    assert!(dst.is_aligned_to(32));

    unsafe {
        asm! {
            "vpxor ymm0, ymm0, ymm0",
            "66:",
            "vmovdqa [{dst}], ymm0",
            "add {dst}, 32",
            "loop 66b",
            dst = inout(reg) dst => _,
            inout("ecx") 4096 / 32 => _,
            options(nostack),
        }
    }
}
