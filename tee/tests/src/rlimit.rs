#[cfg(target_pointer_width = "32")]
use libc::SYS_ugetrlimit;
use nix::libc::{self, RLIMIT_AS, c_long, syscall};

#[cfg(not(target_pointer_width = "32"))]
#[expect(non_upper_case_globals)]
const SYS_ugetrlimit: c_long = !0;

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn getrlimit() {
    #[repr(C)]
    struct Rlimit {
        current: u32,
        max: u32,
    }

    #[repr(C)]
    struct PaddedRlimit {
        value: Rlimit,
        padding: u64,
    }

    const MAGIC: u64 = 0x1122334455667788;
    const INVALID: u32 = 0x44332211;
    let mut value = PaddedRlimit {
        value: Rlimit {
            current: INVALID,
            max: INVALID,
        },
        padding: MAGIC,
    };

    let res = unsafe { syscall(SYS_ugetrlimit, RLIMIT_AS, &mut value) };
    assert_eq!(res, 0);
    assert_eq!(value.padding, MAGIC);
    assert_eq!(value.value.current, 0xffff_ffff);
    assert_eq!(value.value.max, 0xffff_ffff);
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn old_getrlimit() {
    #[repr(C)]
    struct OldRlimit {
        current: u32,
        max: u32,
    }

    #[repr(C)]
    struct PaddedOldRlimit {
        value: OldRlimit,
        padding: u64,
    }

    const MAGIC: u64 = 0x1122334455667788;
    const INVALID: u32 = 0x44332211;
    let mut value = PaddedOldRlimit {
        value: OldRlimit {
            current: INVALID,
            max: INVALID,
        },
        padding: MAGIC,
    };

    let res = unsafe { syscall(libc::SYS_getrlimit, RLIMIT_AS, &mut value) };
    assert_eq!(res, 0);
    assert_eq!(value.padding, MAGIC);
    assert_eq!(value.value.current, 0x7fff_ffff);
    assert_eq!(value.value.max, 0x7fff_ffff);
}
