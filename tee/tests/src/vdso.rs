use nix::libc::{AT_SYSINFO_EHDR, c_ulong, getauxval};

const AT_SYSINFO: c_ulong = AT_SYSINFO_EHDR - 1;

#[test]
fn magic() {
    let ehdr = unsafe { getauxval(AT_SYSINFO_EHDR) };
    assert_ne!(ehdr, 0);

    let magic_ptr = ehdr as *const [u8; 4];
    let header = unsafe { magic_ptr.read() };
    assert_eq!(header, *b"\x7fELF");
}

#[test]
fn sysinfo() {
    let ehdr = unsafe { getauxval(AT_SYSINFO) };
    if cfg!(target_pointer_width = "32") {
        assert_ne!(ehdr, 0);
    } else {
        assert_eq!(ehdr, 0);
    }
}
