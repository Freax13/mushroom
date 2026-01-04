use std::ffi::CStr;

use bytemuck::{Pod, Zeroable};
use nix::sys::{
    personality::{self, Persona},
    utsname::uname as newuname,
};

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct OldUtsname {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
}

impl OldUtsname {
    pub fn sysname(&self) -> &CStr {
        CStr::from_bytes_until_nul(&self.sysname).unwrap()
    }

    pub fn machine(&self) -> &CStr {
        CStr::from_bytes_until_nul(&self.machine).unwrap()
    }
}

fn uname() -> OldUtsname {
    #[cfg(not(target_pointer_width = "32"))]
    {
        unimplemented!()
    }
    #[cfg(target_pointer_width = "32")]
    {
        use nix::libc::{self, syscall};
        let mut name = OldUtsname::zeroed();
        let res = unsafe { syscall(libc::SYS_olduname, &mut name) };
        assert_eq!(res, 0);
        name
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct OldOldUtsname {
    pub sysname: [u8; 9],
    pub nodename: [u8; 9],
    pub release: [u8; 9],
    pub version: [u8; 9],
    pub machine: [u8; 9],
}

impl OldOldUtsname {
    pub fn sysname(&self) -> &CStr {
        CStr::from_bytes_until_nul(&self.sysname).unwrap()
    }

    pub fn machine(&self) -> &CStr {
        CStr::from_bytes_until_nul(&self.machine).unwrap()
    }
}

fn olduname() -> OldOldUtsname {
    #[cfg(not(target_pointer_width = "32"))]
    {
        unimplemented!()
    }
    #[cfg(target_pointer_width = "32")]
    {
        use nix::libc::{self, syscall};
        let mut name = OldOldUtsname::zeroed();
        let res = unsafe { syscall(libc::SYS_oldolduname, &mut name) };
        assert_eq!(res, 0);
        name
    }
}

#[test]
fn newuname_default_personality() {
    let name = newuname().unwrap();
    assert_eq!(name.sysname(), "Linux");
    assert_eq!(name.machine(), "x86_64");
}
#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn uname_default_personality() {
    let name = uname();
    assert_eq!(name.sysname(), c"Linux");
    assert_eq!(name.machine(), c"x86_64");
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn olduname_default_personality() {
    let name = olduname();
    assert_eq!(name.sysname(), c"Linux");
    assert_eq!(name.machine(), c"x86_64");
}

const PER_LINUX32: Persona = Persona::from_bits_retain(8);

#[test]
fn newuname_linux32_personality() {
    personality::set(PER_LINUX32).unwrap();

    let name = newuname().unwrap();
    assert_eq!(name.sysname(), "Linux");
    assert_eq!(name.machine(), "i686");
}
#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn uname_linux32_personality() {
    personality::set(PER_LINUX32).unwrap();

    let name = uname();
    assert_eq!(name.sysname(), c"Linux");
    assert_eq!(name.machine(), c"i686");
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn olduname_linux32_personality() {
    personality::set(PER_LINUX32).unwrap();

    let name = olduname();
    assert_eq!(name.sysname(), c"Linux");
    assert_eq!(name.machine(), c"i686");
}
