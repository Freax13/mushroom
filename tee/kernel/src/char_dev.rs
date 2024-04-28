use linkme::distributed_slice;

use crate::{
    error::{err, Result},
    fs::fd::{FileDescriptor, OpenFileDescription},
    user::process::syscall::args::{OpenFlags, Stat},
};

pub mod mem;
pub mod mushroom;

pub trait CharDev: OpenFileDescription + Sized {
    const MAJOR: u16;
    const MINOR: u8;

    fn new(flags: OpenFlags, stat: Stat) -> Result<Self>;
}

pub fn open(flags: OpenFlags, stat: Stat) -> Result<FileDescriptor> {
    let registration = REGISTRATIONS
        .iter()
        .find(|r| u64::from(r.rdev) == stat.rdev)
        .ok_or(err!(NoDev))?;
    (registration.new)(flags, stat)
}

#[distributed_slice]
pub static REGISTRATIONS: [Registration];

pub struct Registration {
    rdev: u32,
    new: fn(flags: OpenFlags, stat: Stat) -> Result<FileDescriptor>,
}

impl Registration {
    pub const fn new<T>() -> Self
    where
        T: CharDev,
    {
        if T::MAJOR > 0xfff {
            panic!("major number is too big");
        }
        let rdev = (T::MAJOR as u32) << 8 | T::MINOR as u32;
        Self {
            rdev,
            new: |flags, stat| T::new(flags, stat).map(FileDescriptor::from),
        }
    }
}
