use alloc::sync::Arc;
use linkme::distributed_slice;

use crate::{
    error::{Result, ensure, err},
    fs::{
        FileSystem,
        fd::{OpenFileDescription, StrongFileDescriptor},
        path::Path,
    },
    user::process::syscall::args::{OpenFlags, Stat},
};

pub mod mem;
pub mod mushroom;

pub trait CharDev: OpenFileDescription + Sized {
    const MAJOR: u16;
    const MINOR: u8;

    fn new(path: Path, flags: OpenFlags, stat: Stat, fs: Arc<dyn FileSystem>) -> Result<Self>;
}

pub fn open(
    path: Path,
    flags: OpenFlags,
    stat: Stat,
    fs: Arc<dyn FileSystem>,
) -> Result<StrongFileDescriptor> {
    ensure!(!flags.contains(OpenFlags::DIRECTORY), IsDir);
    let registration = REGISTRATIONS
        .iter()
        .find(|r| u64::from(r.rdev) == stat.rdev)
        .ok_or(err!(NoDev))?;
    (registration.new)(path, flags, stat, fs)
}

#[distributed_slice]
pub static REGISTRATIONS: [Registration];

pub struct Registration {
    rdev: u32,
    new: fn(
        path: Path,
        flags: OpenFlags,
        stat: Stat,
        fs: Arc<dyn FileSystem>,
    ) -> Result<StrongFileDescriptor>,
}

impl Registration {
    pub const fn new<T>() -> Self
    where
        T: CharDev,
    {
        if T::MAJOR > 0xfff {
            panic!("major number is too big");
        }
        let rdev = ((T::MAJOR as u32) << 8) | T::MINOR as u32;
        Self {
            rdev,
            new: |path, flags, stat, fs| {
                T::new(path, flags, stat, fs).map(StrongFileDescriptor::from)
            },
        }
    }
}
