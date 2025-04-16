use alloc::sync::Arc;
use linkme::distributed_slice;

use crate::{
    error::{Result, ensure, err},
    fs::{
        FileSystem,
        fd::StrongFileDescriptor,
        node::{FileAccessContext, LinkLocation},
    },
    user::process::syscall::args::{OpenFlags, Stat},
};

pub mod mem;
pub mod mushroom;

pub trait CharDev {
    const MAJOR: u16;
    const MINOR: u8;

    #[allow(clippy::new_ret_no_self)]
    fn new(
        location: LinkLocation,
        flags: OpenFlags,
        stat: Stat,
        fs: Arc<dyn FileSystem>,
        ctx: &FileAccessContext,
    ) -> Result<StrongFileDescriptor>;
}

pub fn open(
    location: LinkLocation,
    flags: OpenFlags,
    stat: Stat,
    fs: Arc<dyn FileSystem>,
    ctx: &FileAccessContext,
) -> Result<StrongFileDescriptor> {
    ensure!(!flags.contains(OpenFlags::DIRECTORY), IsDir);
    let registration = REGISTRATIONS
        .iter()
        .find(|r| u64::from(r.rdev) == stat.rdev)
        .ok_or(err!(NoDev))?;
    (registration.new)(location, flags, stat, fs, ctx)
}

#[distributed_slice]
pub static REGISTRATIONS: [Registration];

pub struct Registration {
    rdev: u32,
    #[expect(clippy::type_complexity)]
    new: fn(
        location: LinkLocation,
        flags: OpenFlags,
        stat: Stat,
        fs: Arc<dyn FileSystem>,
        ctx: &FileAccessContext,
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
            new: |location, flags, stat, fs, ctx| T::new(location, flags, stat, fs, ctx),
        }
    }
}
