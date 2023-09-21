use alloc::boxed::Box;
use async_trait::async_trait;
use log::debug;

use super::{Events, OpenFileDescription};
use crate::{
    error::Result,
    fs::node::new_ino,
    user::process::syscall::args::{FileMode, FileType, FileTypeAndMode, Stat, Timespec},
};

pub struct UnixSocket {
    ino: u64,
}

impl UnixSocket {
    pub fn new_pair() -> (Self, Self) {
        (Self { ino: new_ino() }, Self { ino: new_ino() })
    }
}

#[async_trait]
impl OpenFileDescription for UnixSocket {
    fn read(&self, _buf: &mut [u8]) -> Result<usize> {
        todo!()
    }

    fn write(&self, _buf: &[u8]) -> Result<usize> {
        todo!()
    }

    fn poll_ready(&self, events: Events) -> Result<Events> {
        debug!("{events:?}");
        Ok(Events::empty())
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        debug!("{events:?}");
        core::future::pending().await
    }

    fn stat(&self) -> Stat {
        Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Socket, FileMode::from_bits_truncate(0o600)),
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        }
    }
}
