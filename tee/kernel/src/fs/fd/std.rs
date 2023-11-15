use log::debug;

use super::OpenFileDescription;
use crate::{
    error::Result,
    fs::node::new_ino,
    user::process::syscall::args::{
        FileMode, FileType, FileTypeAndMode, OpenFlags, Stat, Timespec,
    },
};

pub struct Stdin {
    ino: u64,
}

impl Stdin {
    pub fn new() -> Self {
        Self { ino: new_ino() }
    }
}

impl OpenFileDescription for Stdin {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn stat(&self) -> Stat {
        Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Fifo, FileMode::from_bits_truncate(0o600)),
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

pub struct Stdout {
    ino: u64,
}

impl Stdout {
    pub fn new() -> Self {
        Self { ino: new_ino() }
    }
}

impl OpenFileDescription for Stdout {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let chunk = core::str::from_utf8(buf);
        debug!("{chunk:02x?}");
        Ok(buf.len())
    }

    fn stat(&self) -> Stat {
        Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Fifo, FileMode::from_bits_truncate(0o600)),
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

pub struct Stderr {
    ino: u64,
}

impl Stderr {
    pub fn new() -> Self {
        Self { ino: new_ino() }
    }
}

impl OpenFileDescription for Stderr {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let chunk = core::str::from_utf8(buf);
        debug!("{chunk:02x?}");
        Ok(buf.len())
    }

    fn stat(&self) -> Stat {
        Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Fifo, FileMode::from_bits_truncate(0o600)),
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
