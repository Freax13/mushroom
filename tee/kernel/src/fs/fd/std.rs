use alloc::{format, sync::Arc};
use log::debug;

use super::{Events, FileLock, OpenFileDescription, pipe::anon::PIPE_FS};
use crate::{
    error::Result,
    fs::{
        FileSystem,
        node::{FileAccessContext, new_ino},
        ownership::Ownership,
        path::Path,
    },
    spin::mutex::Mutex,
    user::process::{
        syscall::args::{FileMode, FileType, FileTypeAndMode, OpenFlags, Stat, Timespec},
        thread::{Gid, Uid},
    },
};

pub struct Stdin {
    ino: u64,
    internal: Mutex<StdinInternal>,
    file_lock: FileLock,
}

struct StdinInternal {
    ownership: Ownership,
}

impl Stdin {
    pub fn new(uid: Uid, gid: Gid) -> Self {
        Self {
            ino: new_ino(),
            internal: Mutex::new(StdinInternal {
                ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
            }),
            file_lock: FileLock::anonymous(),
        }
    }
}

impl OpenFileDescription for Stdin {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn path(&self) -> Result<Path> {
        Path::new(format!("pipe:[{}]", self.ino).into_bytes())
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Fifo, guard.ownership.mode()),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(PIPE_FS.clone())
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & Events::empty()
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

pub struct Stdout {
    ino: u64,
    internal: Mutex<StdoutInternal>,
    file_lock: FileLock,
}

struct StdoutInternal {
    ownership: Ownership,
}

impl Stdout {
    pub fn new(uid: Uid, gid: Gid) -> Self {
        Self {
            ino: new_ino(),
            internal: Mutex::new(StdoutInternal {
                ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
            }),
            file_lock: FileLock::anonymous(),
        }
    }
}

impl OpenFileDescription for Stdout {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn path(&self) -> Result<Path> {
        Path::new(format!("pipe:[{}]", self.ino).into_bytes())
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let chunk = core::str::from_utf8(buf);
        debug!("{chunk:02x?}");
        Ok(buf.len())
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Fifo, guard.ownership.mode()),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(PIPE_FS.clone())
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & Events::WRITE
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

pub struct Stderr {
    ino: u64,
    internal: Mutex<StderrInternal>,
    file_lock: FileLock,
}

struct StderrInternal {
    ownership: Ownership,
}

impl Stderr {
    pub fn new(uid: Uid, gid: Gid) -> Self {
        Self {
            ino: new_ino(),
            internal: Mutex::new(StderrInternal {
                ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
            }),
            file_lock: FileLock::anonymous(),
        }
    }
}

impl OpenFileDescription for Stderr {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn path(&self) -> Result<Path> {
        Path::new(format!("pipe:[{}]", self.ino).into_bytes())
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let chunk = core::str::from_utf8(buf);
        debug!("{chunk:02x?}");
        Ok(buf.len())
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Fifo, guard.ownership.mode()),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(PIPE_FS.clone())
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & Events::WRITE
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}
