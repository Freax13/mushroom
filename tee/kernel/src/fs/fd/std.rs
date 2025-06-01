use core::future::pending;

use alloc::{boxed::Box, format, sync::Arc, vec};
use async_trait::async_trait;
use log::debug;

use super::{
    Events, FileLock, NonEmptyEvents, OpenFileDescription, ReadBuf, WriteBuf, pipe::anon::PIPE_FS,
};
use crate::{
    error::{Result, ensure},
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

#[async_trait]
impl OpenFileDescription for Stdin {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn path(&self) -> Result<Path> {
        Path::new(format!("pipe:[{}]", self.ino).into_bytes())
    }

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        ensure!(buf.buffer_len() == 0, Inval);
        Ok(0)
    }

    fn pread(&self, _pos: usize, buf: &mut dyn ReadBuf) -> Result<usize> {
        ensure!(buf.buffer_len() == 0, Inval);
        Ok(0)
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

    fn poll_ready(&self, _events: Events) -> Option<NonEmptyEvents> {
        None
    }

    async fn ready(&self, _events: Events) -> NonEmptyEvents {
        pending().await
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

#[async_trait]
impl OpenFileDescription for Stdout {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn path(&self) -> Result<Path> {
        Path::new(format!("pipe:[{}]", self.ino).into_bytes())
    }

    fn write(&self, buf: &dyn WriteBuf) -> Result<usize> {
        let mut raw = vec![0; buf.buffer_len()];
        buf.read(0, &mut raw)?;
        let chunk = core::str::from_utf8(&raw);
        if let Ok(chunk) = chunk {
            for line in chunk.lines() {
                debug!("{line}");
            }
        } else {
            debug!("{chunk:02x?}");
        }
        Ok(raw.len())
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

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        NonEmptyEvents::new(events & Events::WRITE)
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        if let Some(events) = self.poll_ready(events) {
            events
        } else {
            pending().await
        }
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

#[async_trait]
impl OpenFileDescription for Stderr {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn path(&self) -> Result<Path> {
        Path::new(format!("pipe:[{}]", self.ino).into_bytes())
    }

    fn write(&self, buf: &dyn WriteBuf) -> Result<usize> {
        let mut raw = vec![0; buf.buffer_len()];
        buf.read(0, &mut raw)?;
        let chunk = core::str::from_utf8(&raw);
        if let Ok(chunk) = chunk {
            for line in chunk.lines() {
                debug!("{line}");
            }
        } else {
            debug!("{chunk:02x?}");
        }
        Ok(raw.len())
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

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        NonEmptyEvents::new(events & Events::WRITE)
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        if let Some(events) = self.poll_ready(events) {
            events
        } else {
            pending().await
        }
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}
