use crate::{
    fs::{
        node::{new_ino, FileAccessContext},
        ownership::Ownership,
        path::Path,
        FileSystem, StatFs,
    },
    spin::{lazy::Lazy, mutex::Mutex},
    user::process::{
        memory::VirtualMemory,
        syscall::args::{OpenFlags, Pipe2Flags, Pointer},
        thread::{Gid, Uid},
    },
};
use alloc::{boxed::Box, format, sync::Arc};
use async_trait::async_trait;

use super::{stream_buffer, Events, FileLock, OpenFileDescription};
use crate::{
    error::Result,
    user::process::syscall::args::{FileMode, FileType, FileTypeAndMode, Stat, Timespec},
};

const CAPACITY: usize = 0x10000;
const PIPE_BUF: usize = 0x1000;

pub static PIPE_FS: Lazy<Arc<PipeFs>> = Lazy::new(|| Arc::new(PipeFs));

pub struct PipeFs;

impl FileSystem for PipeFs {
    fn stat(&self) -> StatFs {
        StatFs {
            ty: 0x50495045,
            bsize: 0x1000,
            blocks: 0,
            bfree: 0,
            bavail: 0,
            files: 0,
            ffree: 0,
            fsid: [0, 0],
            namelen: 255,
            frsize: 0,
            flags: 0,
        }
    }
}

fn path(ino: u64) -> Path {
    Path::new(format!("pipe:[{ino}]",).into_bytes()).unwrap()
}

struct Internal {
    ownership: Ownership,
}

pub struct ReadHalf {
    ino: u64,
    internal: Arc<Mutex<Internal>>,
    stream_buffer: stream_buffer::ReadHalf<CAPACITY, PIPE_BUF>,
    flags: Mutex<OpenFlags>,
    file_lock: FileLock,
}

#[async_trait]
impl OpenFileDescription for ReadHalf {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock()
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.flags.lock().update(flags);
    }

    fn path(&self) -> Path {
        path(self.ino)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.stream_buffer.read(buf)
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        self.stream_buffer.read_to_user(vm, pointer, len)
    }

    fn poll_ready(&self, events: Events) -> Events {
        self.stream_buffer.poll_ready(events)
    }

    fn epoll_ready(&self, events: Events) -> Result<Events> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        loop {
            let wait = self.stream_buffer.wait();

            let events = self.epoll_ready(events)?;
            if !events.is_empty() {
                return Ok(events);
            }

            wait.await;
        }
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
            ino: 0,
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

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

pub struct WriteHalf {
    ino: u64,
    internal: Arc<Mutex<Internal>>,
    stream_buffer: stream_buffer::WriteHalf<CAPACITY, PIPE_BUF>,
    flags: Mutex<OpenFlags>,
    file_lock: FileLock,
}

#[async_trait::async_trait]
impl OpenFileDescription for WriteHalf {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock()
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.flags.lock().update(flags);
    }

    fn path(&self) -> Path {
        path(self.ino)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.stream_buffer.write(buf)
    }

    fn write_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        self.stream_buffer.write_from_user(vm, pointer, len)
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
            ino: 0,
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
        self.stream_buffer.poll_ready(events)
    }

    fn epoll_ready(&self, events: Events) -> Result<Events> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        loop {
            let wait = self.stream_buffer.wait();

            let events = self.epoll_ready(events)?;
            if !events.is_empty() {
                return Ok(events);
            }

            wait.await;
        }
    }

    async fn ready_for_write(&self, count: usize) -> Result<()> {
        self.stream_buffer.ready_for_write(count).await
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

pub fn new(flags: Pipe2Flags, uid: Uid, gid: Gid) -> (ReadHalf, WriteHalf) {
    let ino = new_ino();
    let internal = Arc::new(Mutex::new(Internal {
        ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
    }));
    let (read_half, write_half) = stream_buffer::new();
    let flags = flags.into();

    (
        ReadHalf {
            ino,
            internal: internal.clone(),
            stream_buffer: read_half,
            flags: Mutex::new(flags),
            file_lock: FileLock::anonymous(),
        },
        WriteHalf {
            ino,
            internal,
            stream_buffer: write_half,
            flags: Mutex::new(flags | OpenFlags::WRONLY),
            file_lock: FileLock::anonymous(),
        },
    )
}
