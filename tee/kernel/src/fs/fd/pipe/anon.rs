use alloc::{boxed::Box, format, sync::Arc};

use async_trait::async_trait;

use crate::{
    error::{Result, bail},
    fs::{
        FileSystem, StatFs,
        fd::{
            BsdFileLock, Events, NonEmptyEvents, OpenFileDescription, OpenFileDescriptionData,
            ReadBuf, WriteBuf,
            epoll::{EpollReady, EpollRequest, EpollResult, WeakEpollReady},
            pipe::{CAPACITY, PIPE_BUF},
            stream_buffer,
        },
        node::{FileAccessContext, new_ino},
        ownership::Ownership,
        path::Path,
    },
    spin::{lazy::Lazy, mutex::Mutex},
    user::{
        syscall::args::{
            FileMode, FileType, FileTypeAndMode, OpenFlags, Pipe2Flags, Stat, Timespec,
        },
        thread::{Gid, Uid},
    },
};

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

fn path(ino: u64) -> Result<Path> {
    Path::new(format!("pipe:[{ino}]",).into_bytes())
}

struct Internal {
    ownership: Ownership,
}

pub struct ReadHalf {
    ino: u64,
    internal: Arc<Mutex<Internal>>,
    stream_buffer: stream_buffer::ReadHalf,
    flags: Mutex<OpenFlags>,
    bsd_file_lock: BsdFileLock,
}

#[async_trait]
impl OpenFileDescription for ReadHalf {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock()
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.flags.lock().update(flags);
        self.stream_buffer.notify().notify();
    }

    fn set_non_blocking(&self, non_blocking: bool) {
        self.flags.lock().set(OpenFlags::NONBLOCK, non_blocking);
        self.stream_buffer.notify().notify();
    }

    fn path(&self) -> Result<Path> {
        path(self.ino)
    }

    fn read(&self, buf: &mut dyn ReadBuf, _: &FileAccessContext) -> Result<usize> {
        self.stream_buffer.read(buf, false, false)
    }

    fn write(&self, _: &dyn WriteBuf, _: &FileAccessContext) -> Result<usize> {
        bail!(BadF)
    }

    fn poll_ready(&self, events: Events, _: &FileAccessContext) -> Option<NonEmptyEvents> {
        self.stream_buffer.poll_ready(events)
    }

    async fn ready(&self, events: Events, ctx: &FileAccessContext) -> NonEmptyEvents {
        self.stream_buffer
            .notify()
            .wait_until(|| self.poll_ready(events, ctx))
            .await
    }

    fn epoll_ready(
        self: Arc<OpenFileDescriptionData<Self>>,
        _: &FileAccessContext,
    ) -> Result<Box<dyn WeakEpollReady>> {
        Ok(Box::new(Arc::downgrade(&self)))
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
            blksize: 0x1000,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(PIPE_FS.clone())
    }

    fn as_pipe_read_half(&self) -> Option<&stream_buffer::ReadHalf> {
        Some(&self.stream_buffer)
    }

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
        Ok(&self.bsd_file_lock)
    }
}

#[async_trait]
impl EpollReady for ReadHalf {
    async fn epoll_ready(&self, req: &EpollRequest) -> EpollResult {
        self.stream_buffer
            .notify()
            .epoll_loop(req, || self.stream_buffer.epoll_ready())
            .await
    }
}

pub struct WriteHalf {
    ino: u64,
    internal: Arc<Mutex<Internal>>,
    stream_buffer: stream_buffer::WriteHalf,
    flags: Mutex<OpenFlags>,
    bsd_file_lock: BsdFileLock,
}

#[async_trait::async_trait]
impl OpenFileDescription for WriteHalf {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock() | OpenFlags::WRONLY
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.flags.lock().update(flags);
        self.stream_buffer.notify().notify();
    }

    fn set_non_blocking(&self, non_blocking: bool) {
        self.flags.lock().set(OpenFlags::NONBLOCK, non_blocking);
        self.stream_buffer.notify().notify();
    }

    fn path(&self) -> Result<Path> {
        path(self.ino)
    }

    fn read(&self, _: &mut dyn ReadBuf, _: &FileAccessContext) -> Result<usize> {
        bail!(BadF)
    }

    fn write(&self, buf: &dyn WriteBuf, _: &FileAccessContext) -> Result<usize> {
        self.stream_buffer.write(buf)
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
            blksize: 0x1000,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(PIPE_FS.clone())
    }

    fn as_pipe_write_half(&self) -> Option<&stream_buffer::WriteHalf> {
        Some(&self.stream_buffer)
    }

    fn poll_ready(&self, events: Events, _: &FileAccessContext) -> Option<NonEmptyEvents> {
        self.stream_buffer.poll_ready(events)
    }

    async fn ready(&self, events: Events, ctx: &FileAccessContext) -> NonEmptyEvents {
        self.stream_buffer
            .notify()
            .wait_until(|| self.poll_ready(events, ctx))
            .await
    }

    async fn ready_for_write(&self, count: usize, _: &FileAccessContext) {
        self.stream_buffer.ready_for_write(count).await
    }

    fn epoll_ready(
        self: Arc<OpenFileDescriptionData<Self>>,
        _: &FileAccessContext,
    ) -> Result<Box<dyn WeakEpollReady>> {
        Ok(Box::new(Arc::downgrade(&self)))
    }

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
        Ok(&self.bsd_file_lock)
    }
}

#[async_trait]
impl EpollReady for WriteHalf {
    async fn epoll_ready(&self, req: &EpollRequest) -> EpollResult {
        self.stream_buffer
            .notify()
            .epoll_loop(req, || self.stream_buffer.epoll_ready())
            .await
    }
}

pub fn new(flags: Pipe2Flags, uid: Uid, gid: Gid) -> (ReadHalf, WriteHalf) {
    let ino = new_ino();
    let internal = Arc::new(Mutex::new(Internal {
        ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
    }));
    let (read_half, write_half) = stream_buffer::new(
        CAPACITY,
        stream_buffer::Type::Pipe {
            atomic_write_size: PIPE_BUF,
        },
    );
    let flags = flags.into();

    (
        ReadHalf {
            ino,
            internal: internal.clone(),
            stream_buffer: read_half,
            flags: Mutex::new(flags),
            bsd_file_lock: BsdFileLock::anonymous(),
        },
        WriteHalf {
            ino,
            internal,
            stream_buffer: write_half,
            flags: Mutex::new(flags | OpenFlags::WRONLY),
            bsd_file_lock: BsdFileLock::anonymous(),
        },
    )
}
