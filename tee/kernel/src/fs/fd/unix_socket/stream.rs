use alloc::{boxed::Box, format, sync::Arc};
use async_trait::async_trait;
use futures::{FutureExt, select_biased};

use super::super::{Events, FileLock, OpenFileDescription};
use crate::{
    error::{Result, bail, ensure},
    fs::{
        FileSystem,
        fd::{
            PipeBlocked,
            stream_buffer::{self, SpliceBlockedError},
        },
        node::{FileAccessContext, new_ino},
        ownership::Ownership,
        path::Path,
    },
    spin::mutex::Mutex,
    user::process::{
        memory::VirtualMemory,
        syscall::args::{
            FileMode, FileType, FileTypeAndMode, OpenFlags, Pointer, RecvFromFlags, SentToFlags,
            SocketAddr, Stat, Timespec,
        },
        thread::{Gid, Uid},
    },
};

const CAPACITY: usize = 262144;

pub struct StreamUnixSocket {
    ino: u64,
    internal: Mutex<StreamUnixSocketInternal>,
    write_half: stream_buffer::WriteHalf,
    read_half: stream_buffer::ReadHalf,
    file_lock: FileLock,
}

struct StreamUnixSocketInternal {
    flags: OpenFlags,
    ownership: Ownership,
}

impl StreamUnixSocket {
    pub fn new_pair(flags: OpenFlags, uid: Uid, gid: Gid) -> (Self, Self) {
        let (read_half1, write_half1) = stream_buffer::new(CAPACITY, stream_buffer::Type::Socket);
        let (read_half2, write_half2) = stream_buffer::new(CAPACITY, stream_buffer::Type::Socket);
        (
            Self {
                ino: new_ino(),
                internal: Mutex::new(StreamUnixSocketInternal {
                    flags,
                    ownership: Ownership::new(
                        FileMode::OWNER_READ | FileMode::OWNER_WRITE,
                        uid,
                        gid,
                    ),
                }),
                write_half: write_half1,
                read_half: read_half2,
                file_lock: FileLock::anonymous(),
            },
            Self {
                ino: new_ino(),
                internal: Mutex::new(StreamUnixSocketInternal {
                    flags,
                    ownership: Ownership::new(
                        FileMode::OWNER_READ | FileMode::OWNER_WRITE,
                        uid,
                        gid,
                    ),
                }),
                write_half: write_half2,
                read_half: read_half1,
                file_lock: FileLock::anonymous(),
            },
        )
    }
}

#[async_trait]
impl OpenFileDescription for StreamUnixSocket {
    fn flags(&self) -> OpenFlags {
        self.internal.lock().flags
    }

    fn path(&self) -> Result<Path> {
        Path::new(format!("socket:[{}]", self.ino).into_bytes())
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.internal.lock().flags = flags;
    }

    fn set_non_blocking(&self, non_blocking: bool) {
        self.internal
            .lock()
            .flags
            .set(OpenFlags::NONBLOCK, non_blocking);
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.read_half.read(buf)
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        self.read_half.read_to_user(vm, pointer, len)
    }

    fn recv_from(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
        _flags: RecvFromFlags,
    ) -> Result<usize> {
        self.read_half.read_to_user(vm, pointer, len)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.write_half.write(buf)
    }

    fn write_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        self.write_half.write_from_user(vm, pointer, len)
    }

    fn send_to(
        &self,
        vm: &VirtualMemory,
        buf: Pointer<[u8]>,
        len: usize,
        _: SentToFlags,
        addr: Pointer<SocketAddr>,
        _addrlen: usize,
    ) -> Result<usize> {
        ensure!(addr.is_null(), IsConn);
        self.write_half.write_from_user(vm, buf, len)
    }

    fn splice_from(
        &self,
        read_half: &stream_buffer::ReadHalf,
        offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        ensure!(offset.is_none(), Inval);
        match stream_buffer::splice(read_half, &self.write_half, len) {
            Ok(len) => Ok(Ok(len)),
            Err(SpliceBlockedError::Read) => Ok(Err(PipeBlocked)),
            Err(SpliceBlockedError::Write) => bail!(Again),
        }
    }

    fn splice_to(
        &self,
        write_half: &stream_buffer::WriteHalf,
        offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        ensure!(offset.is_none(), Inval);
        match stream_buffer::splice(&self.read_half, write_half, len) {
            Ok(len) => Ok(Ok(len)),
            Err(SpliceBlockedError::Read) => bail!(Again),
            Err(SpliceBlockedError::Write) => Ok(Err(PipeBlocked)),
        }
    }

    fn poll_ready(&self, events: Events) -> Events {
        self.write_half.poll_ready(events) | self.read_half.poll_ready(events)
    }

    fn epoll_ready(&self, events: Events) -> Result<Events> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        loop {
            let write_wait = self.write_half.wait();
            let read_wait = self.read_half.wait();

            let events = self.write_half.poll_ready(events) | self.read_half.poll_ready(events);
            if !events.is_empty() {
                return Ok(events);
            }

            select_biased! {
                _ = write_wait.fuse() => {}
                _ = read_wait.fuse() => {}
            }
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
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Socket, guard.ownership.mode()),
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
        bail!(BadF)
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

impl Drop for StreamUnixSocket {
    fn drop(&mut self) {
        self.read_half.shutdown();
        self.write_half.shutdown();
    }
}
