use alloc::{boxed::Box, collections::VecDeque, format, sync::Arc, vec};
use core::cmp;

use async_trait::async_trait;
use futures::future;

use crate::{
    error::{Result, bail, ensure, err},
    fs::{
        FileSystem,
        fd::{
            BsdFileLock, Events, FileDescriptorTable, NonEmptyEvents, OpenFileDescription,
            OpenFileDescriptionData, ReadBuf, VectoredUserBuf, WriteBuf,
            epoll::{EpollReady, EpollRequest, EpollResult, EventCounter, WeakEpollReady},
        },
        node::{FileAccessContext, new_ino},
        ownership::Ownership,
        path::Path,
    },
    rt::notify::Notify,
    spin::mutex::Mutex,
    user::{
        memory::VirtualMemory,
        process::limits::CurrentNoFileLimit,
        syscall::{
            args::{
                FileMode, FileType, FileTypeAndMode, MsgHdr, OpenFlags, RecvFromFlags,
                SendMsgFlags, SentToFlags, SocketAddr, SocketAddrUnix, Stat, Timespec,
            },
            traits::Abi,
        },
        thread::{Gid, Uid},
    },
};

pub struct DgramUnixSocket {
    ino: u64,
    internal: Mutex<DgramUnixSocketInternal>,
    write_half: WriteHalf,
    read_half: ReadHalf,
    bsd_file_lock: BsdFileLock,
}

struct DgramUnixSocketInternal {
    flags: OpenFlags,
    ownership: Ownership,
}

impl DgramUnixSocket {
    pub fn new_pair(flags: OpenFlags, uid: Uid, gid: Gid) -> (Self, Self) {
        let buffer1 = Arc::new(Buffer::new());
        let buffer2 = Arc::new(Buffer::new());

        let read_half1 = ReadHalf {
            buffer: buffer1.clone(),
        };
        let read_half2 = ReadHalf {
            buffer: buffer2.clone(),
        };

        let write_half1 = WriteHalf { buffer: buffer2 };
        let write_half2 = WriteHalf { buffer: buffer1 };

        (
            Self {
                ino: new_ino(),
                internal: Mutex::new(DgramUnixSocketInternal {
                    flags,
                    ownership: Ownership::new(
                        FileMode::OWNER_READ | FileMode::OWNER_WRITE,
                        uid,
                        gid,
                    ),
                }),
                write_half: write_half1,
                read_half: read_half1,
                bsd_file_lock: BsdFileLock::anonymous(),
            },
            Self {
                ino: new_ino(),
                internal: Mutex::new(DgramUnixSocketInternal {
                    flags,
                    ownership: Ownership::new(
                        FileMode::OWNER_READ | FileMode::OWNER_WRITE,
                        uid,
                        gid,
                    ),
                }),
                write_half: write_half2,
                read_half: read_half2,
                bsd_file_lock: BsdFileLock::anonymous(),
            },
        )
    }

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        let data = self.read_half.read()?;
        let len = cmp::min(data.len(), buf.buffer_len());
        buf.write(0, &data[..len])?;
        Ok(len)
    }
}

#[async_trait]
impl OpenFileDescription for DgramUnixSocket {
    fn flags(&self) -> OpenFlags {
        self.internal.lock().flags
    }

    fn path(&self) -> Result<Path> {
        Path::new(format!("socket:[{}]", self.ino).into_bytes())
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.internal.lock().flags.update(flags);
    }

    fn set_non_blocking(&self, non_blocking: bool) {
        self.internal
            .lock()
            .flags
            .set(OpenFlags::NONBLOCK, non_blocking);
    }

    fn read(&self, buf: &mut dyn ReadBuf, _: &FileAccessContext) -> Result<usize> {
        self.read(buf)
    }

    fn recv_from(
        &self,
        buf: &mut dyn ReadBuf,
        flags: RecvFromFlags,
    ) -> Result<(usize, Option<SocketAddr>)> {
        if flags.contains(RecvFromFlags::PEEK) {
            todo!()
        }

        let len = self.read(buf)?;
        Ok((len, None))
    }

    fn recv_msg(
        &self,
        vm: &VirtualMemory,
        abi: Abi,
        msg_hdr: &mut MsgHdr,
        _: &FileDescriptorTable,
        _: CurrentNoFileLimit,
    ) -> Result<usize> {
        ensure!(msg_hdr.namelen == 0, IsConn);
        ensure!(msg_hdr.flags == 0, Inval);

        let mut vectored_buf = VectoredUserBuf::new(vm, msg_hdr.iov, msg_hdr.iovlen, abi)?;
        let len = self.read(&mut vectored_buf)?;

        msg_hdr.controllen = 0;

        Ok(len)
    }

    fn write(&self, buf: &dyn WriteBuf, _: &FileAccessContext) -> Result<usize> {
        let len = buf.buffer_len();
        let mut bytes = vec![0; len];
        buf.read(0, &mut bytes)?;
        self.write_half.write(Box::from(bytes));
        Ok(len)
    }

    fn send_to(
        &self,
        buf: &dyn WriteBuf,
        flags: SentToFlags,
        addr: Option<SocketAddr>,
        ctx: &FileAccessContext,
    ) -> Result<usize> {
        ensure!(addr.is_none(), IsConn);

        if flags != SentToFlags::empty() {
            todo!()
        }

        self.write(buf, ctx)
    }

    fn send_msg(
        &self,
        vm: &VirtualMemory,
        abi: Abi,
        msg_hdr: &mut MsgHdr,
        _: SendMsgFlags,
        _: &FileDescriptorTable,
        ctx: &FileAccessContext,
    ) -> Result<usize> {
        ensure!(msg_hdr.name.is_null(), IsConn);
        ensure!(msg_hdr.namelen == 0, IsConn);

        ensure!(msg_hdr.control.is_null(), IsConn);
        ensure!(msg_hdr.controllen == 0, IsConn);

        if msg_hdr.flags != 0 {
            todo!()
        }

        let vectored_buf = VectoredUserBuf::new(vm, msg_hdr.iov, msg_hdr.iovlen, abi)?;
        self.write(&vectored_buf, ctx)
    }

    fn poll_ready(&self, events: Events, _: &FileAccessContext) -> Option<NonEmptyEvents> {
        let mut ready_events = Events::empty();
        ready_events.set(
            Events::READ,
            !self.read_half.buffer.internal.lock().packets.is_empty(),
        );
        ready_events.set(Events::WRITE, true);
        NonEmptyEvents::new(ready_events & events)
    }

    async fn ready(&self, events: Events, ctx: &FileAccessContext) -> NonEmptyEvents {
        let mut read_wait = self.read_half.buffer.notify.wait();
        let mut write_wait = self.write_half.buffer.notify.wait();
        loop {
            let events = self.poll_ready(events, ctx);
            if let Some(events) = events {
                return events;
            }
            future::select(read_wait.next(), write_wait.next()).await;
        }
    }

    fn epoll_ready(
        self: Arc<OpenFileDescriptionData<Self>>,
        _: &FileAccessContext,
    ) -> Result<Box<dyn WeakEpollReady>> {
        Ok(Box::new(Arc::downgrade(&self)))
    }

    fn get_socket_name(&self) -> Result<SocketAddr> {
        Ok(SocketAddr::Unix(SocketAddrUnix::Unnamed))
    }

    fn get_peer_name(&self) -> Result<SocketAddr> {
        Ok(SocketAddr::Unix(SocketAddrUnix::Unnamed))
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

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
        Ok(&self.bsd_file_lock)
    }
}

#[async_trait]
impl EpollReady for DgramUnixSocket {
    async fn epoll_ready(&self, req: &EpollRequest) -> EpollResult {
        Notify::zip_epoll_loop(
            req,
            &self.read_half.buffer.notify,
            || {
                let mut result = EpollResult::new();
                let guard = self.read_half.buffer.internal.lock();
                if !guard.packets.is_empty() {
                    result.set_ready(Events::READ);
                }
                result.add_counter(Events::READ, &guard.read_counter);
                result
            },
            &self.write_half.buffer.notify,
            || {
                let mut result = EpollResult::new();
                let guard = self.write_half.buffer.internal.lock();
                result.set_ready(Events::WRITE);
                result.add_counter(Events::WRITE, &guard.write_counter);
                drop(guard);
                result
            },
        )
        .await
    }
}

struct Buffer {
    internal: Mutex<BufferInternal>,
    notify: Notify,
}

struct BufferInternal {
    packets: VecDeque<Box<[u8]>>,
    read_counter: EventCounter,
    write_counter: EventCounter,
}

impl Buffer {
    fn new() -> Self {
        Self {
            internal: Mutex::new(BufferInternal {
                packets: VecDeque::new(),
                read_counter: EventCounter::new(),
                write_counter: EventCounter::new(),
            }),
            notify: Notify::new(),
        }
    }
}

struct ReadHalf {
    buffer: Arc<Buffer>,
}

impl ReadHalf {
    fn read(&self) -> Result<Box<[u8]>> {
        let mut guard = self.buffer.internal.lock();
        let packet = guard.packets.pop_front().ok_or(err!(Again))?;
        guard.write_counter.inc();
        drop(guard);
        self.buffer.notify.notify();
        Ok(packet)
    }
}

struct WriteHalf {
    buffer: Arc<Buffer>,
}

impl WriteHalf {
    fn write(&self, data: Box<[u8]>) {
        let mut guard = self.buffer.internal.lock();
        guard.packets.push_back(data);
        guard.read_counter.inc();
        drop(guard);
        self.buffer.notify.notify();
    }
}
