use alloc::{boxed::Box, collections::VecDeque, format, sync::Arc, vec};
use core::cmp;

use async_trait::async_trait;
use futures::future;
use usize_conversions::usize_from;

use crate::{
    error::{Result, bail, ensure},
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
    rt::notify::{Notify, NotifyOnDrop},
    spin::mutex::Mutex,
    user::{
        memory::VirtualMemory,
        syscall::{
            args::{
                FileMode, FileType, FileTypeAndMode, MsgHdr, OpenFlags, RecvFromFlags,
                SendMsgFlags, SentToFlags, SocketAddr, Stat, Timespec,
            },
            traits::Abi,
        },
        thread::{Gid, Uid},
    },
};

pub struct SeqPacketUnixSocket {
    ino: u64,
    internal: Mutex<SeqPacketUnixSocketInternal>,
    write_half: WriteHalf,
    read_half: ReadHalf,
    bsd_file_lock: BsdFileLock,
}

struct SeqPacketUnixSocketInternal {
    flags: OpenFlags,
    ownership: Ownership,
}

impl SeqPacketUnixSocket {
    pub fn new_pair(flags: OpenFlags, uid: Uid, gid: Gid) -> (Self, Self) {
        let flags = flags | OpenFlags::RDWR;

        let state1 = Arc::new(Mutex::new(State::new()));
        let state2 = Arc::new(Mutex::new(State::new()));

        let notify1 = Arc::new(Notify::new());
        let notify2 = Arc::new(Notify::new());

        let read_half1 = ReadHalf {
            state: state1.clone(),
            notify: NotifyOnDrop(notify1.clone()),
        };
        let read_half2 = ReadHalf {
            state: state2.clone(),
            notify: NotifyOnDrop(notify2.clone()),
        };

        let write_half1 = WriteHalf {
            state: state2,
            notify: NotifyOnDrop(notify2),
        };
        let write_half2 = WriteHalf {
            state: state1,
            notify: NotifyOnDrop(notify1),
        };

        (
            Self {
                ino: new_ino(),
                internal: Mutex::new(SeqPacketUnixSocketInternal {
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
                internal: Mutex::new(SeqPacketUnixSocketInternal {
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

    fn read(&self, buf: &mut dyn ReadBuf, peek: bool) -> Result<usize> {
        let Some(data) = self.read_half.read(peek)? else {
            return Ok(0);
        };
        let len = cmp::min(data.len(), buf.buffer_len());
        buf.write(0, &data[..len])?;
        Ok(len)
    }
}

#[async_trait]
impl OpenFileDescription for SeqPacketUnixSocket {
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
        self.read(buf, false)
    }

    fn recv_from(
        &self,
        buf: &mut dyn ReadBuf,
        flags: RecvFromFlags,
    ) -> Result<(usize, Option<SocketAddr>)> {
        if flags.contains(RecvFromFlags::WAITALL) {
            todo!()
        }

        let peek = flags.contains(RecvFromFlags::PEEK);
        let len = self.read(buf, peek)?;
        Ok((len, None))
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
        flags: SendMsgFlags,
        _: &FileDescriptorTable,
        ctx: &FileAccessContext,
    ) -> Result<usize> {
        if flags != SendMsgFlags::empty() {
            todo!()
        }
        if msg_hdr.controllen != 0 {
            todo!()
        }
        if msg_hdr.flags != 0 {
            todo!();
        }

        let addr = if msg_hdr.namelen != 0 {
            Some(SocketAddr::read(
                msg_hdr.name,
                usize_from(msg_hdr.namelen),
                vm,
            )?)
        } else {
            None
        };

        let vectored_buf = VectoredUserBuf::new(vm, msg_hdr.iov, msg_hdr.iovlen, abi)?;
        self.send_to(&vectored_buf, SentToFlags::empty(), addr, ctx)
    }

    fn poll_ready(&self, events: Events, _: &FileAccessContext) -> Option<NonEmptyEvents> {
        let mut ready_events = Events::empty();
        ready_events.set(
            Events::READ,
            !self.read_half.state.lock().packets.is_empty()
                || Arc::strong_count(&self.read_half.state) == 1,
        );
        ready_events.set(Events::WRITE, true);
        ready_events.set(Events::HUP, Arc::strong_count(&self.read_half.state) == 1);
        NonEmptyEvents::new(ready_events & events)
    }

    async fn ready(&self, events: Events, ctx: &FileAccessContext) -> NonEmptyEvents {
        let mut read_wait = self.read_half.notify.wait();
        let mut write_wait = self.write_half.notify.wait();
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
impl EpollReady for SeqPacketUnixSocket {
    async fn epoll_ready(&self, req: &EpollRequest) -> EpollResult {
        Notify::zip_epoll_loop(
            req,
            &self.read_half.notify,
            || {
                let mut result = EpollResult::new();
                let guard = self.read_half.state.lock();
                if !guard.packets.is_empty() || Arc::strong_count(&self.read_half.state) == 1 {
                    result.set_ready(Events::READ);
                }
                if Arc::strong_count(&self.read_half.state) == 1 {
                    result.set_ready(Events::HUP);
                }
                result.add_counter(Events::READ, &guard.read_counter);
                result
            },
            &self.write_half.notify,
            || {
                let mut result = EpollResult::new();
                let guard = self.write_half.state.lock();
                result.set_ready(Events::WRITE);
                result.add_counter(Events::WRITE, &guard.write_counter);
                result
            },
        )
        .await
    }
}

struct State {
    packets: VecDeque<Box<[u8]>>,
    read_counter: EventCounter,
    write_counter: EventCounter,
}

impl State {
    fn new() -> Self {
        Self {
            packets: VecDeque::new(),
            read_counter: EventCounter::new(),
            write_counter: EventCounter::new(),
        }
    }
}

struct ReadHalf {
    state: Arc<Mutex<State>>,
    notify: NotifyOnDrop,
}

impl ReadHalf {
    fn read(&self, peek: bool) -> Result<Option<Box<[u8]>>> {
        let mut guard = self.state.lock();
        let packet = if peek {
            guard.packets.front().cloned()
        } else {
            guard.packets.pop_front()
        };
        if let Some(packet) = packet {
            guard.write_counter.inc();
            self.notify.notify();
            return Ok(Some(packet));
        }
        drop(guard);

        if Arc::strong_count(&self.state) == 1 {
            return Ok(None);
        }

        bail!(Again)
    }
}

struct WriteHalf {
    state: Arc<Mutex<State>>,
    notify: NotifyOnDrop,
}

impl WriteHalf {
    fn write(&self, data: Box<[u8]>) {
        let mut guard = self.state.lock();
        guard.packets.push_back(data);
        guard.read_counter.inc();
        drop(guard);
        self.notify.notify();
    }
}
