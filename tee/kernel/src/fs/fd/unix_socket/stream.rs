use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::{
        btree_map::{BTreeMap, Entry},
        vec_deque::VecDeque,
    },
    format,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{cmp, ffi::c_void};

use async_trait::async_trait;
use bytemuck::bytes_of;
use usize_conversions::usize_from;
use x86_64::align_up;

use crate::{
    error::{Result, bail, ensure, err},
    fs::{
        FileSystem,
        fd::{
            BsdFileLock, Events, FdFlags, FileDescriptorTable, NonEmptyEvents, OpenFileDescription,
            OpenFileDescriptionData, PipeBlocked, ReadBuf, StrongFileDescriptor, VectoredUserBuf,
            WriteBuf,
            epoll::{EpollReady, EpollRequest, EpollResult, EventCounter, WeakEpollReady},
            socket_common_ioctl, stream_buffer,
        },
        node::{FileAccessContext, bind_socket, get_socket, new_ino},
        ownership::Ownership,
        path::Path,
    },
    net::CMsgBuilder,
    rt::notify::{Notify, NotifyOnDrop},
    spin::{
        mutex::{Mutex, MutexGuard},
        once::Once,
    },
    user::{
        memory::VirtualMemory,
        process::limits::CurrentNoFileLimit,
        syscall::{
            args::{
                Accept4Flags, FileMode, FileType, FileTypeAndMode, MsgHdr, OpenFlags, Pointer,
                RecvFromFlags, RecvMsgFlags, SendMsgFlags, SentToFlags, ShutdownHow, SocketAddr,
                SocketAddrUnix, SocketType, Stat, Timespec, Timeval, Ucred,
                pointee::{Timeval32, Timeval64},
            },
            traits::Abi,
        },
        thread::{Gid, ThreadGuard, Uid},
    },
};

const CAPACITY: usize = 262144;

static ABSTRACT_SOCKETS: Mutex<BTreeMap<Vec<u8>, Weak<OpenFileDescriptionData<StreamUnixSocket>>>> =
    Mutex::new(BTreeMap::new());

pub struct StreamUnixSocket {
    this: Weak<OpenFileDescriptionData<Self>>,
    ino: u64,
    internal: Mutex<StreamUnixSocketInternal>,
    socketname: Mutex<SocketAddrUnix>,
    activate_notify: Notify,
    mode: Once<Mode>,
    bsd_file_lock: BsdFileLock,
}

#[derive(Clone)]
struct StreamUnixSocketInternal {
    flags: OpenFlags,
    ownership: Ownership,
    receive_timeout: Timeval,
}

enum Mode {
    Active(Active),
    Passive(Passive),
}

impl StreamUnixSocket {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        flags: OpenFlags,
        uid: Uid,
        gid: Gid,
    ) -> (StrongFileDescriptor, Arc<OpenFileDescriptionData<Self>>) {
        StrongFileDescriptor::new_cyclic_with_data(|this| Self {
            this: this.clone(),
            ino: new_ino(),
            internal: Mutex::new(StreamUnixSocketInternal {
                flags,
                ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
                receive_timeout: Timeval::ZERO,
            }),
            socketname: Mutex::new(SocketAddrUnix::Unnamed),
            activate_notify: Notify::new(),
            mode: Once::new(),
            bsd_file_lock: BsdFileLock::anonymous(),
        })
    }

    pub fn new_pair(
        flags: OpenFlags,
        ctx: &FileAccessContext,
    ) -> (StrongFileDescriptor, StrongFileDescriptor) {
        let cred = Ucred::from(ctx);

        let (read_half1, write_half2) = LockedBuffer::new();
        let (read_half2, write_half1) = LockedBuffer::new();
        (
            StrongFileDescriptor::new_cyclic(|this| Self {
                this: this.clone(),
                ino: new_ino(),
                internal: Mutex::new(StreamUnixSocketInternal {
                    flags,
                    ownership: Ownership::new(
                        FileMode::OWNER_READ | FileMode::OWNER_WRITE,
                        ctx.filesystem_user_id(),
                        ctx.filesystem_group_id(),
                    ),
                    receive_timeout: Timeval::ZERO,
                }),
                socketname: Mutex::new(SocketAddrUnix::Unnamed),
                activate_notify: Notify::new(),
                mode: Once::with_value(Mode::Active(Active {
                    write_half: write_half1,
                    read_half: read_half1,
                    peername: SocketAddrUnix::Unnamed,
                    localcred: cred,
                    peercred: cred,
                })),
                bsd_file_lock: BsdFileLock::anonymous(),
            }),
            StrongFileDescriptor::new_cyclic(|this| Self {
                this: this.clone(),
                ino: new_ino(),
                internal: Mutex::new(StreamUnixSocketInternal {
                    flags,
                    ownership: Ownership::new(
                        FileMode::OWNER_READ | FileMode::OWNER_WRITE,
                        ctx.filesystem_user_id(),
                        ctx.filesystem_group_id(),
                    ),
                    receive_timeout: Timeval::ZERO,
                }),
                socketname: Mutex::new(SocketAddrUnix::Unnamed),
                activate_notify: Notify::new(),
                mode: Once::with_value(Mode::Active(Active {
                    write_half: write_half2,
                    read_half: read_half2,
                    peername: SocketAddrUnix::Unnamed,
                    localcred: cred,
                    peercred: cred,
                })),
                bsd_file_lock: BsdFileLock::anonymous(),
            }),
        )
    }

    pub fn bind(&self, socketname: SocketAddrUnix) -> Result<Weak<OpenFileDescriptionData<Self>>> {
        ensure!(!matches!(socketname, SocketAddrUnix::Unnamed), Inval);

        let mut guard = self.socketname.lock();
        // Make sure that the socket is not already bound.
        ensure!(matches!(*guard, SocketAddrUnix::Unnamed), Inval);
        *guard = socketname;
        drop(guard);

        Ok(self.this.clone())
    }
}

#[async_trait]
impl OpenFileDescription for StreamUnixSocket {
    fn flags(&self) -> OpenFlags {
        self.internal.lock().flags | OpenFlags::RDWR
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
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active
            .read_half
            .lock()
            .read(buf, false, false)
            .map(|(len, _ancillary_data)| len)
    }

    fn recv_from(
        &self,
        buf: &mut dyn ReadBuf,
        flags: RecvFromFlags,
    ) -> Result<(usize, Option<SocketAddr>)> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        let peek = flags.contains(RecvFromFlags::PEEK);
        let waitall = flags.contains(RecvFromFlags::WAITALL)
            && !flags.contains(RecvFromFlags::DONTWAIT)
            && !self.internal.lock().flags.contains(OpenFlags::NONBLOCK);
        active
            .read_half
            .lock()
            .read(buf, peek, waitall)
            .map(|(len, _ancillary_data)| (len, None))
    }

    fn recv_msg(
        &self,
        vm: &VirtualMemory,
        abi: Abi,
        msg_hdr: &mut MsgHdr,
        flags: RecvMsgFlags,
        fdtable: &FileDescriptorTable,
        no_file_limit: CurrentNoFileLimit,
    ) -> Result<usize> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };

        let mut vectored_buf = VectoredUserBuf::new(vm, msg_hdr.iov, msg_hdr.iovlen, abi)?;
        let waitall = flags.contains(RecvMsgFlags::WAITALL)
            && !flags.contains(RecvMsgFlags::DONTWAIT)
            && !self.internal.lock().flags.contains(OpenFlags::NONBLOCK);
        let peek = flags.contains(RecvMsgFlags::PEEK);
        let (len, ancillary_data) =
            active
                .read_half
                .lock()
                .read(&mut vectored_buf, peek, waitall)?;

        let mut cmsg_builder = CMsgBuilder::new(abi, vm, msg_hdr);
        if let Some(ancillary_data) = ancillary_data
            && let Some(fds) = ancillary_data.rights.filter(|fds| !fds.is_empty())
        {
            let mut fd_flags = FdFlags::empty();
            fd_flags.set(FdFlags::CLOEXEC, flags.contains(RecvMsgFlags::CMSG_CLOEXEC));
            cmsg_builder.add_fds(1, 1, fds, fd_flags, fdtable, no_file_limit)?;
        }
        drop(cmsg_builder);

        Ok(len)
    }

    fn write(&self, buf: &dyn WriteBuf, _: &FileAccessContext) -> Result<usize> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active.write_half.lock().write(buf, None)
    }

    fn send_to(
        &self,
        buf: &dyn WriteBuf,
        _: SentToFlags,
        addr: Option<SocketAddr>,
        _: &FileAccessContext,
    ) -> Result<usize> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        ensure!(addr.is_none(), IsConn);
        active.write_half.lock().write(buf, None)
    }

    fn send_msg(
        &self,
        vm: &VirtualMemory,
        abi: Abi,
        msg_hdr: &mut MsgHdr,
        _: SendMsgFlags,
        fdtable: &FileDescriptorTable,
        _: &FileAccessContext,
    ) -> Result<usize> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };

        let ancillary_data = if msg_hdr.controllen > 0 {
            let mut ancillary_data = AncillaryData::default();

            while msg_hdr.controllen > 0 {
                let (len, header) = vm.read_sized_with_abi(msg_hdr.control, abi)?;
                ensure!(msg_hdr.controllen >= header.len, Inval);
                let buffer_len = usize_from(header.len).checked_sub(len).ok_or(err!(Inval))?;

                match (header.level, header.r#type) {
                    (1, 1) => {
                        // SCM_RIGHTS
                        ensure!(buffer_len % 4 == 0, Inval);
                        let num_fds = buffer_len / 4;

                        ensure!(ancillary_data.rights.is_none(), Inval);

                        let fds = (0..num_fds)
                            .map(|i| {
                                let fd =
                                    vm.read(msg_hdr.control.bytes_offset(len).cast().add(i))?;
                                fdtable.get_strong(fd)
                            })
                            .collect::<Result<_>>()?;
                        ancillary_data.rights = Some(fds);
                    }
                    (1, 2) => {
                        // SCM_CREDENTIALS
                        ensure!(buffer_len >= size_of::<Ucred>(), Inval);

                        ensure!(ancillary_data.cred.is_none(), Inval);

                        let cred = vm.read(msg_hdr.control.bytes_offset(len).cast())?;
                        // TODO: Validate cred
                        ancillary_data.cred = Some(cred);
                    }
                    _ => bail!(Inval),
                }

                let align = match abi {
                    Abi::I386 => 4,
                    Abi::Amd64 => 8,
                };
                let offset = align_up(header.len, align);
                msg_hdr.control = msg_hdr.control.bytes_offset(usize_from(offset));
                msg_hdr.controllen = msg_hdr.controllen.saturating_sub(offset);
            }

            Some(ancillary_data)
        } else {
            None
        };

        let vectored_buf = VectoredUserBuf::new(vm, msg_hdr.iov, msg_hdr.iovlen, abi)?;
        active
            .write_half
            .lock()
            .write(&vectored_buf, ancillary_data)
    }

    fn splice_from(
        &self,
        read_half: &stream_buffer::ReadHalf,
        offset: Option<usize>,
        len: usize,
        _: &FileAccessContext,
    ) -> Result<Result<usize, PipeBlocked>> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        ensure!(offset.is_none(), Inval);
        active.read_half.lock().splice_from(read_half, len)
    }

    fn splice_to(
        &self,
        write_half: &stream_buffer::WriteHalf,
        offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        ensure!(offset.is_none(), Inval);
        active.read_half.lock().splice_to(write_half, len)
    }

    fn shutdown(&self, how: ShutdownHow) -> Result<()> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        match mode {
            Mode::Active(active) => match how {
                ShutdownHow::Rd => {
                    active.read_half.lock().shutdown();
                }
                ShutdownHow::Wr => {
                    active.write_half.lock().shutdown();
                }
                ShutdownHow::RdWr => {
                    active.read_half.lock().shutdown();
                    active.write_half.lock().shutdown();
                }
            },
            Mode::Passive(passive) => match how {
                ShutdownHow::Rd | ShutdownHow::RdWr => {
                    let mut guard = passive.internal.lock();
                    guard.shutdown = true;
                    guard.read_event_counter.inc();
                    drop(guard);
                    passive.connect_notify.notify();
                }
                ShutdownHow::Wr => {}
            },
        }
        Ok(())
    }

    fn bind(&self, addr: SocketAddr, ctx: &mut FileAccessContext) -> Result<()> {
        let SocketAddr::Unix(addr) = addr else {
            bail!(Inval);
        };

        match addr {
            SocketAddrUnix::Pathname(path) => {
                let guard = self.internal.lock();

                let cwd = ctx.process().unwrap().cwd();
                bind_socket(
                    cwd,
                    &path,
                    guard.ownership.mode(),
                    guard.ownership.uid(),
                    guard.ownership.gid(),
                    self,
                    ctx,
                )
            }
            SocketAddrUnix::Unnamed => {
                // Auto-bind. Pick a 5-hexdigit abstract name and bind it.

                const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";
                let mut candidates = HEX_DIGITS.iter().flat_map(|&a| {
                    HEX_DIGITS.iter().flat_map(move |&b| {
                        HEX_DIGITS.iter().flat_map(move |&c| {
                            HEX_DIGITS.iter().flat_map(move |&d| {
                                HEX_DIGITS.iter().map(move |&e| [a, b, c, d, e])
                            })
                        })
                    })
                });

                let mut guard = ABSTRACT_SOCKETS.lock();
                let name = candidates
                    .find(|name| !guard.contains_key(name.as_slice()))
                    .ok_or(err!(AddrInUse))?;
                let addr = SocketAddrUnix::Abstract(name.to_vec());
                let weak = self.bind(addr)?;
                guard.insert(name.to_vec(), weak);
                Ok(())
            }
            SocketAddrUnix::Abstract(ref name) => {
                let mut guard = ABSTRACT_SOCKETS.lock();
                let entry = guard.entry(name.to_owned());
                let Entry::Vacant(entry) = entry else {
                    bail!(AddrInUse);
                };
                let weak = self.bind(addr)?;
                entry.insert(weak);
                Ok(())
            }
        }
    }

    fn get_socket_option(&self, _: Abi, level: i32, optname: i32) -> Result<Vec<u8>> {
        match (level, optname) {
            (1, 3) => {
                // SO_TYPE
                let ty = SocketType::Stream as u32;
                Ok(ty.to_le_bytes().to_vec())
            }
            (1, 4) => Ok(0u32.to_ne_bytes().to_vec()), // SO_ERROR
            (1, 7) => {
                // SO_SNDBUF
                let val = 0x1000u32;
                Ok(val.to_ne_bytes().to_vec())
            }
            (1, 9) => Ok(0u32.to_ne_bytes().to_vec()), // SO_KEEPALIVE
            (1, 16) => Ok(0u32.to_ne_bytes().to_vec()), // SO_PASSCRED
            (1, 17) => {
                // SO_PEERCRED
                let cred = match self.mode.get() {
                    Some(Mode::Active(active)) => active.peercred,
                    Some(Mode::Passive(active)) => active.localcred,
                    None => Ucred {
                        pid: 0,
                        uid: Uid::UNCHANGED,
                        gid: Gid::UNCHANGED,
                    },
                };
                Ok(bytes_of(&cred).to_vec())
            }
            (1, 38) => Ok(0u32.to_ne_bytes().to_vec()), // SO_PROTOCOL
            _ => bail!(OpNotSupp),
        }
    }

    fn set_socket_option(
        &self,
        virtual_memory: Arc<VirtualMemory>,
        abi: Abi,
        level: i32,
        optname: i32,
        optval: Pointer<[u8]>,
        optlen: i32,
    ) -> Result<()> {
        match (level, optname) {
            (1, 2) => Ok(()), // SO_REUSEADDR
            (1, 9) => Ok(()), // SO_KEEPALIVE
            (1, 20) => {
                // SO_RCVTIMEO

                match abi {
                    Abi::I386 => ensure!(optlen == size_of::<Timeval32>() as i32, Inval),
                    Abi::Amd64 => ensure!(optlen == size_of::<Timeval64>() as i32, Inval),
                }
                let value = virtual_memory.read_with_abi(optval.cast::<Timeval>(), abi)?;

                let mut guard = self.internal.lock();
                guard.receive_timeout = value;
                drop(guard);

                Ok(())
            }
            _ => bail!(OpNotSupp),
        }
    }

    fn get_receive_timeout(&self) -> Timeval {
        self.internal.lock().receive_timeout
    }

    fn get_socket_name(&self) -> Result<SocketAddr> {
        Ok(SocketAddr::Unix(self.socketname.lock().clone()))
    }

    fn get_peer_name(&self) -> Result<SocketAddr> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        Ok(SocketAddr::Unix(active.peername.clone()))
    }

    fn listen(&self, backlog: usize, ctx: &FileAccessContext) -> Result<()> {
        let mut initialized = false;
        let mode = self.mode.call_once(|| {
            initialized = true;
            Mode::Passive(Passive {
                connect_notify: Notify::new(),
                internal: Mutex::new(PassiveInternal {
                    queue: VecDeque::new(),
                    read_event_counter: EventCounter::new(),
                    backlog: 0,
                    shutdown: false,
                }),
                localcred: Ucred::from(ctx),
            })
        });
        if initialized {
            self.activate_notify.notify();
        }
        let Mode::Passive(passive) = mode else {
            bail!(IsConn)
        };

        let mut guard = passive.internal.lock();
        let was_full = guard.backlog >= guard.queue.len();
        guard.backlog = cmp::max(backlog, 1);
        let is_full = guard.backlog >= guard.queue.len();
        drop(guard);

        // If the backlog size was changed, notify sockets that are trying to connect.
        if was_full && !is_full {
            passive.connect_notify.notify();
        }

        Ok(())
    }

    fn accept(&self, flags: Accept4Flags) -> Result<(StrongFileDescriptor, SocketAddr)> {
        let mode = self.mode.get().ok_or(err!(Inval))?;
        let Mode::Passive(passive) = mode else {
            bail!(Inval)
        };
        let mut guard = passive.internal.lock();
        let Some(active) = guard.queue.pop_front() else {
            let shutdown = guard.shutdown;
            drop(guard);

            ensure!(shutdown, Again);
            let nonblock = self.internal.lock().flags.contains(OpenFlags::NONBLOCK);
            if nonblock { bail!(Again) } else { bail!(Inval) }
        };
        passive.connect_notify.notify();
        drop(guard);

        let addr = SocketAddr::Unix(active.peername.clone());

        let mut internal = self.internal.lock().clone();
        internal
            .flags
            .set(OpenFlags::NONBLOCK, flags.contains(Accept4Flags::NONBLOCK));
        internal
            .flags
            .set(OpenFlags::CLOEXEC, flags.contains(Accept4Flags::CLOEXEC));
        let socket = StrongFileDescriptor::new_cyclic(|this| StreamUnixSocket {
            this: this.clone(),
            ino: new_ino(),
            internal: Mutex::new(internal),
            socketname: self.socketname.clone(),
            activate_notify: Notify::new(),
            mode: Once::with_value(Mode::Active(active)),
            bsd_file_lock: BsdFileLock::anonymous(),
        });
        Ok((socket, addr))
    }

    async fn connect(&self, addr: SocketAddr, ctx: &mut FileAccessContext) -> Result<()> {
        let SocketAddr::Unix(addr) = addr else {
            bail!(Inval);
        };

        let server = match addr {
            SocketAddrUnix::Pathname(path) => get_socket(&path, ctx)?,
            SocketAddrUnix::Unnamed => bail!(Inval),
            SocketAddrUnix::Abstract(name) => ABSTRACT_SOCKETS
                .lock()
                .get(&name)
                .and_then(Weak::upgrade)
                .ok_or(err!(ConnRefused))?,
        };
        let server_mode = server.mode.get().ok_or(err!(ConnRefused))?;
        let Mode::Passive(passive) = server_mode else {
            bail!(ConnRefused)
        };

        passive
            .connect_notify
            .wait_until(|| {
                let mut guard = passive.internal.lock();
                if guard.shutdown {
                    return Some(Err(err!(ConnRefused)));
                }
                if guard.backlog <= guard.queue.len() {
                    return None;
                }

                let res = self
                    .mode
                    .init(|| {
                        let cred = Ucred::from(&*ctx);

                        let (read_half1, write_half2) = LockedBuffer::new();
                        let (read_half2, write_half1) = LockedBuffer::new();

                        guard.queue.push_back(Active {
                            write_half: write_half2,
                            read_half: read_half2,
                            peername: self.socketname.lock().clone(),
                            peercred: cred,
                            localcred: passive.localcred,
                        });
                        guard.read_event_counter.inc();
                        passive.connect_notify.notify();

                        self.activate_notify.notify();

                        Mode::Active(Active {
                            write_half: write_half1,
                            read_half: read_half1,
                            peername: server.socketname.lock().clone(),
                            peercred: passive.localcred,
                            localcred: cred,
                        })
                    })
                    .map(drop)
                    .map_err(|_| err!(IsConn));
                Some(res)
            })
            .await?;
        Ok(())
    }

    fn poll_ready(&self, events: Events, _: &FileAccessContext) -> Option<NonEmptyEvents> {
        let mode = self.mode.get()?;
        match mode {
            Mode::Active(active) => {
                let poll_read = active.read_half.lock().poll_read(events);
                let poll_write = active.write_half.lock().poll_write(events);
                NonEmptyEvents::zip(poll_read, poll_write)
            }
            Mode::Passive(passive) => {
                let guard = passive.internal.lock();
                let mut ready_events = Events::empty();
                ready_events.set(Events::READ, !guard.queue.is_empty() || guard.shutdown);
                NonEmptyEvents::new(ready_events & events)
            }
        }
    }

    async fn ready(&self, events: Events, _: &FileAccessContext) -> NonEmptyEvents {
        let mode = self.activate_notify.wait_until(|| self.mode.get()).await;
        match mode {
            Mode::Active(active) => {
                let write_ready = active
                    .write_half
                    .notify
                    .wait_until(|| active.write_half.lock().poll_write(events));
                let read_ready = active
                    .read_half
                    .notify
                    .wait_until(|| active.read_half.lock().poll_read(events));
                NonEmptyEvents::select(write_ready, read_ready).await
            }
            Mode::Passive(passive) => {
                passive
                    .connect_notify
                    .wait_until(|| {
                        let guard = passive.internal.lock();
                        let mut ready_events = Events::empty();
                        ready_events.set(Events::READ, !guard.queue.is_empty() || guard.shutdown);
                        ready_events &= events;
                        NonEmptyEvents::new(ready_events)
                    })
                    .await
            }
        }
    }

    async fn ready_for_write(&self, _count: usize, _: &FileAccessContext) {
        let mode = self.activate_notify.wait_until(|| self.mode.get()).await;
        let Mode::Active(active) = mode else {
            return;
        };
        active
            .write_half
            .notify
            .wait_until(|| active.write_half.lock().can_write().then_some(()))
            .await;
    }

    fn epoll_ready(
        self: Arc<OpenFileDescriptionData<Self>>,
        _: &FileAccessContext,
    ) -> Result<Box<dyn WeakEpollReady>> {
        Ok(Box::new(Arc::downgrade(&self)))
    }

    fn ioctl(
        &self,
        thread: &mut ThreadGuard,
        cmd: u32,
        arg: Pointer<c_void>,
        abi: Abi,
    ) -> Result<u64> {
        socket_common_ioctl(self, thread, cmd, arg, abi)
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
impl EpollReady for StreamUnixSocket {
    async fn epoll_ready(&self, req: &EpollRequest) -> EpollResult {
        let mode = self.activate_notify.wait_until(|| self.mode.get()).await;
        match mode {
            Mode::Active(active) => {
                Notify::zip_epoll_loop(
                    req,
                    &active.read_half.notify,
                    || active.read_half.lock().epoll_read(),
                    &active.write_half.notify,
                    || active.write_half.lock().epoll_write(),
                )
                .await
            }
            Mode::Passive(passive) => {
                passive
                    .connect_notify
                    .epoll_loop(req, || {
                        let mut result = EpollResult::new();
                        let guard = passive.internal.lock();
                        if !guard.queue.is_empty() || guard.shutdown {
                            result.set_ready(Events::READ);
                        }
                        result.add_counter(Events::READ, &guard.read_event_counter);
                        result
                    })
                    .await
            }
        }
    }
}

struct Active {
    write_half: LockedBuffer,
    read_half: LockedBuffer,
    peername: SocketAddrUnix,
    #[expect(dead_code)]
    localcred: Ucred,
    peercred: Ucred,
}

impl Drop for Active {
    fn drop(&mut self) {
        let reset = self.read_half.lock().shutdown();
        if reset {
            // If the socket was closed with remaining bytes, change the buffer
            // into a special failed state.
            self.write_half.lock().reset_conn();
        } else {
            // Otherwise, properly shut down the write half.
            self.write_half.lock().shutdown();
        }
    }
}

struct Buffer {
    data: VecDeque<u8>,
    capacity: usize,
    boundaries: VecDeque<MessageBoundary>,
    total_sent: usize,
    total_received: usize,
    state: BufferState,
    read_counter: EventCounter,
    write_counter: EventCounter,
}

#[derive(Clone, Copy)]
enum BufferState {
    Open,
    Shutdown,
    Reset,
}

impl BufferState {
    pub fn is_closed(&self) -> bool {
        match self {
            Self::Open => false,
            Self::Shutdown | Self::Reset => true,
        }
    }
}

struct MessageBoundary {
    boundary: usize,
    data: AncillaryData,
    len: usize,
}

#[derive(Default)]
struct AncillaryData {
    rights: Option<Vec<StrongFileDescriptor>>,
    cred: Option<Ucred>,
}

impl Buffer {
    pub fn new() -> Self {
        Self {
            data: VecDeque::new(),
            capacity: CAPACITY,
            boundaries: VecDeque::new(),
            total_sent: 0,
            total_received: 0,
            state: BufferState::Open,
            read_counter: EventCounter::new(),
            write_counter: EventCounter::new(),
        }
    }
}

struct LockedBuffer {
    buffer: Arc<Mutex<Buffer>>,
    notify: NotifyOnDrop,
}

impl LockedBuffer {
    pub fn new() -> (Self, Self) {
        let arc = Arc::new(Mutex::new(Buffer::new()));
        let notify = Arc::new(Notify::new());
        (
            Self {
                buffer: arc.clone(),
                notify: NotifyOnDrop(notify.clone()),
            },
            Self {
                buffer: arc,
                notify: NotifyOnDrop(notify),
            },
        )
    }

    pub fn lock(&self) -> BufferGuard<'_> {
        BufferGuard {
            buffer: self,
            guard: self.buffer.lock(),
        }
    }
}

struct BufferGuard<'a> {
    buffer: &'a LockedBuffer,
    guard: MutexGuard<'a, Buffer>,
}

impl BufferGuard<'_> {
    pub fn read(
        &mut self,
        buf: &mut dyn ReadBuf,
        peek: bool,
        waitall: bool,
    ) -> Result<(usize, Option<AncillaryData>)> {
        let buffer = &mut *self.guard;

        let buffer_len = buf.buffer_len();
        if buffer_len == 0 {
            return Ok((0, None));
        }

        if buffer.data.is_empty() {
            match buffer.state {
                BufferState::Open => {}
                BufferState::Shutdown => return Ok((0, None)),
                BufferState::Reset => bail!(ConnReset),
            }

            if Arc::strong_count(&self.buffer.buffer) == 1 {
                return Ok((0, None));
            }

            bail!(Again)
        }

        let mut len = cmp::min(buffer_len, buffer.data.len());

        if let Some(front) = buffer.boundaries.front() {
            let next_message_boundary = (front.boundary + front.len) - buffer.total_received;
            len = cmp::min(len, next_message_boundary);
        } else if waitall {
            ensure!(len == buffer_len, Again);
        }

        let (slice1, slice2) = buffer.data.as_slices();
        if let Some(slice) = slice1.get(..len) {
            buf.write(0, slice)?;
        } else {
            buf.write(0, slice1)?;
            buf.write(slice1.len(), &slice2[..len - slice1.len()])?;
        }
        if !peek {
            buffer.data.drain(..len);
            buffer.total_received += len;
        }

        let ancillary_data = buffer
            .boundaries
            .pop_front_if(|b| b.boundary < buffer.total_received)
            .map(|b| b.data);

        buffer.write_counter.inc();
        self.buffer.notify.notify();

        Ok((len, ancillary_data))
    }

    pub fn write(
        &mut self,
        buf: &dyn WriteBuf,
        ancillary_data: Option<AncillaryData>,
    ) -> Result<usize> {
        let buffer = &mut *self.guard;

        let len = buf.buffer_len();
        if len == 0 {
            // Yes, dropping `ancillary_data` is correct here.
            return Ok(0);
        }

        ensure!(!buffer.state.is_closed(), Pipe);
        ensure!(Arc::strong_count(&self.buffer.buffer) > 1, Pipe);

        let remaining_capacity = buffer.capacity.saturating_sub(buffer.data.len());
        ensure!(remaining_capacity > 0, Again);
        let len = cmp::min(len, remaining_capacity);

        buffer.data.resize(buffer.data.len() + len, 0);
        let (slice1, slice2) = buffer.data.as_mut_slices();
        if let Some(offset) = slice2.len().checked_sub(len) {
            buf.read(0, &mut slice2[offset..])?;
        } else {
            let offset = slice1.len() - (len - slice2.len());
            buf.read(0, &mut slice1[offset..])?;
            buf.read(len - slice2.len(), slice2)?;
        }

        if let Some(ancillary_data) = ancillary_data {
            buffer.boundaries.push_back(MessageBoundary {
                boundary: buffer.total_sent,
                data: ancillary_data,
                len,
            });
        }

        buffer.total_sent += len;

        buffer.read_counter.inc();
        self.buffer.notify.notify();

        Ok(len)
    }

    pub fn can_write(&self) -> bool {
        let buffer = &*self.guard;
        buffer.data.len() < buffer.capacity
            || buffer.state.is_closed()
            || Arc::strong_count(&self.buffer.buffer) == 1
    }

    pub fn splice_from(
        &mut self,
        read_half: &stream_buffer::ReadHalf,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        let buffer = &mut *self.guard;

        if len == 0 {
            return Ok(Ok(0));
        }

        ensure!(!buffer.state.is_closed(), Pipe);
        ensure!(Arc::strong_count(&self.buffer.buffer) > 1, Pipe);

        let len = cmp::min(len, buffer.capacity.saturating_sub(buffer.data.len()));
        read_half.splice_to(len, |buf, len| {
            buffer.data.extend(buf.drain(..len));
            buffer.total_sent += len;
            buffer.read_counter.inc();
            self.buffer.notify.notify();
        })
    }

    pub fn splice_to(
        &mut self,
        write_half: &stream_buffer::WriteHalf,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        let buffer = &mut *self.guard;

        if len == 0 {
            return Ok(Ok(0));
        }

        if buffer.data.is_empty() {
            match buffer.state {
                BufferState::Open => {}
                BufferState::Shutdown => return Ok(Ok(0)),
                BufferState::Reset => bail!(ConnReset),
            }

            if Arc::strong_count(&self.buffer.buffer) == 1 {
                return Ok(Ok(0));
            }

            bail!(Again)
        }

        let mut len = cmp::min(len, buffer.data.len());

        if let Some(front) = buffer.boundaries.front() {
            let next_message_boundary = (front.boundary + front.len) - buffer.total_received;
            len = cmp::min(len, next_message_boundary);
        }

        write_half.splice_from(len, |buf, len| {
            buf.extend(buffer.data.drain(..len));
            buffer.total_received += len;
            buffer
                .boundaries
                .pop_front_if(|b| b.boundary <= buffer.total_received);
            buffer.read_counter.inc();
            self.buffer.notify.notify();
        })
    }

    /// Close the buffer.
    ///
    /// Returns `true` if there are remaining bytes in the buffer.
    pub fn shutdown(&mut self) -> bool {
        if !self.guard.state.is_closed() {
            self.guard.state = BufferState::Shutdown;
            self.buffer.notify.notify();
        }
        !self.guard.data.is_empty()
    }

    pub fn reset_conn(&mut self) {
        self.guard.state = BufferState::Reset;
        self.buffer.notify.notify();
    }

    pub fn poll_read(&self, events: Events) -> Option<NonEmptyEvents> {
        let buffer = &*self.guard;

        let mut ready_events = Events::empty();
        let strong_count = Arc::strong_count(&self.buffer.buffer);
        ready_events.set(
            Events::READ,
            !buffer.data.is_empty() || strong_count == 1 || buffer.state.is_closed(),
        );
        ready_events.set(Events::RDHUP, strong_count == 1 || buffer.state.is_closed());

        ready_events &= events;
        NonEmptyEvents::new(ready_events)
    }

    pub fn poll_write(&self, events: Events) -> Option<NonEmptyEvents> {
        let buffer = &*self.guard;

        let mut ready_events = Events::empty();
        let closed = buffer.state.is_closed() || Arc::strong_count(&self.buffer.buffer) == 1;
        ready_events.set(Events::WRITE, buffer.data.len() < buffer.capacity || closed);
        ready_events &= events;
        ready_events.set(Events::HUP, closed);
        ready_events.set(Events::ERR, closed);

        NonEmptyEvents::new(ready_events)
    }

    pub fn epoll_read(&self) -> EpollResult {
        let mut result = EpollResult::new();
        let buffer = &*self.guard;
        let strong_count = Arc::strong_count(&self.buffer.buffer);
        if !buffer.data.is_empty() || strong_count == 1 || buffer.state.is_closed() {
            result.set_ready(Events::READ);
        }
        if strong_count == 1 || buffer.state.is_closed() {
            result.set_ready(Events::RDHUP);
        }
        result.add_counter(Events::READ, &buffer.read_counter);
        result
    }

    pub fn epoll_write(&self) -> EpollResult {
        let mut result = EpollResult::new();
        let buffer = &*self.guard;
        let closed = buffer.state.is_closed() || Arc::strong_count(&self.buffer.buffer) == 1;
        if buffer.data.len() < buffer.capacity || closed {
            result.set_ready(Events::WRITE);
        }
        if closed {
            result.set_ready(Events::HUP);
        }
        result.add_counter(Events::READ, &buffer.write_counter);
        result
    }
}

struct Passive {
    connect_notify: Notify,
    internal: Mutex<PassiveInternal>,
    localcred: Ucred,
}

struct PassiveInternal {
    queue: VecDeque<Active>,
    read_event_counter: EventCounter,
    backlog: usize,
    shutdown: bool,
}
