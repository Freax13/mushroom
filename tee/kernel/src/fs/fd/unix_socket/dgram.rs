use alloc::{
    boxed::Box,
    collections::{
        VecDeque,
        btree_map::{BTreeMap, Entry},
    },
    format,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::{cmp, ffi::c_void};

use async_trait::async_trait;
use usize_conversions::usize_from;
use x86_64::align_up;

use crate::{
    error::{Result, bail, ensure, err},
    fs::{
        FileSystem,
        fd::{
            BsdFileLock, Events, FdFlags, FileDescriptorTable, NonEmptyEvents, OpenFileDescription,
            OpenFileDescriptionData, ReadBuf, StrongFileDescriptor, VectoredUserBuf, WriteBuf,
            epoll::{EpollReady, EpollRequest, EpollResult, EventCounter, WeakEpollReady},
            socket_common_ioctl,
        },
        node::{FileAccessContext, bind_dgram_socket, get_dgram_socket, new_ino},
        ownership::Ownership,
        path::Path,
    },
    net::CMsgBuilder,
    rt::notify::Notify,
    spin::mutex::Mutex,
    user::{
        memory::VirtualMemory,
        process::limits::CurrentNoFileLimit,
        syscall::{
            args::{
                FileMode, FileType, FileTypeAndMode, MsgHdr, MsgHdrFlags, OpenFlags, Pointer,
                RecvFromFlags, RecvMsgFlags, SendMsgFlags, SentToFlags, SocketAddr, SocketAddrUnix,
                Stat, Timespec, Ucred,
            },
            traits::Abi,
        },
        thread::{Gid, ThreadGuard, Uid},
    },
};

static ABSTRACT_SOCKETS: Mutex<BTreeMap<Vec<u8>, Weak<OpenFileDescriptionData<DgramUnixSocket>>>> =
    Mutex::new(BTreeMap::new());

pub struct DgramUnixSocket {
    this: Weak<OpenFileDescriptionData<Self>>,
    ino: u64,
    addr: Arc<Mutex<Option<SocketAddrUnix>>>,
    internal: Mutex<DgramUnixSocketInternal>,
    notify: Notify,
    bsd_file_lock: BsdFileLock,
    localcred: Ucred,
}

struct DgramUnixSocketInternal {
    flags: OpenFlags,
    ownership: Ownership,
    connection: Option<Connection>,
    packets: VecDeque<Packet>,
    read_counter: EventCounter,
    write_counter: EventCounter,

    passcred: bool,
}

impl DgramUnixSocket {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(flags: OpenFlags, ctx: &FileAccessContext) -> StrongFileDescriptor {
        StrongFileDescriptor::new_cyclic(|this| Self {
            this: this.clone(),
            ino: new_ino(),
            addr: Arc::new(Mutex::new(None)),
            internal: Mutex::new(DgramUnixSocketInternal {
                flags,
                ownership: Ownership::new(
                    FileMode::OWNER_READ | FileMode::OWNER_WRITE,
                    ctx.filesystem_user_id(),
                    ctx.filesystem_group_id(),
                ),
                connection: None,
                packets: VecDeque::new(),
                read_counter: EventCounter::new(),
                write_counter: EventCounter::new(),
                passcred: false,
            }),
            notify: Notify::new(),
            bsd_file_lock: BsdFileLock::anonymous(),
            localcred: Ucred::from(ctx),
        })
    }

    pub fn new_pair(
        flags: OpenFlags,
        ctx: &FileAccessContext,
    ) -> (StrongFileDescriptor, StrongFileDescriptor) {
        // Create two sockets.
        let cred = Ucred::from(ctx);
        let (fd1, socket1) = StrongFileDescriptor::new_cyclic_with_data(|this| Self {
            this: this.clone(),
            ino: new_ino(),
            addr: Arc::new(Mutex::new(None)),
            internal: Mutex::new(DgramUnixSocketInternal {
                flags,
                ownership: Ownership::new(
                    FileMode::OWNER_READ | FileMode::OWNER_WRITE,
                    ctx.filesystem_user_id(),
                    ctx.filesystem_group_id(),
                ),
                connection: None,
                packets: VecDeque::new(),
                read_counter: EventCounter::new(),
                write_counter: EventCounter::new(),
                passcred: false,
            }),
            notify: Notify::new(),
            bsd_file_lock: BsdFileLock::anonymous(),
            localcred: cred,
        });
        let (fd2, socket2) = StrongFileDescriptor::new_cyclic_with_data(|this| Self {
            this: this.clone(),
            ino: new_ino(),
            addr: Arc::new(Mutex::new(None)),
            internal: Mutex::new(DgramUnixSocketInternal {
                flags,
                ownership: Ownership::new(
                    FileMode::OWNER_READ | FileMode::OWNER_WRITE,
                    ctx.filesystem_user_id(),
                    ctx.filesystem_group_id(),
                ),
                connection: None,
                packets: VecDeque::new(),
                read_counter: EventCounter::new(),
                write_counter: EventCounter::new(),
                passcred: false,
            }),
            notify: Notify::new(),
            bsd_file_lock: BsdFileLock::anonymous(),
            localcred: cred,
        });

        // Connect the two sockets.
        let socket1_weak = Arc::downgrade(&socket1);
        let socket2_weak = Arc::downgrade(&socket2);
        socket1.internal.lock().connection = Some(Connection {
            remote_addr: socket2.addr.clone(),
            socket: socket2_weak,
            reset: false,
        });
        socket2.internal.lock().connection = Some(Connection {
            remote_addr: socket1.addr.clone(),
            socket: socket1_weak,
            reset: false,
        });

        (fd1, fd2)
    }

    pub fn bind(&self, socketname: SocketAddrUnix) -> Result<Weak<OpenFileDescriptionData<Self>>> {
        ensure!(!matches!(socketname, SocketAddrUnix::Unnamed), Inval);

        let mut guard = self.addr.lock();
        // Make sure that the socket is not already bound.
        ensure!(guard.is_none(), Inval);
        *guard = Some(socketname);
        drop(guard);

        Ok(self.this.clone())
    }

    fn send_packet_to(
        &self,
        addr: Option<SocketAddr>,
        mut packet: Packet,
        ctx: &FileAccessContext,
    ) -> Result<()> {
        let destination = if let Some(addr) = addr {
            let SocketAddr::Unix(addr) = addr else {
                bail!(Inval);
            };
            match addr {
                SocketAddrUnix::Pathname(path) => get_dgram_socket(&path, &mut ctx.clone())?,
                SocketAddrUnix::Unnamed => bail!(Inval),
                SocketAddrUnix::Abstract(name) => ABSTRACT_SOCKETS
                    .lock()
                    .get(&name)
                    .and_then(Weak::upgrade)
                    .ok_or(err!(ConnRefused))?,
            }
        } else {
            let guard = self.internal.lock();
            let connection = guard.connection.as_ref().ok_or(err!(NotConn))?;
            ensure!(!connection.reset, ConnReset);
            packet.connection_end = self.this.clone();
            connection.socket.upgrade().ok_or(err!(ConnRefused))?
        };

        let mut guard = destination.internal.lock();
        // If the other socket is connected, make sure it's connected to this socket.
        if let Some(connection) = guard.connection.as_ref() {
            ensure!(Weak::ptr_eq(&self.this, &connection.socket), Perm);
        }

        // Append the packet.
        guard.packets.push_back(packet);
        guard.read_counter.inc();
        drop(guard);

        destination.notify.notify();

        Ok(())
    }

    fn recv_packet(&self) -> Result<Packet> {
        let mut guard = self.internal.lock();
        let packet = guard.packets.pop_front().ok_or(err!(Again))?;
        drop(guard);

        if let Some(other) = packet.connection_end.upgrade() {
            let mut guard = other.internal.lock();
            guard.write_counter.inc();
            drop(guard);
            other.notify.notify();
        }

        Ok(packet)
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

    fn bind(&self, addr: SocketAddr, ctx: &mut FileAccessContext) -> Result<()> {
        let SocketAddr::Unix(addr) = addr else {
            bail!(Inval);
        };

        match addr {
            SocketAddrUnix::Pathname(path) => {
                let guard = self.internal.lock();
                let cwd = ctx.process().unwrap().cwd();
                bind_dgram_socket(
                    cwd,
                    &path,
                    guard.ownership.mode(),
                    guard.ownership.uid(),
                    guard.ownership.gid(),
                    self,
                    ctx,
                )?;
            }
            SocketAddrUnix::Unnamed => {
                let mut guard = self.addr.lock();
                if guard.is_none() {
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

                    let mut sockets_guard = ABSTRACT_SOCKETS.lock();
                    let name = candidates
                        .find(|name| !sockets_guard.contains_key(name.as_slice()))
                        .ok_or(err!(AddrInUse))?;
                    sockets_guard.insert(name.to_vec(), self.this.clone());
                    drop(sockets_guard);

                    let addr = SocketAddrUnix::Abstract(name.to_vec());
                    *guard = Some(addr);
                }
            }
            SocketAddrUnix::Abstract(name) => {
                let mut guard = self.addr.lock();
                ensure!(guard.is_none(), Inval);

                let mut sockets_guard = ABSTRACT_SOCKETS.lock();
                let entry = sockets_guard.entry(name.clone());
                match entry {
                    Entry::Vacant(entry) => {
                        entry.insert(self.this.clone());
                    }
                    Entry::Occupied(mut entry) => {
                        ensure!(entry.get().strong_count() == 0, AddrInUse);
                        entry.insert(self.this.clone());
                    }
                }
                drop(sockets_guard);

                let addr = SocketAddrUnix::Abstract(name);
                *guard = Some(addr);
            }
        }

        Ok(())
    }

    async fn connect(&self, addr: SocketAddr, ctx: &mut FileAccessContext) -> Result<()> {
        let mut guard = self.internal.lock();
        let old_connected_socket = guard.connection.as_ref().map(|conn| conn.socket.clone());
        match addr {
            SocketAddr::Unspecified => {
                guard.connection.take();
            }
            SocketAddr::Unix(addr) => {
                let new_socket = match addr {
                    SocketAddrUnix::Pathname(path) => get_dgram_socket(&path, ctx)?,
                    SocketAddrUnix::Unnamed => todo!(),
                    SocketAddrUnix::Abstract(name) => ABSTRACT_SOCKETS
                        .lock()
                        .get(&name)
                        .and_then(Weak::upgrade)
                        .ok_or(err!(ConnRefused))?,
                };

                // Don't do anything if the new socket matches an existing connection.
                if guard.connection.as_ref().is_some_and(|conn| {
                    core::ptr::addr_eq(conn.socket.as_ptr(), Arc::as_ptr(&new_socket))
                }) {
                    return Ok(());
                }

                let mut other_guard = new_socket.internal.lock();
                if let Some(connection) = other_guard.connection.as_mut() {
                    ensure!(Weak::ptr_eq(&self.this, &connection.socket), Perm);
                    connection.reset = false;
                }
                drop(other_guard);

                guard.connection = Some(Connection {
                    remote_addr: new_socket.addr.clone(),
                    socket: Arc::downgrade(&new_socket),
                    reset: false,
                });
            }
            _ => bail!(Inval),
        }
        let had_packets = !guard.packets.is_empty();
        if old_connected_socket.is_some() {
            guard.packets.clear();
            guard.write_counter.inc();
        }
        drop(guard);

        self.notify.notify();

        if had_packets
            && let Some(old_connection) = old_connected_socket.and_then(|weak| weak.upgrade())
        {
            let mut guard = old_connection.internal.lock();
            if let Some(connection) = guard.connection.as_mut()
                && Weak::ptr_eq(&self.this, &connection.socket)
            {
                connection.reset = true;
            }
        }

        Ok(())
    }

    fn read(&self, buf: &mut dyn ReadBuf, _: &FileAccessContext) -> Result<usize> {
        self.recv_from(buf, RecvFromFlags::empty()).map(|(n, _)| n)
    }

    fn recv_from(
        &self,
        buf: &mut dyn ReadBuf,
        _: RecvFromFlags,
    ) -> Result<(usize, Option<SocketAddr>)> {
        let packet = self.recv_packet()?;

        let len = cmp::min(packet.data.len(), buf.buffer_len());
        buf.write(0, &packet.data[..len])?;

        let addr = packet.sender_addr.lock().clone().map(SocketAddr::Unix);

        Ok((len, addr))
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
        ensure!(msg_hdr.namelen == 0, IsConn);
        ensure!(msg_hdr.flags == MsgHdrFlags::empty(), Inval);

        let mut packet = self.recv_packet()?;

        let mut vectored_buf = VectoredUserBuf::new(vm, msg_hdr.iov, msg_hdr.iovlen, abi)?;
        let len = cmp::min(packet.data.len(), ReadBuf::buffer_len(&vectored_buf));
        vectored_buf.write(0, &packet.data[..len])?;

        if msg_hdr.namelen != 0 {
            let addr = packet.sender_addr.lock().clone().map(SocketAddr::Unix);
            if let Some(addr) = addr {
                msg_hdr.namelen = addr.write(msg_hdr.name, usize_from(msg_hdr.namelen), vm)? as u32;
            } else {
                msg_hdr.namelen = 0;
            }
        }

        let mut cmsg_builder = CMsgBuilder::new(abi, vm, msg_hdr);
        if let Some(ancillary_data) = packet.ancillary_data.as_mut()
            && let Some(fds) = ancillary_data.rights.take().filter(|fds| !fds.is_empty())
        {
            let mut fd_flags = FdFlags::empty();
            fd_flags.set(FdFlags::CLOEXEC, flags.contains(RecvMsgFlags::CMSG_CLOEXEC));
            cmsg_builder.add_fds(1, 1, fds, fd_flags, fdtable, no_file_limit)?;
        }
        let passcred = self.internal.lock().passcred;
        if passcred {
            let cred = packet
                .ancillary_data
                .as_ref()
                .and_then(|ancillary_data| ancillary_data.cred)
                .unwrap_or(packet.sender_cred);
            cmsg_builder.add(1, 2, cred)?;
        }
        drop(cmsg_builder);

        Ok(len)
    }

    fn write(&self, buf: &dyn WriteBuf, ctx: &FileAccessContext) -> Result<usize> {
        self.send_to(buf, SentToFlags::empty(), None, ctx)
    }

    fn send_to(
        &self,
        buf: &dyn WriteBuf,
        flags: SentToFlags,
        addr: Option<SocketAddr>,
        ctx: &FileAccessContext,
    ) -> Result<usize> {
        if flags != SentToFlags::empty() {
            todo!()
        }

        let len = buf.buffer_len();
        let mut bytes = vec![0; len];
        buf.read(0, &mut bytes)?;
        let data = Box::from(bytes);

        let packet = Packet {
            data,
            sender_addr: self.addr.clone(),
            sender_cred: self.localcred,
            connection_end: Weak::new(),
            ancillary_data: None,
        };

        self.send_packet_to(addr, packet, ctx)?;

        Ok(len)
    }

    fn send_msg(
        &self,
        vm: &VirtualMemory,
        abi: Abi,
        msg_hdr: &mut MsgHdr,
        flags: SendMsgFlags,
        fdtable: &FileDescriptorTable,
        ctx: &FileAccessContext,
    ) -> Result<usize> {
        if (flags & !SendMsgFlags::NOSIGNAL) != SendMsgFlags::empty() {
            todo!("{flags:?}")
        }
        if msg_hdr.flags != MsgHdrFlags::empty() {
            todo!();
        }

        let vectored_buf = VectoredUserBuf::new(vm, msg_hdr.iov, msg_hdr.iovlen, abi)?;
        let len = WriteBuf::buffer_len(&vectored_buf);
        let mut bytes = vec![0; len];
        vectored_buf.read(0, &mut bytes)?;
        let data = Box::from(bytes);

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
                    _ => {
                        todo!("level={} type={}", header.level, header.r#type)
                    }
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

        let packet = Packet {
            data,
            sender_addr: self.addr.clone(),
            sender_cred: self.localcred,
            connection_end: Weak::new(),
            ancillary_data,
        };

        let addr = if msg_hdr.namelen != 0 {
            Some(SocketAddr::read(
                msg_hdr.name,
                usize_from(msg_hdr.namelen),
                vm,
            )?)
        } else {
            None
        };

        self.send_packet_to(addr, packet, ctx)?;

        Ok(len)
    }

    fn poll_ready(&self, events: Events, _: &FileAccessContext) -> Option<NonEmptyEvents> {
        let mut ready_events = Events::empty();
        ready_events.set(Events::READ, !self.internal.lock().packets.is_empty());
        ready_events.set(Events::WRITE, true);
        NonEmptyEvents::new(ready_events & events)
    }

    async fn ready(&self, events: Events, ctx: &FileAccessContext) -> NonEmptyEvents {
        self.notify
            .wait_until(|| self.poll_ready(events, ctx))
            .await
    }

    fn epoll_ready(
        self: Arc<OpenFileDescriptionData<Self>>,
        _: &FileAccessContext,
    ) -> Result<Box<dyn WeakEpollReady>> {
        Ok(Box::new(Arc::downgrade(&self)))
    }

    fn get_socket_name(&self) -> Result<SocketAddr> {
        let addr = self.addr.lock().clone();
        let addr = addr.unwrap_or(SocketAddrUnix::Unnamed);
        Ok(SocketAddr::Unix(addr))
    }

    fn get_peer_name(&self) -> Result<SocketAddr> {
        let addr = self
            .internal
            .lock()
            .connection
            .as_ref()
            .ok_or(err!(NotConn))?
            .remote_addr
            .clone();
        let addr = addr.lock().clone();
        let addr = addr.unwrap_or(SocketAddrUnix::Unnamed);
        Ok(SocketAddr::Unix(addr))
    }

    fn get_socket_option(&self, _: Abi, level: i32, optname: i32) -> Result<Vec<u8>> {
        match (level, optname) {
            (1, 16) => {
                // SO_PASSCRED
                let passcred = self.internal.lock().passcred;
                Ok(u32::from(passcred).to_ne_bytes().to_vec())
            }
            _ => bail!(OpNotSupp),
        }
    }

    fn set_socket_option(
        &self,
        virtual_memory: Arc<VirtualMemory>,
        _: Abi,
        level: i32,
        optname: i32,
        optval: Pointer<[u8]>,
        optlen: i32,
    ) -> Result<()> {
        match (level, optname) {
            (1, 16) => {
                // SO_PASSCRED
                ensure!(optlen == 4, Inval);
                let passcred = virtual_memory.read(optval.cast::<u32>())? != 0;
                let mut guard = self.internal.lock();
                guard.passcred = passcred;
                Ok(())
            }
            _ => bail!(OpNotSupp),
        }
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
impl EpollReady for DgramUnixSocket {
    async fn epoll_ready(&self, req: &EpollRequest) -> EpollResult {
        self.notify
            .epoll_loop(req, || {
                let mut result = EpollResult::new();
                let guard = self.internal.lock();
                if !guard.packets.is_empty() {
                    result.set_ready(Events::READ);
                }
                result.set_ready(Events::WRITE);
                result.add_counter(Events::READ, &guard.read_counter);
                result.add_counter(Events::WRITE, &guard.write_counter);
                result
            })
            .await
    }
}

struct Connection {
    remote_addr: Arc<Mutex<Option<SocketAddrUnix>>>,
    socket: Weak<OpenFileDescriptionData<DgramUnixSocket>>,
    reset: bool,
}

struct Packet {
    data: Box<[u8]>,
    sender_addr: Arc<Mutex<Option<SocketAddrUnix>>>,
    sender_cred: Ucred,
    /// A weak pointer to the socket that send the packet iff that socket was
    /// connected to the receiver
    connection_end: Weak<OpenFileDescriptionData<DgramUnixSocket>>,
    ancillary_data: Option<AncillaryData>,
}

#[derive(Clone, Default)]
struct AncillaryData {
    rights: Option<Vec<StrongFileDescriptor>>,
    cred: Option<Ucred>,
}
