use core::{
    cmp,
    ffi::c_void,
    net::{Ipv4Addr, SocketAddrV4},
    ops::Not,
    pin::pin,
};

use alloc::{
    boxed::Box,
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    sync::{Arc, Weak},
    vec::Vec,
};
use async_trait::async_trait;
use bytemuck::bytes_of;

use crate::{
    error::{Result, bail, ensure, err},
    fs::{
        FileSystem,
        fd::{Events, FileDescriptor, FileLock, OpenFileDescription, common_ioctl, stream_buffer},
        node::{FileAccessContext, new_ino},
        ownership::Ownership,
        path::Path,
    },
    rt::{
        self,
        notify::{Notify, NotifyOnDrop},
    },
    spin::{
        mutex::{Mutex, MutexGuard},
        once::Once,
    },
    time::{now, sleep_until},
    user::process::{
        memory::VirtualMemory,
        syscall::{
            args::{
                Accept4Flags, ClockId, FileMode, FileType, FileTypeAndMode, Linger, OpenFlags,
                Pointer, RecvFromFlags, SentToFlags, ShutdownHow, SocketAddr, SocketAddrInet,
                SocketType, SocketTypeWithFlags, Stat, Timespec,
            },
            traits::Abi,
        },
        thread::{Gid, Uid},
    },
};

// TODO: Periodically clean up closed TCP sockets.
static PORTS: Mutex<BTreeMap<u16, PortData>> = Mutex::new(BTreeMap::new());

#[derive(Default)]
struct PortData {
    round_robin_counter: usize,
    entries: Vec<PortDataEntry>,
    /// This notify is signaled when a passive socket is ready to accept more
    /// clients again i.e. that a slot in its backlog just became available.
    /// This notify is also signaled when a passive socket is closed.
    connect_notify: Arc<Notify>,
}

impl PortData {
    /// Check all the pre-conditions required for binding a port, but don't
    /// actually bind it just yet. Instead return a [`BindGuard`] that can be
    /// used to bind a port at a later time.
    pub fn prepare_bind(
        &mut self,
        ip: Ipv4Addr,
        reuse_addr: bool,
        reuse_port: bool,
        effective_uid: Uid,
    ) -> Result<BindGuard<'_>> {
        let local_ip = ip.is_unspecified().not().then_some(ip);

        if let Some(local_ip) = local_ip {
            // We only support binding to localhost -> make sure that the
            // address is a loopback address.
            ensure!(local_ip.is_loopback(), AddrNotAvail);
        }

        let mut i = 0;
        while let Some(entry) = self.entries.get(i) {
            i += 1;
            // Skip (and remove) entries whose sockets are no longer live.
            let Some(mode) = entry.mode.upgrade() else {
                i -= 1;
                self.entries.swap_remove(i);
                continue;
            };

            // Skip entries that don't overlap with `ip`.
            if entry
                .local_ip
                .zip(local_ip)
                .is_some_and(|(entry_ip, ip)| entry_ip != ip)
            {
                continue;
            }

            // Skip entries that are allowed to overlap according to SO_REUSEPORT.
            if reuse_port && entry.reuse_port && entry.effective_uid == effective_uid {
                continue;
            }

            // Unless when SO_REUSE_ADDR is set, make sure that there's no
            // overlap between an specified and an unspecified address.
            if !reuse_addr || !entry.reuse_addr {
                ensure!(
                    Option::zip(entry.local_ip, local_ip)
                        .is_some_and(|(entry_ip, ip)| entry_ip != ip),
                    AddrInUse
                );
            }

            // Fail if there's already a listening socket.
            let is_listening = mode
                .get()
                .is_some_and(|mode| matches!(mode, Mode::Passive(..)));
            ensure!(!is_listening, AddrInUse);
        }

        Ok(BindGuard {
            port_data: self,
            local_ip,
            reuse_addr,
            reuse_port,
            effective_uid,
        })
    }

    /// Check if the socket with the given mode pointer can be made into a
    /// listening socket.
    fn can_listen(&self, mode: &Arc<Once<Mode>>) -> bool {
        // Find the entry for the socket.
        let socket_entry = self
            .entries
            .iter()
            .find(|entry| entry.mode.as_ptr() == &**mode)
            .expect("socket can't listen before it's bound");

        // Check if there are any conflicting sockets.
        !self
            .entries
            .iter()
            // Ignore the socket itself.
            .filter(|entry| entry.mode.as_ptr() != &**mode)
            // Ignore if both sockets have the reuse_port option enabled.
            .filter(|entry| !(entry.reuse_port && socket_entry.reuse_port))
            // Ignore sockets that don't have an overlap in the bound address.
            .filter(|entry| {
                Option::zip(entry.local_ip, socket_entry.local_ip)
                    .is_none_or(|(entry_ip, ip)| entry_ip == ip)
            })
            // Only consider sockets which are still active.
            .filter_map(|entry| entry.mode.upgrade())
            // See if there are any listening sockets.
            .any(|port| {
                port.get()
                    .is_some_and(|mode| matches!(mode, Mode::Passive(_)))
            })
    }
}

struct BindGuard<'a> {
    port_data: &'a mut PortData,
    local_ip: Option<Ipv4Addr>,
    reuse_addr: bool,
    reuse_port: bool,
    effective_uid: Uid,
}

impl BindGuard<'_> {
    pub fn bind(self, mode: Weak<Once<Mode>>) {
        self.port_data.entries.push(PortDataEntry {
            local_ip: self.local_ip,
            remote_addr: None,
            reuse_addr: self.reuse_addr,
            reuse_port: self.reuse_port,
            effective_uid: self.effective_uid,
            mode,
        });
    }
}

struct PortDataEntry {
    local_ip: Option<Ipv4Addr>,
    remote_addr: Option<SocketAddrV4>,
    reuse_addr: bool,
    reuse_port: bool,
    effective_uid: Uid,
    mode: Weak<Once<Mode>>,
}

const EPHEMERAL_PORT_START: u16 = 32768;
const EPHEMERAL_PORT_END: u16 = 60999;

pub struct TcpSocket {
    ino: u64,
    internal: Mutex<TcpSocketInternal>,
    activate_notify: Notify,
    bound_socket: Once<BoundSocket>,
}

#[derive(Clone)]
struct TcpSocketInternal {
    flags: OpenFlags,
    ownership: Ownership,
    reuse_addr: bool,
    reuse_port: bool,
    send_buffer_size: usize,
    no_delay: bool,
    linger: Option<i32>,
}

impl TcpSocket {
    pub fn new(r#type: SocketTypeWithFlags, uid: Uid, gid: Gid) -> Self {
        Self {
            ino: new_ino(),
            internal: Mutex::new(TcpSocketInternal {
                flags: r#type.flags,
                ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
                reuse_addr: false,
                reuse_port: false,
                send_buffer_size: 1024 * 1024,
                no_delay: false,
                linger: None,
            }),
            activate_notify: Notify::new(),
            bound_socket: Once::new(),
        }
    }

    /// Try to bind the socket to an address. Returns `true` if the socket was
    /// bound, returns `false` if the socket was already bound. Returns
    /// `Err(..)` if the socket could not be bound to the given address.
    fn try_bind(&self, addr: SocketAddrInet) -> Result<bool> {
        let guard = self.internal.lock();
        let reuse_addr = guard.reuse_addr;
        let reuse_port = guard.reuse_port;
        drop(guard);

        let mut socket_addr = SocketAddrV4::from(addr);
        let effective_uid = Uid::SUPER_USER; // TODO

        let mut guard = PORTS.lock();

        // Prepare a bind guard.
        let bind_guard = if socket_addr.port() == 0 {
            'port: {
                // If no port has been specified, try to find one that can be
                // bound to.
                for port in EPHEMERAL_PORT_START..=EPHEMERAL_PORT_END {
                    let entry = guard.entry(port).or_default();
                    if let Ok(bind_guard) =
                        entry.prepare_bind(*socket_addr.ip(), false, false, effective_uid)
                    {
                        socket_addr.set_port(port);
                        break 'port bind_guard;
                    }
                }
                // If we can't find a port, fail.
                bail!(AddrInUse)
            }
        } else {
            guard.entry(socket_addr.port()).or_default().prepare_bind(
                *socket_addr.ip(),
                reuse_addr,
                reuse_port,
                effective_uid,
            )?
        };

        // Try to initialize the socket.
        let res = self.bound_socket.init(|| BoundSocket {
            bind_addr: socket_addr,
            reuse_port,
            reuse_addr,
            connect_notify: NotifyOnDrop(bind_guard.port_data.connect_notify.clone()),
            mode: Arc::new(Once::new()),
        });
        // Return false if the socket was already bound.
        let Ok(bound) = res else {
            return Ok(false);
        };
        self.activate_notify.notify();

        // Complete the bind operation.
        bind_guard.bind(Arc::downgrade(&bound.mode));

        Ok(true)
    }

    fn get_or_bind_ephemeral(&self) -> Result<&BoundSocket> {
        self.try_bind(SocketAddrInet::from(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            0,
        )))?;
        Ok(self.bound_socket.get().unwrap())
    }
}

#[async_trait]
impl OpenFileDescription for TcpSocket {
    fn flags(&self) -> OpenFlags {
        self.internal.lock().flags
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

    fn bind(
        &self,
        virtual_memory: &VirtualMemory,
        addr: Pointer<SocketAddr>,
        addrlen: usize,
    ) -> Result<()> {
        ensure!(addrlen == size_of::<SocketAddr>(), Inval);
        let addr = virtual_memory.read(addr)?;
        let SocketAddr::Inet(addr) = addr else {
            bail!(Inval);
        };
        ensure!(self.try_bind(addr)?, Inval);
        Ok(())
    }

    fn get_socket_name(&self) -> Result<Vec<u8>> {
        let addr = self
            .bound_socket
            .get()
            .map(|bound| {
                // The address of a socket might change when it's connected. If
                // the socket is connected, prefer the address stored with that
                // connection.
                if let Some(Mode::Active(active)) = bound.mode.get() {
                    active.local_addr
                } else {
                    bound.bind_addr
                }
            })
            .map(SocketAddrInet::from)
            .unwrap_or_default();
        let addr = SocketAddr::Inet(addr);
        Ok(bytes_of(&addr).to_vec())
    }

    fn get_peer_name(&self) -> Result<Vec<u8>> {
        let socket = self.bound_socket.get().ok_or(err!(NotConn))?;
        let mode = socket.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        let addr = SocketAddrInet::from(active.remote_addr);
        let addr = SocketAddr::Inet(addr);
        Ok(bytes_of(&addr).to_vec())
    }

    fn listen(&self, backlog: usize) -> Result<()> {
        // Make sure that the backlog is never empty.
        let backlog = cmp::max(backlog, 1);

        let bound = self.get_or_bind_ephemeral()?;

        let guard = PORTS.lock();
        // Check if the socket is allowed to listen on the given port.
        let entries = &guard[&bound.bind_addr.port()];
        ensure!(entries.can_listen(&bound.mode), AddrInUse);

        // If uninitialized, initialize the socket as a passive socket.
        let mode = bound.mode.call_once(|| {
            Mode::Passive(PassiveTcpSocket {
                notify: Arc::new(Notify::new()),
                internal: Mutex::new(PassiveTcpSocketInternal {
                    backlog: 0,
                    queue: VecDeque::new(),
                }),
            })
        });
        drop(guard);

        // Fail if the socket was previously an active socket.
        let Mode::Passive(passive) = mode else {
            bail!(IsConn);
        };

        // Update the backlog capacity.
        let mut guard = passive.internal.lock();
        let was_full = guard.queue.len() >= guard.backlog;
        guard.backlog = backlog;
        let is_full = guard.queue.len() >= guard.backlog;
        drop(guard);

        // If the socket is now ready to accept a socket, notify any sockets
        // that are trying to connect.
        if was_full && !is_full {
            bound.connect_notify.notify();
        }

        Ok(())
    }

    fn accept(&self, flags: Accept4Flags) -> Result<(FileDescriptor, Vec<u8>)> {
        let bound = self.bound_socket.get().ok_or(err!(Inval))?;
        let mode = bound.mode.get().ok_or(err!(Inval))?;
        let Mode::Passive(passive) = mode else {
            bail!(Inval);
        };
        let active = passive
            .internal
            .lock()
            .queue
            .pop_front()
            .ok_or(err!(Again))?;
        let remote_addr = active.remote_addr;

        let mut internal = self.internal.lock().clone();
        internal
            .flags
            .set(OpenFlags::NONBLOCK, flags.contains(Accept4Flags::NONBLOCK));
        internal
            .flags
            .set(OpenFlags::CLOEXEC, flags.contains(Accept4Flags::CLOEXEC));

        let socket = Self {
            ino: new_ino(),
            internal: Mutex::new(internal),
            activate_notify: Notify::new(),
            bound_socket: Once::with_value(BoundSocket {
                bind_addr: bound.bind_addr,
                reuse_addr: bound.reuse_addr,
                reuse_port: bound.reuse_port,
                connect_notify: bound.connect_notify.clone(),
                mode: Arc::new(Once::with_value(Mode::Active(active))),
            }),
        };
        let fd = FileDescriptor::from(socket);

        let socket_addr = SocketAddr::Inet(SocketAddrInet::from(remote_addr));
        let socket_addr = bytes_of(&socket_addr).to_vec();

        Ok((fd, socket_addr))
    }

    async fn connect(
        &self,
        virtual_memory: &VirtualMemory,
        addr: Pointer<SocketAddr>,
        addrlen: usize,
    ) -> Result<()> {
        let bound = self.get_or_bind_ephemeral()?;

        ensure!(addrlen == size_of::<SocketAddr>(), Inval);
        let remote_addr = virtual_memory.read(addr)?;
        let SocketAddr::Inet(remote_addr) = remote_addr else {
            bail!(Inval);
        };
        let remote_addr = SocketAddrV4::from(remote_addr);

        let remote_ip = *remote_addr.ip();
        let remote_ip = remote_ip.is_unspecified().not().then_some(remote_ip);

        if let Some(remote_ip) = remote_ip {
            ensure!(remote_ip.is_loopback(), NetUnreach);
        }

        'outer: loop {
            let mut guard = PORTS.lock();

            let ports = guard
                .get_mut(&remote_addr.port())
                .ok_or(err!(ConnRefused))?;
            let connect_notify = ports.connect_notify.clone();
            let wait = connect_notify.wait();

            let mut i = 0;
            let mut found_passive_socket = false;
            loop {
                // If there are no more sockets that could accept a new socket
                // drop the locks, wait, and try again.
                if i >= ports.entries.len() {
                    // Bail out if there are no sockets.
                    ensure!(found_passive_socket, ConnRefused);
                    drop(guard);
                    wait.await;
                    continue 'outer;
                }

                // Add a round robin offset and get the entry.
                let offset_index =
                    (i + ports.round_robin_counter.wrapping_add(i)) % ports.entries.len();
                i += 1;
                let entry = &ports.entries[offset_index];

                // Skip over entries that don't have a matching IP.
                if Option::zip(entry.local_ip, remote_ip)
                    .is_some_and(|(entry_ip, remote_ip)| entry_ip != remote_ip)
                {
                    continue;
                }

                // Remove entries if the port is no longer alive.
                let Some(mode) = entry.mode.upgrade() else {
                    ports.entries.remove(offset_index);
                    i -= 1;
                    continue;
                };

                // Skip any non-active or non-passive sockets.
                let Some(mode) = mode.get() else {
                    continue;
                };
                let Mode::Passive(passive) = mode else {
                    continue;
                };

                // This is a socket that we could connect to.
                found_passive_socket = true;

                // Determine the peer address.
                // If possible use the address bound to by the listening
                // socket.
                let peer_ip = entry.local_ip;
                // Otherwise, fall back to the address in the connect call.
                let peer_ip = peer_ip.or(remote_ip);
                // Otherwise, fall back to the address bound by the connecting
                // socket.
                let peer_ip = peer_ip.or_else(|| {
                    let ip = bound.bind_addr.ip();
                    ip.is_unspecified().not().then_some(*ip)
                });
                // If all of that fails, use localhost.
                let peer_ip = peer_ip.unwrap_or(Ipv4Addr::LOCALHOST);
                let mut remote_addr = remote_addr;
                remote_addr.set_ip(peer_ip);

                // Determine the local address.
                // If possible use the address bound to by the listening
                // socket.
                let local_ip = bound
                    .bind_addr
                    .ip()
                    .is_unspecified()
                    .not()
                    .then_some(*bound.bind_addr.ip());
                // Otherwise use localhost.
                let local_ip = local_ip.unwrap_or(Ipv4Addr::LOCALHOST);

                // Try to reserve a slot in the backlog.
                let Some(connect_guard) = passive.prepare_connect() else {
                    continue;
                };

                // We've found a socket that's willing to connect :)

                // Increase the round robin counter.
                ports.round_robin_counter += i;

                // Make sure that the (src,dst) pair does not already exist for
                // this port.
                let ports = if remote_addr.port() == bound.bind_addr.port() {
                    ports
                } else {
                    guard.get_mut(&bound.bind_addr.port()).unwrap()
                };
                let duplicate_pair = ports.entries.iter().any(|entry| {
                    entry.local_ip == Some(local_ip) && entry.remote_addr == Some(remote_addr)
                });
                ensure!(!duplicate_pair, AddrInUse);

                // Initialize an active socket.
                bound
                    .mode
                    .init(|| {
                        let (socket1, socket2) = ActiveTcpSocket::new_pair(
                            SocketAddrV4::new(local_ip, bound.bind_addr.port()),
                            remote_addr,
                        );
                        connect_guard.connect(socket2);
                        Mode::Active(socket1)
                    })
                    .map_err(|_| err!(IsConn))?;
                self.activate_notify.notify();

                // Update the entry for this socket to reflect the IPs.
                let this_entry = ports
                    .entries
                    .iter_mut()
                    .find(|e| e.mode.as_ptr() == Arc::as_ptr(&bound.mode))
                    .unwrap();
                this_entry.local_ip = Some(local_ip);
                this_entry.remote_addr = Some(remote_addr);

                return Ok(());
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
            _ => bail!(Inval),
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
        let mut guard = self.internal.lock();
        match (level, optname) {
            (1, 2) => {
                // SO_REUSEADDR
                ensure!(optlen == 4, Inval);
                let optval = virtual_memory.read(optval.cast::<i32>())? != 0;
                guard.reuse_addr = optval;
                Ok(())
            }
            (1, 7) => {
                // SO_SNDBUF
                ensure!(optlen == 4, Inval);
                let optval = virtual_memory.read(optval.cast::<i32>())?;
                let new_send_buffer_size = optval as usize * 2;
                let new_send_buffer_size = cmp::min(new_send_buffer_size, 2048); // 2048 is the minimum
                guard.send_buffer_size = new_send_buffer_size;
                if let Some(bound) = self.bound_socket.get() {
                    if let Some(Mode::Active(active)) = bound.mode.get() {
                        active.write_half.set_buffer_capacity(new_send_buffer_size);
                    }
                }
                Ok(())
            }
            (1, 9) => {
                // SO_KEEPALIVE
                Ok(())
            }
            (1, 13) => {
                // SO_LINGER
                ensure!(optlen == 8, Inval);
                let optval = virtual_memory.read(optval.cast::<Linger>())?;
                guard.linger = (optval.onoff != 0).then_some(optval.linger);
                Ok(())
            }
            (1, 15) => {
                // SO_REUSEPORT
                ensure!(optlen == 4, Inval);
                let optval = virtual_memory.read(optval.cast::<i32>())? != 0;
                guard.reuse_port = optval;
                Ok(())
            }
            (6, 1) => {
                // TCP_NODELAY
                ensure!(optlen == 4, Inval);
                let optval = virtual_memory.read(optval.cast::<i32>())? != 0;
                guard.no_delay = optval;
                Ok(())
            }
            (6, 4) => {
                // TCP_KEEPIDLE
                Ok(())
            }
            (6, 5) => {
                // TCP_KEEPINTVL
                Ok(())
            }
            (6, 6) => {
                // TCP_KEEPCNT
                Ok(())
            }
            _ => bail!(Inval),
        }
    }

    fn shutdown(&self, how: ShutdownHow) -> Result<()> {
        let bound = self.bound_socket.get().ok_or(err!(NotConn))?;
        let mode = bound.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn)
        };
        match how {
            ShutdownHow::Rd => active.read_half.shutdown(),
            ShutdownHow::Wr => active.write_half.shutdown(),
            ShutdownHow::RdWr => {
                active.read_half.shutdown();
                active.write_half.shutdown();
            }
        }
        Ok(())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let bound = self.bound_socket.get().ok_or(err!(NotConn))?;
        let mode = bound.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active.read_half.read(buf)
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let bound = self.bound_socket.get().ok_or(err!(NotConn))?;
        let mode = bound.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active.read_half.read_to_user(vm, pointer, len)
    }

    fn recv_from(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
        flags: RecvFromFlags,
    ) -> Result<usize> {
        let bound = self.bound_socket.get().ok_or(err!(NotConn))?;
        let mode = bound.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        if flags.contains(RecvFromFlags::OOB) {
            let oob_data = active.read_half.read_oob()?;
            if len != 0 {
                vm.write(pointer.cast(), oob_data)?;
                Ok(1)
            } else {
                Ok(0)
            }
        } else {
            active.read_half.read_to_user(vm, pointer, len)
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let bound = self.bound_socket.get().ok_or(err!(NotConn))?;
        let mode = bound.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active.write_half.write(buf)
    }

    fn write_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let bound = self.bound_socket.get().ok_or(err!(NotConn))?;
        let mode = bound.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active.write_half.write_from_user(vm, pointer, len)
    }

    fn send_to(
        &self,
        vm: &VirtualMemory,
        buf: Pointer<[u8]>,
        len: usize,
        flags: SentToFlags,
        addr: Pointer<SocketAddr>,
        _addrlen: usize,
    ) -> Result<usize> {
        ensure!(addr.is_null(), IsConn);

        let bound = self.bound_socket.get().ok_or(err!(NotConn))?;
        let mode = bound.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active
            .write_half
            .send_from_user(vm, buf, len, flags.contains(SentToFlags::OOB))
    }

    fn path(&self) -> Result<Path> {
        todo!()
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        todo!()
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
        todo!()
    }

    fn poll_ready(&self, events: Events) -> Events {
        let Some(bound) = self.bound_socket.get() else {
            return Events::empty();
        };
        let Some(mode) = bound.mode.get() else {
            return Events::empty();
        };
        match mode {
            Mode::Passive(passive_tcp_socket) => {
                let mut events = events & Events::READ;
                if events.contains(Events::READ)
                    && passive_tcp_socket.internal.lock().queue.is_empty()
                {
                    events.remove(Events::READ);
                }
                events
            }
            Mode::Active(active_tcp_socket) => {
                active_tcp_socket.read_half.poll_ready(events)
                    | active_tcp_socket.write_half.poll_ready(events)
            }
        }
    }

    fn epoll_ready(&self, events: Events) -> Result<Events> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        let mode = loop {
            let wait = self.activate_notify.wait();
            if let Some(bound) = self.bound_socket.get() {
                if let Some(mode) = bound.mode.get() {
                    break mode;
                }
            }
            wait.await;
        };
        match mode {
            Mode::Passive(passive_tcp_socket) => {
                if !events.contains(Events::READ) {
                    return core::future::pending().await;
                }
                loop {
                    let wait = passive_tcp_socket.notify.wait();
                    let guard = passive_tcp_socket.internal.lock();
                    if !guard.queue.is_empty() {
                        return Ok(Events::READ);
                    }
                    drop(guard);
                    wait.await;
                }
            }
            Mode::Active(active_tcp_socket) => loop {
                let wait_read = async {
                    loop {
                        let wait = active_tcp_socket.read_half.wait();
                        if !active_tcp_socket.read_half.poll_ready(events).is_empty() {
                            break;
                        }
                        wait.await;
                    }
                };
                let wait_write = async {
                    loop {
                        let wait = active_tcp_socket.write_half.wait();
                        if !active_tcp_socket.write_half.poll_ready(events).is_empty() {
                            break;
                        }
                        wait.await;
                    }
                };
                let wait_read = pin!(wait_read);
                let wait_write = pin!(wait_write);
                futures::future::select(wait_read, wait_write).await;
                let events = active_tcp_socket.read_half.poll_ready(events)
                    | active_tcp_socket.write_half.poll_ready(events);
                if !events.is_empty() {
                    return Ok(events);
                }
            },
        }
    }

    fn ioctl(&self, virtual_memory: &VirtualMemory, cmd: u32, arg: Pointer<c_void>) -> Result<u64> {
        match cmd {
            0x8905 => {
                // SIOCATMARK
                let at_mark = self
                    .bound_socket
                    .get()
                    .and_then(|socket| socket.mode.get())
                    .map(|mode| {
                        if let Mode::Active(active) = mode {
                            active.read_half.at_mark()
                        } else {
                            false
                        }
                    })
                    .unwrap_or_default();
                virtual_memory.write(arg.cast(), u32::from(at_mark))?;
                Ok(0)
            }
            _ => common_ioctl(self, virtual_memory, cmd, arg),
        }
    }

    fn file_lock(&self) -> Result<&FileLock> {
        todo!()
    }
}

impl Drop for TcpSocket {
    fn drop(&mut self) {
        let Some(bound) = self.bound_socket.get() else {
            return;
        };
        let linger = self.internal.get_mut().linger.unwrap_or(60);

        // When linger is 0, we skip the normal shutdown procedure and
        // immediately disconnect the socket.
        if linger == 0 {
            return;
        }

        let now = now(ClockId::Monotonic);
        let deadline = now.saturating_add(Timespec {
            tv_sec: linger,
            tv_nsec: 0,
        });

        let Some(mode) = bound.mode.get() else {
            return;
        };

        let Mode::Active(active_tcp_socket) = mode else {
            return;
        };

        active_tcp_socket.read_half.shutdown();
        active_tcp_socket.write_half.shutdown();

        // Keep the socket alive until the deadline.
        let mode = bound.mode.clone();
        rt::spawn(async move {
            sleep_until(deadline, ClockId::Monotonic).await;
            drop(mode);
        });
    }
}

struct BoundSocket {
    bind_addr: SocketAddrV4,
    reuse_addr: bool,
    reuse_port: bool,
    connect_notify: NotifyOnDrop,
    mode: Arc<Once<Mode>>,
}

enum Mode {
    Passive(PassiveTcpSocket),
    Active(ActiveTcpSocket),
}

struct PassiveTcpSocket {
    notify: Arc<Notify>,
    internal: Mutex<PassiveTcpSocketInternal>,
}

struct PassiveTcpSocketInternal {
    backlog: usize,
    queue: VecDeque<ActiveTcpSocket>,
}

impl PassiveTcpSocket {
    pub fn prepare_connect(&self) -> Option<ConnectGuard> {
        let guard = self.internal.lock();
        (guard.queue.len() < guard.backlog).then(|| ConnectGuard {
            passive_socket: self,
            guard,
        })
    }
}

struct ConnectGuard<'a> {
    passive_socket: &'a PassiveTcpSocket,
    guard: MutexGuard<'a, PassiveTcpSocketInternal>,
}

impl ConnectGuard<'_> {
    pub fn connect(mut self, socket: ActiveTcpSocket) {
        if self.guard.queue.is_empty() {
            self.passive_socket.notify.notify();
        }
        self.guard.queue.push_back(socket);
    }
}

struct ActiveTcpSocket {
    local_addr: SocketAddrV4,
    remote_addr: SocketAddrV4,
    read_half: stream_buffer::ReadHalf,
    write_half: stream_buffer::WriteHalf,
}

impl ActiveTcpSocket {
    fn new_pair(local_addr: SocketAddrV4, remote_addr: SocketAddrV4) -> (Self, Self) {
        let (rx1, tx1) = stream_buffer::new(0x200000, stream_buffer::Type::Socket);
        let (rx2, tx2) = stream_buffer::new(0x200000, stream_buffer::Type::Socket);
        (
            Self {
                local_addr,
                remote_addr,
                read_half: rx1,
                write_half: tx2,
            },
            Self {
                local_addr: remote_addr,
                remote_addr: local_addr,
                read_half: rx2,
                write_half: tx1,
            },
        )
    }
}
