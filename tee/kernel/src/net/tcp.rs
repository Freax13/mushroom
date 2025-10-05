use alloc::{
    boxed::Box,
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    format,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    cmp,
    ffi::c_void,
    net::{self, IpAddr},
    ops::Not,
};

use async_trait::async_trait;
use usize_conversions::usize_from;

use crate::{
    error::{Result, bail, ensure, err},
    fs::{
        FileSystem,
        fd::{
            BsdFileLock, BsdFileLockRecord, Events, FileDescriptorTable, LazyBsdFileLockRecord,
            LazyUnixFileLockRecord, NonEmptyEvents, OpenFileDescription, ReadBuf,
            StrongFileDescriptor, UnixFileLockRecord, VectoredUserBuf, WriteBuf, common_ioctl,
            file::{File, open_file},
            inotify::Watchers,
            stream_buffer,
        },
        node::{FileAccessContext, INode, LinkLocation, new_ino, procfs::ProcFs},
        ownership::Ownership,
        path::Path,
    },
    memory::page::KernelPage,
    net::IpVersion,
    rt::{
        self,
        notify::{Notify, NotifyOnDrop},
    },
    spin::{
        mutex::{Mutex, MutexGuard},
        once::Once,
    },
    time::{now, sleep_until},
    user::{
        memory::{VirtualMemory, WriteToVec},
        process::limits::CurrentNoFileLimit,
        syscall::{
            args::{
                Accept4Flags, ClockId, FallocateMode, FileMode, FileType, FileTypeAndMode, Linger,
                MsgHdr, OpenFlags, Pointer, RecvFromFlags, SendMsgFlags, SentToFlags, ShutdownHow,
                SocketAddr, SocketType, SocketTypeWithFlags, Stat, Timespec,
            },
            traits::Abi,
        },
        thread::{Gid, ThreadGuard, Uid},
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
        ip: IpAddr,
        ephemeral: bool,
        reuse_addr: bool,
        reuse_port: bool,
        v6only: bool,
        effective_uid: Uid,
    ) -> Result<BindGuard<'_>> {
        let ip_version = IpVersion::from(ip);
        let local_ip = ip.is_unspecified().not().then_some(ip);

        let mut i = 0;
        while let Some(entry) = self.entries.get(i) {
            i += 1;
            // Skip (and remove) entries whose sockets are no longer live.
            let Some(mode) = entry.mode.upgrade() else {
                i -= 1;
                self.entries.swap_remove(i);
                continue;
            };

            ensure!(!ephemeral, AddrInUse);

            // Skip entries with a different address family.
            match (entry.ip_version, ip_version) {
                (IpVersion::V4, IpVersion::V4) => {}
                (IpVersion::V4, IpVersion::V6) => {
                    if v6only {
                        continue;
                    }
                }
                (IpVersion::V6, IpVersion::V4) => {
                    if entry.v6only {
                        continue;
                    }
                }
                (IpVersion::V6, IpVersion::V6) => {}
            }

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
            ip_version,
            local_ip,
            reuse_addr,
            reuse_port,
            v6only,
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
            // Ignore sockets with a different ip version.
            .filter(|entry| entry.ip_version == socket_entry.ip_version)
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
    ip_version: IpVersion,
    local_ip: Option<IpAddr>,
    reuse_addr: bool,
    reuse_port: bool,
    v6only: bool,
    effective_uid: Uid,
}

impl BindGuard<'_> {
    pub fn bind(self, mode: Weak<Once<Mode>>, ino: u64) {
        self.port_data.entries.push(PortDataEntry {
            ino,
            ip_version: self.ip_version,
            local_ip: self.local_ip,
            remote_addr: None,
            reuse_addr: self.reuse_addr,
            reuse_port: self.reuse_port,
            v6only: self.v6only,
            effective_uid: self.effective_uid,
            mode,
        });
    }
}

struct PortDataEntry {
    ino: u64,
    ip_version: IpVersion,
    local_ip: Option<IpAddr>,
    remote_addr: Option<net::SocketAddr>,
    reuse_addr: bool,
    reuse_port: bool,
    v6only: bool,
    effective_uid: Uid,
    mode: Weak<Once<Mode>>,
}

const EPHEMERAL_PORT_START: u16 = 32768;
const EPHEMERAL_PORT_END: u16 = 60999;

pub struct TcpSocket {
    ino: u64,
    ip_version: IpVersion,
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
    receive_buffer_size: usize,
    no_delay: bool,
    linger: Option<i32>,
    v6only: bool,
}

impl TcpSocket {
    pub fn new(ip_version: IpVersion, r#type: SocketTypeWithFlags, uid: Uid, gid: Gid) -> Self {
        Self {
            ino: new_ino(),
            ip_version,
            internal: Mutex::new(TcpSocketInternal {
                flags: r#type.flags,
                ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
                reuse_addr: false,
                reuse_port: false,
                send_buffer_size: 1024 * 1024,
                receive_buffer_size: 1024 * 1024,
                no_delay: false,
                linger: None,
                v6only: false,
            }),
            activate_notify: Notify::new(),
            bound_socket: Once::new(),
        }
    }

    /// Try to bind the socket to an address. Returns `true` if the socket was
    /// bound, returns `false` if the socket was already bound. Returns
    /// `Err(..)` if the socket could not be bound to the given address.
    fn try_bind(&self, mut socket_addr: net::SocketAddr, ctx: &FileAccessContext) -> Result<bool> {
        ensure!(IpVersion::from(socket_addr.ip()) == self.ip_version, Inval);

        // We only support binding to localhost -> make sure that the
        // address is a loopback address.
        ensure!(
            socket_addr.ip().is_unspecified() || socket_addr.ip().is_loopback(),
            AddrNotAvail
        );

        // Make sure that the user has permission to bind the port.
        ensure!(
            socket_addr.port() == 0 || socket_addr.port() >= 1024 || ctx.is_user(Uid::SUPER_USER),
            Acces
        );

        let guard = self.internal.lock();
        let reuse_addr = guard.reuse_addr;
        let reuse_port = guard.reuse_port;
        let v6only = guard.v6only;
        drop(guard);

        let effective_uid = Uid::SUPER_USER; // TODO

        let mut guard = PORTS.lock();

        // Prepare a bind guard.
        let bind_guard = if socket_addr.port() == 0 {
            'port: {
                // If no port has been specified, try to find one that can be
                // bound to.
                for port in EPHEMERAL_PORT_START..=EPHEMERAL_PORT_END {
                    let entry = guard.entry(port).or_default();
                    if let Ok(bind_guard) = entry.prepare_bind(
                        socket_addr.ip(),
                        true,
                        reuse_addr,
                        reuse_port,
                        v6only,
                        effective_uid,
                    ) {
                        socket_addr.set_port(port);
                        break 'port bind_guard;
                    }
                }
                // If we can't find a port, fail.
                bail!(AddrInUse)
            }
        } else {
            guard.entry(socket_addr.port()).or_default().prepare_bind(
                socket_addr.ip(),
                false,
                reuse_addr,
                reuse_port,
                v6only,
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
        bind_guard.bind(Arc::downgrade(&bound.mode), self.ino);

        Ok(true)
    }

    fn get_or_bind_ephemeral(&self, ctx: &FileAccessContext) -> Result<&BoundSocket> {
        self.try_bind(self.ip_version.unspecified_addr(), ctx)?;
        Ok(self.bound_socket.get().unwrap())
    }
}

#[async_trait]
impl OpenFileDescription for TcpSocket {
    fn flags(&self) -> OpenFlags {
        self.internal.lock().flags
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
        let addr = net::SocketAddr::try_from(addr)?;
        ensure!(self.try_bind(addr, ctx)?, Inval);
        Ok(())
    }

    fn get_socket_name(&self) -> Result<SocketAddr> {
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
            .unwrap_or_else(|| self.ip_version.unspecified_addr());
        Ok(SocketAddr::from(addr))
    }

    fn get_peer_name(&self) -> Result<SocketAddr> {
        let socket = self.bound_socket.get().ok_or(err!(NotConn))?;
        let mode = socket.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        Ok(SocketAddr::from(active.remote_addr))
    }

    fn listen(&self, backlog: usize, ctx: &FileAccessContext) -> Result<()> {
        // Make sure that the backlog is never empty.
        let backlog = cmp::max(backlog, 1);

        let bound = self.get_or_bind_ephemeral(ctx)?;

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

    fn accept(&self, flags: Accept4Flags) -> Result<(StrongFileDescriptor, SocketAddr)> {
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
            ip_version: self.ip_version,
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
        let fd = StrongFileDescriptor::from(socket);

        let socket_addr = SocketAddr::from(remote_addr);

        Ok((fd, socket_addr))
    }

    async fn connect(&self, addr: SocketAddr, ctx: &mut FileAccessContext) -> Result<()> {
        let v6only = self.internal.lock().v6only;

        let bound = self.get_or_bind_ephemeral(ctx)?;

        let remote_addr = net::SocketAddr::try_from(addr)?;

        let remote_ip = remote_addr.ip();
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
                    (i.wrapping_add(ports.round_robin_counter)) % ports.entries.len();
                i += 1;
                let entry = &ports.entries[offset_index];

                // Skip over entries that don't have a matching domain.
                match (entry.ip_version, self.ip_version) {
                    (IpVersion::V4, IpVersion::V4) => {} // matches
                    (IpVersion::V4, IpVersion::V6) => {
                        if v6only {
                            continue; // doesn't match
                        } else {
                            // matches
                        }
                    }
                    (IpVersion::V6, IpVersion::V4) => {
                        if entry.v6only {
                            continue; // doesn't match
                        } else {
                            // matches
                        }
                    }
                    (IpVersion::V6, IpVersion::V6) => {} // matches
                }

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
                    ip.is_unspecified().not().then_some(ip)
                });
                // If all of that fails, use localhost.
                let peer_ip = peer_ip.unwrap_or_else(|| self.ip_version.localhost_ip());
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
                    .then_some(bound.bind_addr.ip());
                // Otherwise use localhost.
                let local_ip = local_ip.unwrap_or_else(|| self.ip_version.localhost_ip());

                let server_ip_version = entry.ip_version;

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
                        let (client, server) = ActiveTcpSocket::new_pair(
                            net::SocketAddr::new(local_ip, bound.bind_addr.port()),
                            remote_addr,
                            server_ip_version,
                        );
                        connect_guard.connect(server);
                        Mode::Active(client)
                    })
                    .map_err(|_| err!(IsConn))?;
                self.activate_notify.notify();

                // Update the entry for this socket to reflect the IPs.
                let this_entry = ports
                    .entries
                    .iter_mut()
                    .find(|e| core::ptr::eq(e.mode.as_ptr(), Arc::as_ptr(&bound.mode)))
                    .unwrap();
                this_entry.local_ip = Some(local_ip);
                this_entry.remote_addr = Some(remote_addr);

                return Ok(());
            }
        }
    }

    fn get_socket_option(&self, _: Abi, level: i32, optname: i32) -> Result<Vec<u8>> {
        let guard = self.internal.lock();
        Ok(match (level, optname) {
            (1, 2) => {
                // SO_REUSEADDR
                let val = guard.reuse_addr as u32;
                val.to_ne_bytes().to_vec()
            }
            (1, 3) => {
                // SO_TYPE
                let ty = SocketType::Stream as u32;
                ty.to_le_bytes().to_vec()
            }
            (1, 4) => 0u32.to_ne_bytes().to_vec(), // SO_ERROR
            (1, 7) => {
                // SO_SNDBUF
                let val = guard.send_buffer_size as u32;
                val.to_ne_bytes().to_vec()
            }
            (1, 8) => {
                // SO_RCVBUF
                let val = guard.receive_buffer_size as u32;
                val.to_ne_bytes().to_vec()
            }
            _ => bail!(Inval),
        })
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
                let new_send_buffer_size = cmp::max(new_send_buffer_size, 2048); // 2048 is the minimum
                guard.send_buffer_size = new_send_buffer_size;
                if let Some(bound) = self.bound_socket.get()
                    && let Some(Mode::Active(active)) = bound.mode.get()
                {
                    active.write_half.set_buffer_capacity(new_send_buffer_size);
                }
                Ok(())
            }
            (1, 8) => {
                // SO_RCVBUF
                ensure!(optlen == 4, Inval);
                let optval = virtual_memory.read(optval.cast::<i32>())?;
                let new_receive_buffer_size = optval as usize * 2;
                let new_receive_buffer_size = cmp::max(new_receive_buffer_size, 2048); // 2048 is the minimum
                guard.receive_buffer_size = new_receive_buffer_size;
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
            (41, 26) => {
                // IPV6_V6ONLY
                ensure!(optlen == 4, Inval);
                ensure!(self.ip_version == IpVersion::V6, Inval);
                let optval = virtual_memory.read(optval.cast::<i32>())? != 0;
                guard.v6only = optval;
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

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        let bound = self.bound_socket.get().ok_or(err!(NotConn))?;
        let mode = bound.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active.read_half.read(buf, false)
    }

    fn recv_from(
        &self,
        buf: &mut dyn ReadBuf,
        flags: RecvFromFlags,
    ) -> Result<(usize, Option<SocketAddr>)> {
        let peek = flags.contains(RecvFromFlags::PEEK);

        let bound = self.bound_socket.get().ok_or(err!(NotConn))?;
        let mode = bound.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        let len = if flags.contains(RecvFromFlags::OOB) {
            let oob_data = active.read_half.read_oob(peek)?;
            if buf.buffer_len() != 0 {
                buf.write(0, &[oob_data])?;
                1
            } else {
                0
            }
        } else {
            active.read_half.read(buf, peek)?
        };
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
        let bound = self.bound_socket.get().ok_or(err!(NotConn))?;
        let mode = bound.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active.write_half.write(buf)
    }

    fn send_to(
        &self,
        buf: &dyn WriteBuf,
        flags: SentToFlags,
        addr: Option<SocketAddr>,
        _: &FileAccessContext,
    ) -> Result<usize> {
        ensure!(addr.is_none(), IsConn);

        let bound = self.bound_socket.get().ok_or(err!(NotConn))?;
        let mode = bound.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active
            .write_half
            .send(buf, flags.contains(SentToFlags::OOB))
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
        ensure!(!flags.contains(SendMsgFlags::FASTOPEN), OpNotSupp);

        if !msg_hdr.control.is_null() {
            todo!();
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

    fn path(&self) -> Result<Path> {
        Path::new(format!("socket:[{}]", self.ino).into_bytes())
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

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        let bound = self.bound_socket.get()?;
        let mode = bound.mode.get()?;
        match mode {
            Mode::Passive(passive_tcp_socket) => {
                let mut events = events & Events::READ;
                if events.contains(Events::READ)
                    && passive_tcp_socket.internal.lock().queue.is_empty()
                {
                    events.remove(Events::READ);
                }
                NonEmptyEvents::new(events)
            }
            Mode::Active(active_tcp_socket) => NonEmptyEvents::zip(
                active_tcp_socket.read_half.poll_ready(events),
                active_tcp_socket.write_half.poll_ready(events),
            ),
        }
    }

    fn epoll_ready(&self, events: Events) -> Result<Option<NonEmptyEvents>> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        let mode = loop {
            let wait = self.activate_notify.wait();
            if let Some(bound) = self.bound_socket.get()
                && let Some(mode) = bound.mode.get()
            {
                break mode;
            }
            wait.await;
        };
        match mode {
            Mode::Passive(passive_tcp_socket) => {
                if !events.contains(Events::READ) {
                    return core::future::pending().await;
                }
                passive_tcp_socket
                    .notify
                    .wait_until(|| {
                        passive_tcp_socket
                            .internal
                            .lock()
                            .queue
                            .is_empty()
                            .not()
                            .then_some(NonEmptyEvents::READ)
                    })
                    .await
            }
            Mode::Active(active_tcp_socket) => {
                let wait_read = async {
                    loop {
                        let wait = active_tcp_socket.read_half.wait();
                        if let Some(events) = active_tcp_socket.read_half.poll_ready(events) {
                            return events;
                        }
                        wait.await;
                    }
                };
                let wait_write = async {
                    loop {
                        let wait = active_tcp_socket.write_half.wait();
                        if let Some(events) = active_tcp_socket.write_half.poll_ready(events) {
                            return events;
                        }
                        wait.await;
                    }
                };
                NonEmptyEvents::select(wait_read, wait_write).await
            }
        }
    }

    fn ioctl(
        &self,
        thread: &mut ThreadGuard,
        cmd: u32,
        arg: Pointer<c_void>,
        abi: Abi,
    ) -> Result<u64> {
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
                thread
                    .virtual_memory()
                    .write(arg.cast(), u32::from(at_mark))?;
                Ok(0)
            }
            _ => common_ioctl(self, thread, cmd, arg, abi),
        }
    }

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
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
    bind_addr: net::SocketAddr,
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
    pub fn prepare_connect(&self) -> Option<ConnectGuard<'_>> {
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
    local_addr: net::SocketAddr,
    remote_addr: net::SocketAddr,
    read_half: stream_buffer::ReadHalf,
    write_half: stream_buffer::WriteHalf,
}

impl ActiveTcpSocket {
    fn new_pair(
        local_addr: net::SocketAddr,
        remote_addr: net::SocketAddr,
        server_domain: IpVersion,
    ) -> (Self, Self) {
        let (rx1, tx1) = stream_buffer::new(0x200000, stream_buffer::Type::Socket);
        let (rx2, tx2) = stream_buffer::new(0x200000, stream_buffer::Type::Socket);

        let client_local_addr = local_addr;
        let client_remote_addr = remote_addr;

        let mut server_local_addr = remote_addr;
        let mut server_remote_addr = local_addr;
        // The server might be a Ipv6 socket. If that's the case, we need to
        // make sure that ip addresses are also ipv6 ones.
        if server_domain == IpVersion::V6
            && let net::SocketAddr::V4(addr) = server_local_addr
        {
            server_local_addr =
                net::SocketAddr::new(IpAddr::V6(addr.ip().to_ipv6_mapped()), addr.port());
        }
        if server_domain == IpVersion::V6
            && let net::SocketAddr::V4(addr) = server_remote_addr
        {
            server_remote_addr =
                net::SocketAddr::new(IpAddr::V6(addr.ip().to_ipv6_mapped()), addr.port());
        }

        (
            Self {
                local_addr: client_local_addr,
                remote_addr: client_remote_addr,
                read_half: rx1,
                write_half: tx2,
            },
            Self {
                local_addr: server_local_addr,
                remote_addr: server_remote_addr,
                read_half: rx2,
                write_half: tx1,
            },
        )
    }
}

pub struct NetTcpFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    pub ino: u64,
    ip_version: IpVersion,
    bsd_file_lock_record: LazyBsdFileLockRecord,
    unix_file_lock_record: LazyUnixFileLockRecord,
    watchers: Watchers,
}

impl NetTcpFile {
    pub fn new(fs: Arc<ProcFs>, ip_version: IpVersion) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            fs,
            ino: new_ino(),
            ip_version,
            bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            unix_file_lock_record: LazyUnixFileLockRecord::new(),
            watchers: Watchers::new(),
        })
    }

    fn content(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        match self.ip_version {
            IpVersion::V4 => {
                writeln!(
                    buffer,
                    "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
                ).unwrap();
            }
            IpVersion::V6 => {
                writeln!(
                    buffer,
                    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
                ).unwrap();
            }
        }

        // ipv4:
        //   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
        //    0: 0100007F:16B3 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2239468 1 ffff8d0cdb1f5f00 100 0 0 10 0
        //
        // ipv6:
        //   sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
        //    0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3928 1 0000000000000000 100 0 0 10 0

        let guard = PORTS.lock();
        for (i, (local_port, data)) in guard.iter().enumerate() {
            for entry in data
                .entries
                .iter()
                .filter(|entry| entry.ip_version == self.ip_version)
            {
                let Some(mode) = entry.mode.upgrade() else {
                    continue;
                };
                let Some(mode) = mode.get() else {
                    // TODO: Should we still generate an entry?
                    continue;
                };

                let local_ip = entry
                    .local_ip
                    .unwrap_or_else(|| self.ip_version.unspecified_ip());
                let remote_addr = entry
                    .remote_addr
                    .unwrap_or_else(|| self.ip_version.unspecified_addr());
                let remote_ip = remote_addr.ip();
                let remote_port = remote_addr.port();

                // TODO: There are probably more status'.
                let status: u8 = match mode {
                    Mode::Active(_) => 0x01,
                    Mode::Passive(_) => 0x0a,
                };

                let tx_queue = 0u32;
                let rx_queue = 0u32;
                let tr = 0u8;
                let tm_when = 0u32;
                let retransmit = 0u32;
                let uid = entry.effective_uid.get();
                let timeout = 0u32;
                let ino = entry.ino;

                write!(buffer, "{i:>4}: ").unwrap();
                for octet in local_ip.as_octets().iter().copied().rev() {
                    write!(buffer, "{octet:02X}").unwrap();
                }
                write!(buffer, ":{local_port:04X} ").unwrap();
                for octet in remote_ip.as_octets().iter().copied().rev() {
                    write!(buffer, "{octet:02X}").unwrap();
                }
                writeln!(
                    buffer,
                    ":{remote_port:04X} {status:02X} {tx_queue:08X}:{rx_queue:08X} {tr:02X}:{tm_when:08X} {retransmit:08X}  {uid:04X} {timeout:>8} {ino} 1 ffff8d0cdb1f5f00 100 0 0 10 0"
                ).unwrap();
            }
        }

        buffer
    }
}

impl INode for NetTcpFile {
    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: self.fs.dev(),
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::File, FileMode::from_bits_retain(0o444)),
            uid: Uid::SUPER_USER,
            gid: Gid::SUPER_USER,
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
        Ok(self.fs.clone())
    }

    fn open(
        &self,
        location: LinkLocation,
        flags: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        open_file(self.this.upgrade().unwrap(), location, flags)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn truncate(&self, _length: usize, _: &FileAccessContext) -> Result<()> {
        bail!(Acces)
    }

    fn bsd_file_lock_record(&self) -> &Arc<BsdFileLockRecord> {
        self.bsd_file_lock_record.get()
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl File for NetTcpFile {
    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, offset: usize, buf: &mut dyn ReadBuf, _no_atime: bool) -> Result<usize> {
        let content = self.content();
        let offset = cmp::min(offset, content.len());
        let content = &content[offset..];
        let len = cmp::min(content.len(), buf.buffer_len());
        buf.write(0, &content[..len])?;
        Ok(len)
    }

    fn write(&self, _offset: usize, _buf: &dyn WriteBuf, _: &FileAccessContext) -> Result<usize> {
        bail!(Acces)
    }

    fn append(&self, _buf: &dyn WriteBuf, _: &FileAccessContext) -> Result<(usize, usize)> {
        bail!(Acces)
    }

    fn truncate(&self) -> Result<()> {
        bail!(Acces)
    }

    fn allocate(
        &self,
        _mode: FallocateMode,
        _offset: usize,
        _len: usize,
        _: &FileAccessContext,
    ) -> Result<()> {
        bail!(Acces)
    }

    fn deleted(&self) -> bool {
        false
    }

    fn unix_file_lock_record(&self) -> &Arc<UnixFileLockRecord> {
        self.unix_file_lock_record.get()
    }
}
