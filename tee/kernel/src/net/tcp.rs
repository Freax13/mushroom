use core::{
    net::{Ipv4Addr, SocketAddrV4},
    ops::Bound,
    pin::pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
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
    error::{bail, ensure, err, Result},
    fs::{
        fd::{stream_buffer, Events, FileDescriptor, FileLock, OpenFileDescription},
        node::FileAccessContext,
        path::Path,
        FileSystem,
    },
    rt::notify::{Notify, NotifyOnDrop},
    spin::{mutex::Mutex, once::Once, rwlock::RwLock},
    user::process::{
        memory::VirtualMemory,
        syscall::{
            args::{
                Accept4Flags, FileMode, OpenFlags, Pointer, ShutdownHow, SocketAddr,
                SocketAddrInet, SocketTypeWithFlags, Stat,
            },
            traits::Abi,
        },
        thread::{Gid, Uid},
    },
};

// TODO: Periodically clean up closed TCP sockets.
static TCP_SOCKETS: RwLock<BTreeMap<SocketAddrV4, Weak<BoundSocket>>> =
    RwLock::new(BTreeMap::new());

pub struct TcpSocket {
    flags: OpenFlags,
    reuse_addr: AtomicBool,
    bound_socket: Once<Arc<BoundSocket>>,
}

impl TcpSocket {
    pub fn new(r#type: SocketTypeWithFlags) -> Self {
        Self {
            flags: r#type.flags,
            reuse_addr: AtomicBool::new(false),
            bound_socket: Once::new(),
        }
    }

    /// Try to bind the socket to an address. Returns `true` if the socket was
    /// bound, returns `false` if the socket was already bound. Returns
    /// `Err(..)` if the socket could not be bound to the given address.
    fn try_bind(&self, addr: SocketAddrInet) -> Result<bool> {
        let allow_reuse = self.reuse_addr.load(Ordering::Relaxed);

        let mut guard = TCP_SOCKETS.write();
        let ip = Ipv4Addr::new(addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3]);

        let socket_addr;
        let mut cursor;

        if addr.port == 0 {
            // Pick a port.
            const EPHEMERAL_PORT_START: u16 = 32768;
            const EPHEMERAL_PORT_END: u16 = 60999;

            cursor =
                guard.upper_bound_mut(Bound::Included(&SocketAddrV4::new(ip, EPHEMERAL_PORT_END)));
            if let Some((prev, _)) = cursor.peek_prev().filter(|(prev, _)| *prev.ip() == ip) {
                // A port has already been bound on IP. Pick the highest
                // available port and make sure that it doesn't exceed the end
                // of the range.
                let port = prev
                    .port()
                    .checked_add(1)
                    .filter(|port| *port <= EPHEMERAL_PORT_END)
                    .ok_or_else(|| err!(AddrInUse))?;
                socket_addr = SocketAddrV4::new(ip, port);
            } else {
                // No ports <DYNAMIC_PORT_START have been bound on IP. Pick the
                // first one.
                socket_addr = SocketAddrV4::new(ip, EPHEMERAL_PORT_START);
            }
        } else {
            // Make sure that the port is not already in use.
            socket_addr = SocketAddrV4::new(ip, addr.port);
            cursor = guard.upper_bound_mut(Bound::Included(&socket_addr));
            if let Some((prev, socket)) = cursor.peek_prev() {
                // If there's already a socket bound to the given address,
                // check that the socket is still alive and whether reusing is
                // allowed.
                if *prev == socket_addr {
                    if let Some(socket) = socket.upgrade() {
                        ensure!(allow_reuse, AddrInUse);
                        ensure!(socket.allow_reuse, AddrInUse);
                        let mut initialized = false;
                        self.bound_socket.call_once(|| {
                            initialized = true;
                            socket
                        });
                        return Ok(!initialized);
                    } else {
                        // The socket is no longer alive. Remove the weak
                        // reference and pretend that it was never there.
                        cursor.remove_prev();
                    }
                }
            }
        }

        let mut initialized = false;
        let bound = self.bound_socket.call_once(|| {
            initialized = true;

            let addr = SocketAddrV4::new(
                Ipv4Addr::new(addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3]),
                addr.port,
            );

            Arc::new(BoundSocket {
                allow_reuse,
                addr,
                mode: Once::new(),
            })
        });
        if !initialized {
            return Ok(false);
        }

        cursor
            .insert_after(socket_addr, Arc::downgrade(bound))
            .unwrap();

        drop(guard);

        Ok(true)
    }

    fn get_or_bind_ephemeral(&self) -> Result<&BoundSocket> {
        self.try_bind(SocketAddrInet {
            port: 0,
            addr: [0, 0, 0, 0],
            _pad: [0; 8],
        })?;
        Ok(self.bound_socket.get().unwrap())
    }
}

#[async_trait]
impl OpenFileDescription for TcpSocket {
    fn flags(&self) -> OpenFlags {
        self.flags
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

    fn listen(&self, backlog: usize) -> Result<()> {
        let bound = self.get_or_bind_ephemeral()?;
        let mode = bound.mode.call_once(|| {
            Mode::Passive(PassiveTcpSocket {
                backlog: AtomicUsize::new(backlog),
                notify: NotifyOnDrop(Arc::new(Notify::new())),
                queue: Mutex::new(VecDeque::new()),
            })
        });
        let Mode::Passive(passive) = mode else {
            bail!(IsConn);
        };
        // TODO: Is the max op correct?
        let old_backlock = passive.backlog.fetch_max(backlog, Ordering::Relaxed);
        if old_backlock < backlog {
            passive.notify.notify();
        }
        Ok(())
    }

    fn accept(&self, flags: Accept4Flags) -> Result<(FileDescriptor, Vec<u8>)> {
        let bound = self.bound_socket.get().ok_or_else(|| err!(Inval))?;
        let mode = bound.mode.get().ok_or_else(|| err!(Inval))?;
        let Mode::Passive(passive) = mode else {
            bail!(Inval);
        };
        let active = passive
            .queue
            .lock()
            .pop_front()
            .ok_or_else(|| err!(Again))?;
        passive.notify.notify();
        let remote_addr = active.remote_addr;

        let socket = Self {
            flags: OpenFlags::from(flags),
            reuse_addr: AtomicBool::new(self.reuse_addr.load(Ordering::Relaxed)),
            bound_socket: Once::with_value(Arc::new(BoundSocket {
                allow_reuse: false,
                addr: bound.addr,
                mode: Once::with_value(Mode::Active(active)),
            })),
        };
        let fd = FileDescriptor::from(socket);

        let socket_addr = SocketAddr::Inet(SocketAddrInet {
            port: remote_addr.port(),
            addr: remote_addr.ip().octets(),
            _pad: [0; 8],
        });
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
        let remote_addr = SocketAddrV4::new(
            Ipv4Addr::new(
                remote_addr.addr[0],
                remote_addr.addr[1],
                remote_addr.addr[2],
                remote_addr.addr[3],
            ),
            remote_addr.port,
        );

        loop {
            let sockets_guard = TCP_SOCKETS.read();
            let remote_socket = sockets_guard
                .get(&remote_addr)
                .and_then(Weak::upgrade)
                .ok_or_else(|| err!(ConnRefused))?;
            let mode = remote_socket.mode.get().ok_or_else(|| err!(ConnRefused))?;
            let Mode::Passive(passive) = mode else {
                bail!(ConnRefused);
            };
            let mut queue_guard = passive.queue.lock();

            // Check if the socket is ready to acept a new connection.
            let backlog = passive.backlog.load(Ordering::Relaxed);
            if queue_guard.len() >= backlog {
                // If not, drop all logs and wait for a notification.

                drop(queue_guard);

                let notify = passive.notify.0.clone();
                let wait = notify.wait();

                drop(remote_socket);
                drop(sockets_guard);

                wait.await;
                continue;
            }

            let mut initialized = false;
            bound.mode.call_once(|| {
                initialized = true;

                let (socket1, socket2) = ActiveTcpSocket::new_pair(bound.addr, remote_addr);
                queue_guard.push_back(socket2);

                Mode::Active(socket1)
            });
            drop(queue_guard);
            ensure!(initialized, IsConn);

            passive.notify.notify();

            return Ok(());
        }
    }

    fn get_socket_option(&self, abi: Abi, level: i32, optname: i32) -> Result<Vec<u8>> {
        match (level, optname) {
            (1, 4) => Ok(0u32.to_ne_bytes().to_vec()), // SO_ERROR
            _ => bail!(Inval),
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
            (1, 2) => {
                // SO_REUSEADDR
                ensure!(optlen == 4, Inval);
                let optval = virtual_memory.read(optval.cast::<i32>())? != 0;
                self.reuse_addr.store(optval, Ordering::Relaxed);
                Ok(())
            }
            _ => bail!(Inval),
        }
    }

    fn shutdown(&self, how: ShutdownHow) -> Result<()> {
        let bound = self.bound_socket.get().ok_or_else(|| err!(NotConn))?;
        let mode = bound.mode.get().ok_or_else(|| err!(NotConn))?;
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
        let bound = self.bound_socket.get().ok_or_else(|| err!(NotConn))?;
        let mode = bound.mode.get().ok_or_else(|| err!(NotConn))?;
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
        let bound = self.bound_socket.get().ok_or_else(|| err!(NotConn))?;
        let mode = bound.mode.get().ok_or_else(|| err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active.read_half.read_to_user(vm, pointer, len)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let bound = self.bound_socket.get().ok_or_else(|| err!(NotConn))?;
        let mode = bound.mode.get().ok_or_else(|| err!(NotConn))?;
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
        let bound = self.bound_socket.get().ok_or_else(|| err!(NotConn))?;
        let mode = bound.mode.get().ok_or_else(|| err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active.write_half.write_from_user(vm, pointer, len)
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
        todo!()
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
                if events.contains(Events::READ) && passive_tcp_socket.queue.lock().is_empty() {
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
        let bound = self.bound_socket.get().expect("TODO");
        let mode = bound.mode.get().expect("TODO");
        match mode {
            Mode::Passive(passive_tcp_socket) => {
                if !events.contains(Events::READ) {
                    return core::future::pending().await;
                }
                loop {
                    let wait = passive_tcp_socket.notify.wait();
                    let guard = passive_tcp_socket.queue.lock();
                    if !guard.is_empty() {
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

    fn file_lock(&self) -> Result<&FileLock> {
        todo!()
    }
}

struct BoundSocket {
    allow_reuse: bool,
    addr: SocketAddrV4,
    mode: Once<Mode>,
}

enum Mode {
    Passive(PassiveTcpSocket),
    Active(ActiveTcpSocket),
}

struct PassiveTcpSocket {
    backlog: AtomicUsize,
    notify: NotifyOnDrop,
    queue: Mutex<VecDeque<ActiveTcpSocket>>,
}

struct ActiveTcpSocket {
    remote_addr: SocketAddrV4,
    read_half: stream_buffer::ReadHalf,
    write_half: stream_buffer::WriteHalf,
}

impl ActiveTcpSocket {
    fn new_pair(local_addr: SocketAddrV4, remote_addr: SocketAddrV4) -> (Self, Self) {
        let (rx1, tx1) = stream_buffer::new(0x10000, stream_buffer::Type::Socket);
        let (rx2, tx2) = stream_buffer::new(0x10000, stream_buffer::Type::Socket);
        (
            Self {
                remote_addr,
                read_half: rx1,
                write_half: tx2,
            },
            Self {
                remote_addr: local_addr,
                read_half: rx2,
                write_half: tx1,
            },
        )
    }
}
