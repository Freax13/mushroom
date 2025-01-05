use core::{
    net::{Ipv4Addr, SocketAddrV4},
    ops::Bound,
    sync::atomic::{AtomicUsize, Ordering},
};

use alloc::{
    boxed::Box,
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    sync::{Arc, Weak},
};
use async_trait::async_trait;

use crate::{
    error::{bail, ensure, err, Result},
    fs::{
        fd::{Events, FileLock, OpenFileDescription},
        node::FileAccessContext,
        path::Path,
        FileSystem,
    },
    rt::notify::Notify,
    spin::{mutex::Mutex, once::Once, rwlock::RwLock},
    user::process::{
        memory::VirtualMemory,
        syscall::args::{
            FileMode, OpenFlags, Pointer, SocketAddr, SocketAddrInet, SocketTypeWithFlags, Stat,
        },
        thread::{Gid, Uid},
    },
};

// TODO: Periodically clean up closed TCP sockets.
static TCP_SOCKETS: RwLock<BTreeMap<SocketAddrV4, Weak<TcpSocket>>> = RwLock::new(BTreeMap::new());

pub struct TcpSocket {
    this: Weak<Self>,
    flags: OpenFlags,
    addr: Once<SocketAddrV4>,
    mode: Once<Mode>,
}

impl TcpSocket {
    pub fn new(r#type: SocketTypeWithFlags) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            flags: r#type.flags,
            addr: Once::new(),
            mode: Once::new(),
        })
    }

    /// Try to bind the socket to an address. Returns `true` if the socket was
    /// bound, returns `false` if the socket was already bound. Returns
    /// `Err(..)` if the socket could not be bound to the given address.
    fn try_bind(&self, addr: SocketAddrInet) -> Result<bool> {
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
            if let Some((prev, _)) = cursor.peek_prev() {
                ensure!(*prev != socket_addr, AddrInUse);
            }
        }

        let mut initialized = false;
        self.addr.call_once(|| {
            initialized = true;

            SocketAddrV4::new(
                Ipv4Addr::new(addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3]),
                addr.port,
            )
        });
        if !initialized {
            return Ok(false);
        }

        cursor.insert_after(socket_addr, self.this.clone()).unwrap();

        drop(guard);

        Ok(true)
    }

    fn addr_or_bind_ephemeral(&self) -> Result<&SocketAddrV4> {
        self.try_bind(SocketAddrInet {
            port: 0,
            addr: [0, 0, 0, 0],
            _pad: [0; 8],
        })?;
        Ok(self.addr.get().unwrap())
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
        self.addr_or_bind_ephemeral()?;
        let mode = self.mode.call_once(|| {
            Mode::Passive(PassiveTcpSocket {
                backlog: AtomicUsize::new(backlog),
                notify: Notify::new(),
                queue: Mutex::new(VecDeque::new()),
            })
        });
        let Mode::Passive(passive) = mode else {
            bail!(IsConn);
        };
        // TODO: Is this correct?
        passive.backlog.fetch_max(backlog, Ordering::Relaxed);
        Ok(())
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

    fn poll_ready(&self, _: Events) -> Events {
        todo!()
    }

    fn epoll_ready(&self, events: Events) -> Result<Events> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, _: Events) -> Result<Events> {
        todo!()
    }

    fn file_lock(&self) -> Result<&FileLock> {
        todo!()
    }
}

#[non_exhaustive]
enum Mode {
    Passive(PassiveTcpSocket),
}

struct PassiveTcpSocket {
    backlog: AtomicUsize,
    notify: Notify,
    queue: Mutex<VecDeque<()>>,
}
