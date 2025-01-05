use core::{
    net::{Ipv4Addr, SocketAddrV4},
    ops::Bound,
};

use alloc::{
    boxed::Box,
    collections::btree_map::BTreeMap,
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
    spin::{once::Once, rwlock::RwLock},
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
}

impl TcpSocket {
    pub fn new(r#type: SocketTypeWithFlags) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            flags: r#type.flags,
            addr: Once::new(),
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
