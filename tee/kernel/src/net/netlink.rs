use core::cmp;

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use async_trait::async_trait;
use bitflags::bitflags;
use bytemuck::{bytes_of, Pod, Zeroable};
use usize_conversions::IntoUsize;
use x86_64::VirtAddr;

use crate::{
    error::{bail, ensure, err, Error, Result},
    fs::{
        fd::{Events, FileLock, OpenFileDescription},
        node::FileAccessContext,
        path::Path,
        FileSystem,
    },
    rt::{self, mpmc, mpsc},
    spin::once::Once,
    user::process::{
        memory::VirtualMemory,
        syscall::{
            args::{
                pointee::{Pointee, PrimitivePointee},
                FileMode, MsgHdr, OpenFlags, Pointer, SentToFlags, SocketAddr, SocketAddrNetlink,
                SocketType, SocketTypeWithFlags, Stat,
            },
            traits::Abi,
        },
        thread::{Gid, Uid},
    },
};

mod route;

pub struct NetlinkSocket {
    flags: OpenFlags,
    family: NetlinkFamily,
    connection: Once<Connection>,
}

struct Connection {
    addr: SocketAddrNetlink,
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpmc::Receiver<Vec<u8>>,
}

impl NetlinkSocket {
    pub fn new(socket_type: SocketTypeWithFlags, netlink_family: i32) -> Result<Self> {
        ensure!(
            matches!(socket_type.socket_type, SocketType::Dgram | SocketType::Raw),
            Inval
        );
        let family = NetlinkFamily::try_from(netlink_family)?;

        Ok(Self {
            flags: socket_type.flags,
            family,
            connection: Once::new(),
        })
    }
}

#[async_trait]
impl OpenFileDescription for NetlinkSocket {
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
        let SocketAddr::Netlink(mut addr) = addr else {
            bail!(Inval);
        };

        if addr.pid == 0 {
            addr.pid = 0xdeafbeef; // TODO: Don't hard-code this.
        }

        let mut initialized = false;
        self.connection.call_once(|| {
            initialized = true;

            // Spawn a kernel task to handle the messages.
            // TODO: Use bounded queues.
            let (user_tx, kernel_rx) = mpsc::new::<Vec<u8>>();
            let (kernel_tx, user_rx) = mpmc::new::<Vec<u8>>();
            match self.family {
                NetlinkFamily::Route => rt::spawn(route::handle(addr.pid, kernel_tx, kernel_rx)),
            }

            Connection {
                addr,
                tx: user_tx,
                rx: user_rx,
            }
        });
        ensure!(initialized, Inval);

        Ok(())
    }

    fn get_socket_name(&self) -> Result<Vec<u8>> {
        let addr = self
            .connection
            .get()
            .map(|connection| connection.addr)
            .unwrap_or_default();
        let addr = SocketAddr::Netlink(addr);
        Ok(bytes_of(&addr).to_vec())
    }

    fn send_to(
        &self,
        vm: &VirtualMemory,
        buf: Pointer<[u8]>,
        len: usize,
        _flags: SentToFlags,
        _addr: Pointer<SocketAddr>,
        _addrlen: usize,
    ) -> Result<usize> {
        let connection = self.connection.get().ok_or(err!(NotConn))?;
        // TODO: Should we truncate?
        let mut buffer = vec![0; len];
        vm.read_bytes(buf.get(), &mut buffer)?;
        connection.tx.send(buffer).map_err(|_| err!(ConnReset))?;
        Ok(len)
    }

    fn recv_msg(&self, vm: &VirtualMemory, abi: Abi, msg_hdr: MsgHdr) -> Result<usize> {
        let connection = self.connection.get().ok_or(err!(NotConn))?;
        let buffer = connection.rx.try_recv().ok_or_else(|| err!(Again))?;

        let mut remaining = &*buffer;
        for i in 0..msg_hdr.msg_iovlen.into_usize() {
            if remaining.is_empty() {
                break;
            }

            let iov = vm.read_with_abi(msg_hdr.msg_iov.add(i), abi)?;
            let chunk_len = cmp::min(iov.len.into_usize(), remaining.len());
            let chunk;
            (chunk, remaining) = remaining.split_at(chunk_len);
            vm.write_bytes(VirtAddr::new(iov.base), chunk)?;
        }

        Ok(buffer.len() - remaining.len())
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        if events == Events::READ {
            let Some(connection) = self.connection.get() else {
                return core::future::pending().await;
            };
            connection.rx.readable().await;
            Ok(events)
        } else {
            todo!()
        }
    }

    fn path(&self) -> Result<Path> {
        todo!()
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn stat(&self) -> Result<Stat> {
        todo!()
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        todo!()
    }

    fn poll_ready(&self, events: Events) -> Events {
        todo!()
    }

    fn file_lock(&self) -> Result<&FileLock> {
        todo!()
    }
}

enum NetlinkFamily {
    Route = 0,
}

impl TryFrom<i32> for NetlinkFamily {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => NetlinkFamily::Route,
            _ => bail!(Inval),
        })
    }
}

const NLMSG_DONE: u16 = 3;

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct MsgHeader {
    /// Length of message including header
    len: u32,
    /// Type of message content
    r#type: u16,
    /// Additional flags
    flags: MsgHeaderFlags,
    /// Sequence number
    seq: u32,
    /// Sender port ID
    pid: u32,
}

impl Pointee for MsgHeader {}
impl PrimitivePointee for MsgHeader {}

bitflags! {
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    #[repr(transparent)]
    pub struct MsgHeaderFlags: u16 {
        /// Must be set on all request messages.
        const REQUEST = 1 << 0;
        /// The message is part of a multipart message terminated by
        /// NLMSG_DONE.
        const MULTI = 1 << 1;
        /// Request for an acknowledgement on success.
        const ACK = 1 << 2;
        /// Echo this request.
        const ECHO = 1 << 3;

        // Additional flag bits for GET requests:

        /// Return the complete table instead of a single entry.
        const ROOT = 1 << 8;
        /// Return all entries matching criteria passed in message content.
        const MATCH = 1 << 9;
        /// Return an atomic snapshot of the table.
        const ATOMIC = 1 << 10;

        // Additional flag bits for NEW requests:

        /// Replace existing matching object.
        const REPLACE = 1 << 8;
        /// Don't replace if the object already exists.
        const EXCL = 1 << 9;
        /// Create object if it doesn't already exist.
        const CREATE = 1 << 10;
        /// Add to the end of the object list.
        const APPEND = 1 << 11;
    }
}
