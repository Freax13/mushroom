use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{cmp, future::pending};

use async_trait::async_trait;
use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
use usize_conversions::usize_from;

use crate::{
    error::{Error, Result, bail, ensure, err},
    fs::{
        FileSystem,
        fd::{
            BsdFileLock, Events, FileDescriptorTable, NonEmptyEvents, OpenFileDescription, ReadBuf,
            VectoredUserBuf, WriteBuf,
        },
        node::{FileAccessContext, new_ino},
        path::Path,
    },
    rt::{self, mpmc, mpsc, notify::Notify},
    spin::once::Once,
    user::{
        memory::VirtualMemory,
        process::limits::CurrentNoFileLimit,
        syscall::{
            args::{
                FileMode, FileType, FileTypeAndMode, MsgHdr, OpenFlags, SentToFlags, SocketAddr,
                SocketAddrNetlink, SocketType, SocketTypeWithFlags, Stat, Timespec,
                pointee::{Pointee, PrimitivePointee},
            },
            traits::Abi,
        },
        thread::{Gid, Uid},
    },
};

mod route;

pub use route::{lo_interface_flags, lo_mtu};

pub struct NetlinkSocket {
    ino: u64,
    flags: OpenFlags,
    family: NetlinkFamily,
    connection: Once<Connection>,
    connect_notify: Notify,
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
            ino: new_ino(),
            flags: socket_type.flags,
            family,
            connection: Once::new(),
            connect_notify: Notify::new(),
        })
    }
}

#[async_trait]
impl OpenFileDescription for NetlinkSocket {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn bind(&self, addr: SocketAddr, _: &mut FileAccessContext) -> Result<()> {
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
        self.connect_notify.notify();

        Ok(())
    }

    fn get_socket_option(&self, _: Abi, level: i32, optname: i32) -> Result<Vec<u8>> {
        Ok(match (level, optname) {
            (1, 3) => {
                // SO_TYPE
                let ty = SocketType::Raw as u32;
                ty.to_le_bytes().to_vec()
            }
            _ => bail!(OpNotSupp),
        })
    }

    fn get_socket_name(&self) -> Result<SocketAddr> {
        let addr = self
            .connection
            .get()
            .map(|connection| connection.addr)
            .unwrap_or_default();
        Ok(SocketAddr::Netlink(addr))
    }

    fn send_to(
        &self,
        buf: &dyn WriteBuf,
        _flags: SentToFlags,
        _addr: Option<SocketAddr>,
        _: &FileAccessContext,
    ) -> Result<usize> {
        let connection = self.connection.get().ok_or(err!(NotConn))?;
        // TODO: Should we truncate?
        let len = buf.buffer_len();
        let mut buffer = vec![0; len];
        buf.read(0, &mut buffer)?;
        connection.tx.send(buffer).map_err(|_| err!(ConnReset))?;
        Ok(len)
    }

    fn recv_msg(
        &self,
        vm: &VirtualMemory,
        abi: Abi,
        msg_hdr: &mut MsgHdr,
        _: &FileDescriptorTable,
        _: CurrentNoFileLimit,
    ) -> Result<usize> {
        let connection = self.connection.get().ok_or(err!(NotConn))?;
        let buffer = connection.rx.try_recv().ok_or(err!(Again))?;

        if msg_hdr.namelen != 0 {
            let addr = SocketAddr::Netlink(SocketAddrNetlink::default());
            msg_hdr.namelen = addr.write(msg_hdr.name, usize_from(msg_hdr.namelen), vm)? as u32;
        }

        let mut vectored_buf = VectoredUserBuf::new(vm, msg_hdr.iov, msg_hdr.iovlen, abi)?;
        let len = cmp::min(buffer.len(), ReadBuf::buffer_len(&vectored_buf));
        let buffer = &buffer[..len];
        vectored_buf.write(0, buffer)?;

        Ok(len)
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
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Socket, FileMode::from_bits_truncate(0o777)),
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
        todo!()
    }

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        let connection = self.connection.get()?;
        let mut ready_events = Events::WRITE;
        if events.contains(Events::READ) {
            ready_events.set(Events::READ, connection.rx.poll_readable());
        }
        NonEmptyEvents::new(ready_events & events)
    }

    fn epoll_ready(&self, events: Events) -> Result<Option<NonEmptyEvents>> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        // Wait until a connection has been established.
        let connection = self
            .connect_notify
            .wait_until(|| self.connection.get())
            .await;

        let read_fut = async move {
            if !events.contains(Events::READ) {
                return pending().await;
            }
            connection.rx.readable().await;
            NonEmptyEvents::READ
        };

        let write_fut = async move {
            if !events.contains(Events::WRITE) {
                return pending().await;
            }
            NonEmptyEvents::WRITE
        };

        NonEmptyEvents::select(read_fut, write_fut).await
    }

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
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
