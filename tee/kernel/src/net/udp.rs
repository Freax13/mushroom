use core::{
    cmp,
    ffi::c_void,
    net::{self, IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Not,
};

use alloc::{
    boxed::Box,
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use async_trait::async_trait;
use usize_conversions::usize_from;

use crate::{
    error::{Result, bail, ensure, err},
    fs::{
        FileSystem,
        fd::{
            Events, FileDescriptorTable, FileLock, NonEmptyEvents, OpenFileDescription,
            OpenFileDescriptionData, ReadBuf, StrongFileDescriptor, VectoredUserBuf, WriteBuf,
            common_ioctl,
        },
        node::FileAccessContext,
        path::Path,
    },
    net::IpVersion,
    rt::notify::Notify,
    spin::mutex::Mutex,
    user::process::{
        limits::CurrentNoFileLimit,
        memory::VirtualMemory,
        syscall::{
            args::{
                FileMode, MsgHdr, OpenFlags, Pointer, RecvFromFlags, SentToFlags, SocketAddr,
                SocketType, SocketTypeWithFlags, Stat,
            },
            traits::Abi,
        },
        thread::{Gid, ThreadGuard, Uid},
    },
};

use super::netlink::{lo_interface_flags, lo_mtu};

const MAX_BUFFER_SIZE: usize = 65507;

// TODO: Periodically clean up closed UDP sockets.
static PORTS: Mutex<BTreeMap<u16, PortData>> = Mutex::new(BTreeMap::new());

#[derive(Default)]
struct PortData {
    round_robin_counter: usize,
    entries: Vec<PortDataEntry>,
}

impl PortData {
    pub fn bind(
        &mut self,
        ip: IpAddr,
        reuse_addr: bool,
        socket: Weak<OpenFileDescriptionData<UdpSocket>>,
    ) -> Result<()> {
        let ip_version = IpVersion::from(ip);
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
            if entry.socket.strong_count() == 0 {
                i -= 1;
                self.entries.swap_remove(i);
                continue;
            };

            // Skip entries with a different address family.
            if entry.ip_version != ip_version {
                continue;
            }

            // Skip entries that don't overlap with `ip`.
            if entry
                .local_ip
                .zip(local_ip)
                .is_some_and(|(entry_ip, ip)| entry_ip != ip)
            {
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
        }

        self.entries.push(PortDataEntry {
            ip_version,
            local_ip,
            reuse_addr,
            socket,
        });

        Ok(())
    }
}

struct PortDataEntry {
    ip_version: IpVersion,
    local_ip: Option<IpAddr>,
    reuse_addr: bool,
    socket: Weak<OpenFileDescriptionData<UdpSocket>>,
}

const EPHEMERAL_PORT_START: u16 = 32768;
const EPHEMERAL_PORT_END: u16 = 60999;

pub struct UdpSocket {
    this: Weak<OpenFileDescriptionData<Self>>,
    ip_version: IpVersion,
    internal: Mutex<UdpSocketInternal>,
    rx_notify: Notify,
}

struct UdpSocketInternal {
    flags: OpenFlags,
    reuse_addr: bool,
    send_buffer_size: usize,
    receive_buffer_size: usize,
    socketname: Option<net::SocketAddr>,
    peername: Option<net::SocketAddr>,
    rx: VecDeque<Packet>,
}

impl UdpSocket {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(ip_version: IpVersion, r#type: SocketTypeWithFlags) -> StrongFileDescriptor {
        StrongFileDescriptor::new_cyclic(|this| Self {
            this: this.clone(),
            ip_version,
            internal: Mutex::new(UdpSocketInternal {
                flags: r#type.flags,
                reuse_addr: false,
                send_buffer_size: 1024 * 1024,
                receive_buffer_size: 1024 * 1024,
                socketname: None,
                peername: None,
                rx: VecDeque::new(),
            }),
            rx_notify: Notify::new(),
        })
    }

    /// Try to bind the socket to an address. Returns `true` if the socket was
    /// bound, returns `false` if the socket was already bound. Returns
    /// `Err(..)` if the socket could not be bound to the given address.
    fn try_bind(&self, mut socket_addr: net::SocketAddr) -> Result<bool> {
        ensure!(IpVersion::from(socket_addr.ip()) == self.ip_version, Inval);

        let mut guard = self.internal.lock();
        if guard.socketname.is_some() {
            return Ok(false);
        }

        let mut ports_guard = PORTS.lock();

        // Prepare a bind guard.
        if socket_addr.port() == 0 {
            'port: {
                // If no port has been specified, try to find one that can be
                // bound to.
                for port in EPHEMERAL_PORT_START..=EPHEMERAL_PORT_END {
                    let entry = ports_guard.entry(port).or_default();
                    if entry
                        .bind(socket_addr.ip(), false, self.this.clone())
                        .is_ok()
                    {
                        socket_addr.set_port(port);
                        break 'port;
                    }
                }
                // If we can't find a port, fail.
                bail!(AddrInUse)
            }
        } else {
            ports_guard.entry(socket_addr.port()).or_default().bind(
                socket_addr.ip(),
                guard.reuse_addr,
                self.this.clone(),
            )?;
        }

        guard.socketname = Some(socket_addr);

        Ok(true)
    }

    fn get_or_bind_ephemeral(&self, peername: IpAddr) -> Result<net::SocketAddr> {
        let mut guard = self.internal.lock();
        if guard.socketname.is_none() {
            drop(guard);
            self.try_bind(net::SocketAddr::new(peername, 0))?;
            guard = self.internal.lock();
        }
        Ok(guard.socketname.unwrap())
    }

    fn recv(&self, buf: &mut (impl ReadBuf + ?Sized), peek: bool) -> Result<(usize, SocketAddr)> {
        let mut guard = self.internal.lock();
        let packed_owned;
        let packet = if peek {
            guard.rx.front().ok_or(err!(Again))?
        } else {
            packed_owned = guard.rx.pop_front().ok_or(err!(Again))?;
            &packed_owned
        };

        let len = cmp::min(buf.buffer_len(), packet.bytes.len());
        buf.write(0, &packet.bytes[..len])?;

        Ok((len, SocketAddr::from(packet.sender)))
    }

    fn send(&self, peername: Option<SocketAddr>, buf: &(impl WriteBuf + ?Sized)) -> Result<usize> {
        let mut peername = if let Some(peername) = peername {
            net::SocketAddr::try_from(peername)?
        } else {
            self.internal.lock().peername.ok_or(err!(NotConn))?
        };

        // If the ip is all zeroes, the packet gets sent to localhost.
        if peername.ip().is_unspecified() {
            let localhost = if peername.is_ipv4() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            };
            peername.set_ip(localhost);
        }

        let sender = self.get_or_bind_ephemeral(self.ip_version.unspecified_ip())?;

        let len = buf.buffer_len();
        ensure!(len <= MAX_BUFFER_SIZE, MsgSize);
        let mut bytes = vec![0; len];
        buf.read(0, &mut bytes)?;
        let bytes = Box::<[u8]>::from(bytes);

        let mut guard = PORTS.lock();
        let Some(data) = guard.get_mut(&peername.port()) else {
            return Ok(len);
        };

        let mut i = 0;
        let mut socket;
        let mut socket_guard = loop {
            if i >= data.entries.len() {
                return Ok(len);
            }
            let idx = (i.wrapping_add(data.round_robin_counter)) % data.entries.len();
            let entry = &data.entries[idx];

            // Skip entries with a different address family.
            if entry.ip_version != self.ip_version {
                i += 1;
                continue;
            }

            // Make sure that the peername matches the bound address.
            let matches = entry.local_ip.is_none_or(|ip| ip == peername.ip());
            if !matches {
                i += 1;
                continue;
            }
            // Skip over closed sockets.
            let Some(s) = entry.socket.upgrade() else {
                data.entries.remove(i);
                continue;
            };
            socket = s;

            // If the socket is connected, make sure that the address matches
            // the sender.
            let guard = socket.internal.lock();
            let matches = guard.peername.is_none_or(|peer| {
                (peer.ip() == sender.ip() || sender.ip().is_unspecified())
                    && (peer.port() == sender.port())
            });
            if !matches {
                i += 1;
                continue;
            }

            break guard;
        };
        data.round_robin_counter = data.round_robin_counter.wrapping_add(i).wrapping_add(1);
        drop(guard);

        socket_guard.rx.push_back(Packet { bytes, sender });
        socket.rx_notify.notify();

        Ok(len)
    }
}

#[async_trait]
impl OpenFileDescription for UdpSocket {
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

    fn path(&self) -> Result<Path> {
        todo!()
    }

    fn get_socket_option(&self, _: Abi, level: i32, optname: i32) -> Result<Vec<u8>> {
        let guard = self.internal.lock();
        Ok(match (level, optname) {
            (1, 3) => {
                // SO_TYPE
                let ty = SocketType::Dgram as u32;
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
            (0, 2) => Ok(()),  // IP_TTL
            (0, 6) => Ok(()),  // IP_RECVOPTS
            (0, 11) => Ok(()), // IP_RECVERR
            (0, 32) => Ok(()), // IP_MULTICAST_IF
            (0, 33) => Ok(()), // IP_MULTICAST_TTL
            (0, 34) => Ok(()), // IP_MULTICAST_LOOP
            (1, 2) => {
                // SO_REUSEADDR
                ensure!(optlen == 4, Inval);
                let optval = virtual_memory.read(optval.cast::<i32>())? != 0;
                guard.reuse_addr = optval;
                Ok(())
            }
            (1, 6) => Ok(()), // SO_BROADCAST
            (1, 7) => {
                // SO_SNDBUF
                ensure!(optlen == 4, Inval);
                let optval = virtual_memory.read(optval.cast::<i32>())?;
                let new_send_buffer_size = optval as usize * 2;
                let new_send_buffer_size = cmp::max(new_send_buffer_size, 2048); // 2048 is the minimum
                guard.send_buffer_size = new_send_buffer_size;
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
            (1, 15) => Ok(()), // SO_REUSEPORT
            _ => bail!(Inval),
        }
    }

    fn bind(&self, addr: SocketAddr, _: &mut FileAccessContext) -> Result<()> {
        let addr = net::SocketAddr::try_from(addr)?;
        ensure!(self.try_bind(addr)?, Inval);
        Ok(())
    }

    fn get_socket_name(&self) -> Result<SocketAddr> {
        let addr = self.internal.lock().socketname;
        let addr = addr.unwrap_or_else(|| self.ip_version.unspecified_addr());
        Ok(SocketAddr::from(addr))
    }

    fn get_peer_name(&self) -> Result<SocketAddr> {
        let addr = self.internal.lock().peername.ok_or(err!(NotConn))?;
        Ok(SocketAddr::from(addr))
    }

    async fn connect(&self, addr: SocketAddr, _: &mut FileAccessContext) -> Result<()> {
        match addr {
            SocketAddr::Unspecified => {
                let mut guard = self.internal.lock();
                guard.peername = None;
            }
            SocketAddr::Inet(remote_addr) => {
                ensure!(self.ip_version == IpVersion::V4, Inval);
                ensure!(remote_addr.ip().is_loopback(), NetUnreach);
                self.get_or_bind_ephemeral(IpAddr::V4(Ipv4Addr::LOCALHOST))?;
                let mut guard = self.internal.lock();
                ensure!(guard.peername.is_none(), IsConn);
                guard.peername = Some(net::SocketAddr::V4(remote_addr));
            }
            SocketAddr::Inet6(remote_addr) => {
                ensure!(self.ip_version == IpVersion::V6, Inval);
                ensure!(remote_addr.ip().is_loopback(), NetUnreach);
                self.get_or_bind_ephemeral(IpAddr::V6(Ipv6Addr::LOCALHOST))?;
                let mut guard = self.internal.lock();
                ensure!(guard.peername.is_none(), IsConn);
                guard.peername = Some(net::SocketAddr::V6(remote_addr));
            }
            _ => bail!(Inval),
        }
        Ok(())
    }

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        let mut ready_events = Events::empty();
        if events.contains(Events::READ) {
            ready_events.set(Events::READ, !self.internal.lock().rx.is_empty());
        }
        ready_events.set(Events::WRITE, true);
        ready_events &= events;
        NonEmptyEvents::new(ready_events)
    }

    fn epoll_ready(&self, events: Events) -> Result<Option<NonEmptyEvents>> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        self.rx_notify.wait_until(|| self.poll_ready(events)).await
    }

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        let (len, _addr) = self.recv(buf, false)?;
        Ok(len)
    }

    fn recv_from(
        &self,
        buf: &mut dyn ReadBuf,
        flags: RecvFromFlags,
    ) -> Result<(usize, Option<SocketAddr>)> {
        let peek = flags.contains(RecvFromFlags::PEEK);
        let (len, addr) = self.recv(buf, peek)?;
        Ok((len, Some(addr)))
    }

    fn recv_msg(
        &self,
        vm: &VirtualMemory,
        abi: Abi,
        msg_hdr: &mut MsgHdr,
        _: &FileDescriptorTable,
        _: CurrentNoFileLimit,
    ) -> Result<usize> {
        let mut vectored_buf = VectoredUserBuf::new(vm, msg_hdr.iov, msg_hdr.iovlen, abi)?;
        let (len, addr) = self.recv(&mut vectored_buf, false)?;

        if msg_hdr.namelen != 0 {
            msg_hdr.namelen = addr.write(msg_hdr.name, usize_from(msg_hdr.namelen), vm)? as u32;
        }

        msg_hdr.controllen = 0;

        Ok(len)
    }

    fn write(&self, buf: &dyn WriteBuf) -> Result<usize> {
        self.send(None, buf)
    }

    fn send_to(
        &self,
        buf: &dyn WriteBuf,
        _: SentToFlags,
        addr: Option<SocketAddr>,
    ) -> Result<usize> {
        self.send(addr, buf)
    }

    fn send_msg(
        &self,
        vm: &VirtualMemory,
        abi: Abi,
        msg_hdr: &mut MsgHdr,
        _: &FileDescriptorTable,
    ) -> Result<usize> {
        if msg_hdr.controllen != 0 {
            todo!()
        }

        let peername = if msg_hdr.namelen != 0 {
            Some(SocketAddr::read(
                msg_hdr.name,
                usize_from(msg_hdr.namelen),
                vm,
            )?)
        } else {
            None
        };

        let vectored_buf = VectoredUserBuf::new(vm, msg_hdr.iov, msg_hdr.iovlen, abi)?;
        self.send(peername, &vectored_buf)
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

    fn file_lock(&self) -> Result<&FileLock> {
        todo!()
    }

    fn ioctl(
        &self,
        thread: &mut ThreadGuard,
        cmd: u32,
        arg: Pointer<c_void>,
        abi: Abi,
    ) -> Result<u64> {
        match cmd {
            0x8913 => {
                // SIOCGIFFLAGS
                thread.virtual_memory().write(
                    arg.cast().bytes_offset(16),
                    lo_interface_flags().bits() as u16,
                )?;
                Ok(0)
            }
            0x8921 => {
                // SIOCGIFMTU
                thread
                    .virtual_memory()
                    .write(arg.cast().bytes_offset(16), lo_mtu())?;
                Ok(0)
            }
            0x8946 => {
                // SIOCETHTOOL
                // TODO
                bail!(OpNotSupp)
            }
            _ => common_ioctl(self, thread, cmd, arg, abi),
        }
    }
}

struct Packet {
    bytes: Box<[u8]>,
    sender: net::SocketAddr,
}
