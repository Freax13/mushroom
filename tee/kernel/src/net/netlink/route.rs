use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;
use bytemuck::{Pod, Zeroable, bytes_of, pod_read_unaligned};

use crate::{
    net::netlink::{MsgHeader, MsgHeaderFlags, NLMSG_DONE, NLMSG_ERROR},
    rt::{mpmc, mpsc},
    user::syscall::args::Domain,
};

pub fn lo_mtu() -> u32 {
    65536
}

pub fn lo_interface_flags() -> InterfaceFlags {
    InterfaceFlags::UP
        | InterfaceFlags::LOOPBACK
        | InterfaceFlags::RUNNING
        | InterfaceFlags::LOWER_UP
}

pub async fn handle(pid: u32, tx: mpmc::Sender<Vec<u8>>, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Ok(rx) = rx.recv().await {
        // TODO: Don't panic when bounds checks fail.

        let mut rx = &*rx;
        while !rx.is_empty() {
            let Some(header) = rx.get(..size_of::<MsgHeader>()) else {
                log::warn!("truncated header");
                break;
            };
            let header = pod_read_unaligned::<MsgHeader>(header);

            if (header.len as usize) < size_of::<MsgHeader>() {
                log::warn!("message is too short");
                break;
            }
            let Some(message) = rx.get(..header.len as usize) else {
                log::warn!("truncated message");
                break;
            };
            rx = &rx[header.len as usize..];
            let payload = &message[size_of::<MsgHeader>()..];

            if !header.flags.contains(MsgHeaderFlags::REQUEST) {
                continue;
            }

            log::debug!("{header:?} {payload:02x?}");

            const RTM_NEWLINK: u16 = 0x10;
            const RTM_GETLINK: u16 = 0x12;
            const RTM_NEWADDR: u16 = 0x14;
            const RTM_GETADDR: u16 = 0x16;
            const RTM_NEWROUTE: u16 = 0x18;
            const RTM_GETROUTE: u16 = 0x1a;
            match header.r#type {
                RTM_GETLINK => {
                    let mut response = Vec::new();

                    let mut rta_attrs = Vec::new();

                    let rta_data = &[0; 6];
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::IFLA_ADDRESS,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let rta_data = &[0; 6];
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::IFLA_BROADCAST,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let rta_data = c"lo".to_bytes_with_nul();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::IFLA_IFNAME,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let rta_data = &lo_mtu().to_ne_bytes();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::IFLA_MTU,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let new_link_header = MsgHeader {
                        len: (size_of::<MsgHeader>() + size_of::<IfInfoMsg>() + rta_attrs.len())
                            as u32,
                        r#type: RTM_NEWLINK,
                        flags: MsgHeaderFlags::MULTI,
                        seq: header.seq,
                        pid,
                    };
                    response.extend_from_slice(bytes_of(&new_link_header));

                    let new_link_data = IfInfoMsg {
                        family: Domain::Unspec as u8,
                        _padding: 0,
                        r#type: ARPHRD_LOOPBACK,
                        index: 1,
                        flags: lo_interface_flags(),
                        change: 0,
                    };
                    response.extend_from_slice(bytes_of(&new_link_data));

                    response.extend_from_slice(&rta_attrs);

                    let done_header = MsgHeader {
                        len: size_of::<MsgHeader>() as u32,
                        r#type: NLMSG_DONE,
                        flags: MsgHeaderFlags::MULTI,
                        seq: header.seq,
                        pid,
                    };
                    response.extend_from_slice(bytes_of(&done_header));

                    let _ = tx.send(response);
                }
                RTM_GETADDR => {
                    let mut response = Vec::new();

                    let mut rta_attrs = Vec::new();

                    let rta_data = &Ipv4Addr::LOCALHOST.octets();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::IFA_ADDRESS,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let rta_data = &Ipv4Addr::LOCALHOST.octets();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::IFA_LOCAL,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let rta_data = c"lo".to_bytes_with_nul();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::IFA_LABEL,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let new_addr_header = MsgHeader {
                        len: (size_of::<MsgHeader>() + size_of::<IfAddrMsg>() + rta_attrs.len())
                            as u32,
                        r#type: RTM_NEWADDR,
                        flags: MsgHeaderFlags::MULTI,
                        seq: header.seq,
                        pid,
                    };
                    response.extend_from_slice(bytes_of(&new_addr_header));

                    let new_addr_data = IfAddrMsg {
                        family: Domain::Inet as u8,
                        prefixlen: 8,
                        flags: AddrFlags::IFA_F_PERMANENT,
                        scope: AddrScope::RT_SCOPE_HOST,
                        index: 1,
                    };
                    response.extend_from_slice(bytes_of(&new_addr_data));

                    response.extend_from_slice(&rta_attrs);

                    let mut rta_attrs = Vec::new();

                    let rta_data = &Ipv6Addr::LOCALHOST.octets();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::IFA_ADDRESS,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let new_addr_header = MsgHeader {
                        len: (size_of::<MsgHeader>() + size_of::<IfAddrMsg>() + rta_attrs.len())
                            as u32,
                        r#type: RTM_NEWADDR,
                        flags: MsgHeaderFlags::MULTI,
                        seq: header.seq,
                        pid,
                    };
                    response.extend_from_slice(bytes_of(&new_addr_header));

                    let new_addr_data = IfAddrMsg {
                        family: Domain::Inet6 as u8,
                        prefixlen: 128,
                        flags: AddrFlags::IFA_F_PERMANENT,
                        scope: AddrScope::RT_SCOPE_HOST,
                        index: 1,
                    };
                    response.extend_from_slice(bytes_of(&new_addr_data));

                    response.extend_from_slice(&rta_attrs);

                    let done_header = MsgHeader {
                        len: size_of::<MsgHeader>() as u32,
                        r#type: NLMSG_DONE,
                        flags: MsgHeaderFlags::MULTI,
                        seq: header.seq,
                        pid,
                    };
                    response.extend_from_slice(bytes_of(&done_header));

                    let _ = tx.send(response);
                }
                RTM_GETROUTE => {
                    let mut response = Vec::new();

                    let mut rta_attrs = Vec::new();

                    let rta_data = u32::from((RouteTable::LOCAL).0).to_ne_bytes();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::RTA_TABLE,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(&rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let rta_data = &Ipv4Addr::new(127, 0, 0, 0).octets();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::RTA_DST,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let rta_data = &Ipv4Addr::LOCALHOST.octets();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::RTA_PREFSRC,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let rta_data = c"lo".to_bytes_with_nul();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::RTA_OIF,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let new_addr_header = MsgHeader {
                        len: (size_of::<MsgHeader>() + size_of::<RtMsg>() + rta_attrs.len()) as u32,
                        r#type: RTM_NEWROUTE,
                        flags: MsgHeaderFlags::MULTI,
                        seq: header.seq,
                        pid,
                    };
                    response.extend_from_slice(bytes_of(&new_addr_header));

                    let new_route_data = RtMsg {
                        family: Domain::Inet as u8,
                        dst_len: 8,
                        src_len: 0,
                        tos: 0,
                        table: RouteTable::LOCAL,
                        protocol: RouteProtocol::KERNEL,
                        scope: RouteScope::HOST,
                        r#type: RouteType::LOCAL,
                        flags: RouteFlags::empty(),
                    };
                    response.extend_from_slice(bytes_of(&new_route_data));

                    response.extend_from_slice(&rta_attrs);

                    let mut rta_attrs = Vec::new();

                    let rta_data = u32::from((RouteTable::LOCAL).0).to_ne_bytes();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::RTA_TABLE,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(&rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let rta_data = &Ipv4Addr::new(127, 0, 0, 0).octets();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::RTA_DST,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let rta_data = &Ipv4Addr::LOCALHOST.octets();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::RTA_PREFSRC,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let rta_data = c"lo".to_bytes_with_nul();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::RTA_OIF,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let new_addr_header = MsgHeader {
                        len: (size_of::<MsgHeader>() + size_of::<RtMsg>() + rta_attrs.len()) as u32,
                        r#type: RTM_NEWROUTE,
                        flags: MsgHeaderFlags::MULTI,
                        seq: header.seq,
                        pid,
                    };
                    response.extend_from_slice(bytes_of(&new_addr_header));

                    let new_route_data = RtMsg {
                        family: Domain::Inet as u8,
                        dst_len: 8,
                        src_len: 0,
                        tos: 0,
                        table: RouteTable::LOCAL,
                        protocol: RouteProtocol::KERNEL,
                        scope: RouteScope::HOST,
                        r#type: RouteType::LOCAL,
                        flags: RouteFlags::empty(),
                    };
                    response.extend_from_slice(bytes_of(&new_route_data));

                    response.extend_from_slice(&rta_attrs);

                    let mut rta_attrs = Vec::new();

                    let rta_data = u32::from((RouteTable::LOCAL).0).to_ne_bytes();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::RTA_TABLE,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(&rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let rta_data = &Ipv4Addr::new(127, 255, 255, 255).octets();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::RTA_DST,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let rta_data = &Ipv4Addr::LOCALHOST.octets();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::RTA_PREFSRC,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let rta_data = c"lo".to_bytes_with_nul();
                    let rta_header = RtAttr {
                        len: (size_of::<RtAttr>() + rta_data.len()) as u16,
                        r#type: RtAttrType::RTA_OIF,
                    };
                    rta_attrs.extend_from_slice(bytes_of(&rta_header));
                    rta_attrs.extend_from_slice(rta_data);
                    rta_attrs.resize(rta_attrs.len().next_multiple_of(4), 0); // add padding

                    let new_addr_header = MsgHeader {
                        len: (size_of::<MsgHeader>() + size_of::<RtMsg>() + rta_attrs.len()) as u32,
                        r#type: RTM_NEWROUTE,
                        flags: MsgHeaderFlags::MULTI,
                        seq: header.seq,
                        pid,
                    };
                    response.extend_from_slice(bytes_of(&new_addr_header));

                    let new_route_data = RtMsg {
                        family: Domain::Inet as u8,
                        dst_len: 32,
                        src_len: 0,
                        tos: 0,
                        table: RouteTable::LOCAL,
                        protocol: RouteProtocol::KERNEL,
                        scope: RouteScope::LINK,
                        r#type: RouteType::BROADCAST,
                        flags: RouteFlags::empty(),
                    };
                    response.extend_from_slice(bytes_of(&new_route_data));

                    response.extend_from_slice(&rta_attrs);

                    let done_header = MsgHeader {
                        len: size_of::<MsgHeader>() as u32,
                        r#type: NLMSG_DONE,
                        flags: MsgHeaderFlags::MULTI,
                        seq: header.seq,
                        pid,
                    };
                    response.extend_from_slice(bytes_of(&done_header));

                    let _ = tx.send(response);
                }
                ty => log::warn!("unknown request type: {ty:#02x}"),
            }

            if header.flags.contains(MsgHeaderFlags::ACK) {
                // Send acknowledgment.

                let mut response = Vec::new();

                // response header
                let error_header = MsgHeader {
                    len: size_of::<MsgHeader>() as u32 + 4,
                    r#type: NLMSG_ERROR,
                    flags: MsgHeaderFlags::CAPPED,
                    seq: header.seq,
                    pid,
                };
                response.extend_from_slice(bytes_of(&error_header));

                let error = 0i32;
                response.extend_from_slice(bytes_of(&error));

                // original request header
                response.extend_from_slice(bytes_of(&header));

                let _ = tx.send(response);
            }
        }
    }

    log::debug!("Netlink socket task ended");
}

const ARPHRD_LOOPBACK: u16 = 772;

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct IfInfoMsg {
    pub family: u8,
    _padding: u8,
    /// Device type
    pub r#type: u16,
    /// Interface index
    pub index: i32,
    /// Device flags
    pub flags: InterfaceFlags,
    /// change mask
    pub change: u32,
}

bitflags! {
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    #[repr(transparent)]
    pub struct InterfaceFlags: u32 {
        const UP = 1 << 0;
        const BROADCAST = 1 << 1;
        const DEBUG = 1 << 2;
        const LOOPBACK = 1 << 3;
        const POINTOPOINT = 1 << 4;
        const NOTRAILERS = 1 << 5;
        const RUNNING = 1 << 6;
        const NOARP = 1 << 7;
        const PROMISC = 1 << 8;
        const ALLMULTI = 1 << 9;
        const MASTER = 1 << 10;
        const SLAVE = 1 << 11;
        const MULTICAST = 1 << 12;
        const PORTSEL = 1 << 13;
        const AUTOMEDIA = 1 << 14;
        const DYNAMIC = 1 << 15;
        const LOWER_UP = 1 << 16;
        const DORMANT = 1 << 17;
        const ECHO = 1 << 18;
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct IfAddrMsg {
    family: u8,
    prefixlen: u8,
    flags: AddrFlags,
    scope: AddrScope,
    index: u32,
}

bitflags! {
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    #[repr(transparent)]
    pub struct AddrFlags: u8 {
        const IFA_F_TEMPORARY = 0x1;
        const IFA_F_NODAD = 0x02;
        const IFA_F_OPTIMISTIC = 0x04;
        const IFA_F_DADFAILED = 0x08;
        const IFA_F_HOMEADDRESS = 0x10;
        const IFA_F_DEPRECATED = 0x20;
        const IFA_F_TENTATIVE = 0x40;
        const IFA_F_PERMANENT = 0x80;
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct AddrScope(u8);

#[expect(dead_code)]
impl AddrScope {
    const RT_SCOPE_UNIVERSE: Self = Self(0);
    const RT_SCOPE_SITE: Self = Self(200);
    const RT_SCOPE_LINK: Self = Self(253);
    const RT_SCOPE_HOST: Self = Self(254);
    const RT_SCOPE_NOWHERE: Self = Self(255);
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct RtMsg {
    /// Address family of route
    family: u8,
    /// Length of destination
    dst_len: u8,
    /// Length of source
    src_len: u8,
    /// TOS filter
    tos: u8,
    /// Routing table ID
    table: RouteTable,
    /// Routing protocol
    protocol: RouteProtocol,
    scope: RouteScope,
    r#type: RouteType,
    flags: RouteFlags,
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
struct RouteTable(u8);

#[expect(dead_code)]
impl RouteTable {
    const UNSPEC: Self = Self(0);
    const COMPAT: Self = Self(252);
    const DEFAULT: Self = Self(253);
    const MAIN: Self = Self(254);
    const LOCAL: Self = Self(255);
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
struct RouteProtocol(u8);

#[expect(dead_code)]
impl RouteProtocol {
    const UNSPEC: Self = Self(0);
    /// Route installed by ICMP redirects; not used by current IPv4
    const REDIRECT: Self = Self(1);
    /// Route installed by kernel
    const KERNEL: Self = Self(2);
    /// Route installed during boot
    const BOOT: Self = Self(3);
    /// Route installed by administrator
    const STATIC: Self = Self(4);
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
struct RouteScope(u8);

#[expect(dead_code)]
impl RouteScope {
    const UNIVERSE: Self = Self(0);
    const SITE: Self = Self(200);
    const LINK: Self = Self(253);
    const HOST: Self = Self(254);
    const NOWHERE: Self = Self(255);
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
struct RouteType(u8);

#[expect(dead_code)]
impl RouteType {
    const UNSPEC: Self = Self(0);
    /// Gateway or direct route
    const UNICAST: Self = Self(1);
    /// Accept locally
    const LOCAL: Self = Self(2);
    /// Accept locally as broadcast, send as broadcast
    const BROADCAST: Self = Self(3);
    /// Accept locally as broadcast, but send as unicast
    const ANYCAST: Self = Self(4);
    /// Multicast route
    const MULTICAST: Self = Self(5);
    /// Drop
    const BLACKHOLE: Self = Self(6);
    /// Destination is unreachable  
    const UNREACHABLE: Self = Self(7);
    /// Administratively prohibited
    const PROHIBIT: Self = Self(8);
    /// Not in this table
    const THROW: Self = Self(9);
    /// Translate this address
    const NAT: Self = Self(10);
    /// Use external resolver
    const XRESOLVE: Self = Self(11);
}

bitflags! {
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    #[repr(transparent)]
    pub struct RouteFlags: u32 {
        /// Notify user of route change
        const NOTIFY = 0x100;
        /// This route is cloned
        const CLONED = 0x200;
        /// Multipath equalizer: NI
        const EQUALIZE = 0x400;
        /// Prefix addresses
        const PREFIX = 0x800;
        /// set rtm_table to FIB lookup result
        const LOOKUP_TABLE = 0x1000;
        /// return full fib lookup match
        const FIB_MATCH = 0x2000;
        /// route is offloaded
        const OFFLOAD = 0x4000;
        /// route is trapping packets
        const TRAP = 0x8000;
        /// route offload failed
        const OFFLOAD_FAILED = 0x20000000;
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct RtAttr {
    pub len: u16,
    pub r#type: RtAttrType,
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
struct RtAttrType(u16);

impl RtAttrType {
    const IFLA_ADDRESS: Self = Self(1);
    const IFLA_BROADCAST: Self = Self(2);
    const IFLA_IFNAME: Self = Self(3);
    const IFLA_MTU: Self = Self(4);

    const IFA_ADDRESS: Self = Self(1);
    const IFA_LOCAL: Self = Self(2);
    const IFA_LABEL: Self = Self(3);

    const RTA_DST: Self = Self(1);
    const RTA_OIF: Self = Self(4);
    const RTA_PREFSRC: Self = Self(7);
    const RTA_TABLE: Self = Self(15);
}
