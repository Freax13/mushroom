use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;
use bytemuck::{Pod, Zeroable, bytes_of, pod_read_unaligned};

use crate::{
    net::netlink::{MsgHeader, MsgHeaderFlags, NLMSG_DONE},
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
                ty => log::warn!("unknown request type: {ty:#02x}"),
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
}
