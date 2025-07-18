// TODO: Move unix sockets here.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{
    error::{Error, Result, bail},
    user::process::syscall::args::Domain,
};

pub mod netlink;
pub mod tcp;
pub mod udp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    pub fn unspecified_ip(&self) -> IpAddr {
        match self {
            IpVersion::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpVersion::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }

    pub fn unspecified_addr(&self) -> SocketAddr {
        SocketAddr::new(self.unspecified_ip(), 0)
    }

    pub fn localhost_ip(&self) -> IpAddr {
        match self {
            IpVersion::V4 => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpVersion::V6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
        }
    }
}

impl TryFrom<Domain> for IpVersion {
    type Error = Error;

    fn try_from(value: Domain) -> Result<Self> {
        Ok(match value {
            Domain::Inet => Self::V4,
            Domain::Inet6 => Self::V6,
            _ => bail!(Inval),
        })
    }
}

impl From<IpAddr> for IpVersion {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
}
