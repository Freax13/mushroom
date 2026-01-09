// TODO: Move unix sockets here.

use core::{
    borrow::Borrow,
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use usize_conversions::{FromUsize, usize_from};

use crate::{
    error::{Error, Result, bail},
    fs::fd::{FdFlags, FileDescriptorTable, StrongFileDescriptor},
    user::{
        memory::VirtualMemory,
        process::limits::CurrentNoFileLimit,
        syscall::{
            args::{
                CmsgHdr, Domain, MsgHdr, MsgHdrFlags, Pointer,
                pointee::{SizedPointee, WritablePointee},
            },
            traits::Abi,
        },
    },
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

pub struct CMsgBuilder<'a> {
    abi: Abi,
    vm: &'a VirtualMemory,
    msg_hdr: &'a mut MsgHdr,
    offset: usize,
}

impl<'a> CMsgBuilder<'a> {
    pub fn new(abi: Abi, vm: &'a VirtualMemory, msg_hdr: &'a mut MsgHdr) -> Self {
        msg_hdr.flags.remove(MsgHdrFlags::CTRUNC);

        Self {
            abi,
            vm,
            msg_hdr,
            offset: 0,
        }
    }

    /// Add a control message.
    ///
    /// `write` is called with a pointer where the payload should be written
    /// and the remaining capacity.
    fn add_generic(
        &mut self,
        level: i32,
        r#type: i32,
        write: impl FnOnce(&VirtualMemory, Pointer<c_void>, usize, Abi) -> Result<CmsgSize>,
    ) -> Result<()> {
        let align = match self.abi {
            Abi::I386 => 4,
            Abi::Amd64 => 8,
        };
        let next_offset = self.offset.next_multiple_of(align);

        let mut cmsg_header = CmsgHdr {
            len: 0,
            level,
            r#type,
        };
        let header_len = cmsg_header.size(self.abi);

        let Some(payload_capacity) =
            usize_from(self.msg_hdr.controllen).checked_sub(next_offset + header_len)
        else {
            self.msg_hdr.flags |= MsgHdrFlags::CTRUNC;
            return Ok(());
        };

        let ptr = self.msg_hdr.control.bytes_offset(next_offset);
        let payload_ptr = ptr.bytes_offset(header_len).cast();
        let size = write(self.vm, payload_ptr, payload_capacity, self.abi)?;

        let payload_len = match size {
            CmsgSize::TooSmall => {
                self.msg_hdr.flags |= MsgHdrFlags::CTRUNC;
                return Ok(());
            }
            CmsgSize::Truncated(payload_len) => {
                self.msg_hdr.flags |= MsgHdrFlags::CTRUNC;
                payload_len
            }
            CmsgSize::Complete(payload_len) => payload_len,
        };

        let total_len = header_len + payload_len;
        cmsg_header.len = u64::from_usize(total_len);
        self.vm.write_with_abi(ptr.cast(), cmsg_header, self.abi)?;

        self.offset = next_offset + total_len;

        Ok(())
    }

    pub fn add<T, P>(&mut self, level: i32, r#type: i32, payload: impl Borrow<T>) -> Result<()>
    where
        T: SizedPointee<P> + WritablePointee<P>,
    {
        self.add_generic(level, r#type, |vm, ptr, capacity, abi| {
            let payload = payload.borrow();
            let payload_len = payload.size(abi);
            if payload_len > capacity {
                return Ok(CmsgSize::TooSmall);
            }
            vm.write_with_abi(ptr.cast::<T>(), payload, abi)?;
            Ok(CmsgSize::Complete(payload_len))
        })
    }

    pub fn add_fds(
        &mut self,
        level: i32,
        r#type: i32,
        fds: impl IntoIterator<Item = StrongFileDescriptor>,
        fd_flags: FdFlags,
        fdtable: &FileDescriptorTable,
        no_file_limit: CurrentNoFileLimit,
    ) -> Result<()> {
        self.add_generic(level, r#type, |vm, mut ptr, mut capacity, _abi| {
            let mut written = 0;
            for fd in fds {
                let Some(new_capacity) = capacity.checked_sub(4) else {
                    if written == 0 {
                        return Ok(CmsgSize::TooSmall);
                    } else {
                        return Ok(CmsgSize::Truncated(written));
                    }
                };

                let Ok(num) = fdtable.insert(fd, fd_flags, no_file_limit) else {
                    break;
                };

                vm.write(ptr.cast(), num)?;

                written += 4;
                ptr = ptr.bytes_offset(4);
                capacity = new_capacity;
            }
            Ok(CmsgSize::Complete(written))
        })
    }
}

impl Drop for CMsgBuilder<'_> {
    fn drop(&mut self) {
        let offset = u64::from_usize(self.offset);
        debug_assert!(self.msg_hdr.controllen >= offset);
        self.msg_hdr.controllen = offset;
    }
}

enum CmsgSize {
    /// The capacity was too small to write the payload.
    TooSmall,
    /// The capacity was big enough to write part of the payload, but not all
    /// of it.
    Truncated(usize),
    /// The capacity was big enough to write the entire payload.
    Complete(usize),
}
