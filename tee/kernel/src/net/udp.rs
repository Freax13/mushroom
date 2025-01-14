use alloc::sync::Arc;

use crate::{
    error::{bail, Result},
    fs::{
        fd::{Events, FileLock, OpenFileDescription},
        node::FileAccessContext,
        path::Path,
        FileSystem,
    },
    user::process::{
        memory::VirtualMemory,
        syscall::{
            args::{FileMode, OpenFlags, Pointer, SocketTypeWithFlags, Stat},
            traits::Abi,
        },
        thread::{Gid, Uid},
    },
};

pub struct UdpSocket {
    flags: OpenFlags,
}

impl UdpSocket {
    pub fn new(r#type: SocketTypeWithFlags) -> Self {
        Self {
            flags: r#type.flags,
        }
    }
}

impl OpenFileDescription for UdpSocket {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Result<Path> {
        todo!()
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
            (0, 11) => Ok(()), // SO_NO_CHECK
            err => bail!(Inval),
        }
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
