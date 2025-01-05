use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
};
use async_trait::async_trait;

use crate::{
    error::Result,
    fs::{
        fd::{Events, FileLock, OpenFileDescription},
        node::FileAccessContext,
        path::Path,
        FileSystem,
    },
    user::process::{
        syscall::args::{FileMode, OpenFlags, SocketTypeWithFlags, Stat},
        thread::{Gid, Uid},
    },
};

pub struct TcpSocket {
    _this: Weak<Self>,
    flags: OpenFlags,
}

impl TcpSocket {
    pub fn new(r#type: SocketTypeWithFlags) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            _this: this.clone(),
            flags: r#type.flags,
        })
    }
}

#[async_trait]
impl OpenFileDescription for TcpSocket {
    fn flags(&self) -> OpenFlags {
        self.flags
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
