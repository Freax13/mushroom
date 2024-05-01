use crate::{
    error::Result,
    fs::node::{DynINode, FileAccessContext},
    user::process::syscall::args::{OpenFlags, Stat},
};

use super::{Events, OpenFileDescription};

pub struct PathFd {
    node: DynINode,
}

impl PathFd {
    pub fn new(node: DynINode) -> Self {
        Self { node }
    }
}

impl OpenFileDescription for PathFd {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn stat(&self) -> Result<Stat> {
        self.node.stat()
    }

    fn as_dir(&self, _ctx: &mut FileAccessContext) -> Result<DynINode> {
        Ok(self.node.clone())
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & Events::empty()
    }
}
