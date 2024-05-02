use crate::{
    error::Result,
    fs::{
        node::{DynINode, FileAccessContext},
        path::Path,
    },
    user::process::syscall::args::{OpenFlags, Stat},
};

use super::{Events, OpenFileDescription};

pub struct PathFd {
    path: Path,
    node: DynINode,
}

impl PathFd {
    pub fn new(path: Path, node: DynINode) -> Self {
        Self { path, node }
    }
}

impl OpenFileDescription for PathFd {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn path(&self) -> Path {
        self.path.clone()
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
