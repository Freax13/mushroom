use crate::{
    error::{bail, Result},
    fs::{
        node::{DynINode, FileAccessContext},
        path::Path,
    },
    user::process::{
        syscall::args::{FileMode, OpenFlags, Stat},
        thread::{Gid, Uid},
    },
};

use super::{Events, FileLock, OpenFileDescription};

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

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(BadF)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        bail!(BadF)
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

    fn file_lock(&self) -> Result<&FileLock> {
        bail!(BadF)
    }
}
