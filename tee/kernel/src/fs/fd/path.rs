use core::future::pending;

use alloc::{boxed::Box, sync::Arc};
use async_trait::async_trait;

use crate::{
    error::{Result, bail},
    fs::{
        FileSystem,
        node::{DynINode, FileAccessContext},
        path::Path,
    },
    user::process::{
        syscall::args::{FileMode, OpenFlags, Stat},
        thread::{Gid, Uid},
    },
};

use super::{Events, FileLock, NonEmptyEvents, OpenFileDescription};

pub struct PathFd {
    path: Path,
    node: DynINode,
}

impl PathFd {
    pub fn new(path: Path, node: DynINode) -> Self {
        Self { path, node }
    }
}

#[async_trait]
impl OpenFileDescription for PathFd {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn path(&self) -> Result<Path> {
        Ok(self.path.clone())
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

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        self.node.fs()
    }

    fn as_dir(&self, _ctx: &mut FileAccessContext) -> Result<DynINode> {
        Ok(self.node.clone())
    }

    fn poll_ready(&self, _events: Events) -> Option<NonEmptyEvents> {
        None
    }

    async fn ready(&self, _events: Events) -> NonEmptyEvents {
        pending().await
    }

    fn file_lock(&self) -> Result<&FileLock> {
        bail!(BadF)
    }

    fn path_fd_node(&self) -> Option<(Path, DynINode)> {
        Some((self.path.clone(), self.node.clone()))
    }
}
