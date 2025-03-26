use core::future::pending;

use alloc::{boxed::Box, sync::Arc};
use async_trait::async_trait;

use crate::{
    error::{Result, bail},
    fs::{
        FileSystem,
        node::{FileAccessContext, Link},
        path::Path,
    },
    user::process::{
        syscall::args::{FileMode, OpenFlags, Stat},
        thread::{Gid, Uid},
    },
};

use super::{Events, FileLock, NonEmptyEvents, OpenFileDescription};

pub struct PathFd {
    link: Link,
}

impl PathFd {
    pub fn new(link: Link) -> Self {
        Self { link }
    }
}

#[async_trait]
impl OpenFileDescription for PathFd {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn path(&self) -> Result<Path> {
        self.link.location.path()
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(BadF)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        bail!(BadF)
    }

    fn stat(&self) -> Result<Stat> {
        self.link.node.stat()
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        self.link.node.fs()
    }

    fn as_dir(&self, _ctx: &mut FileAccessContext) -> Result<Link> {
        Ok(self.link.clone())
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

    fn path_fd_link(&self) -> Option<&Link> {
        Some(&self.link)
    }
}
