use crate::fs::node::{new_ino, FileAccessContext};
use crate::fs::ownership::Ownership;
use crate::fs::path::Path;
use crate::fs::FileSystem;
use crate::spin::mutex::Mutex;
use crate::user::process::thread::{Gid, Uid};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::{vec, vec::Vec};
use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::error::{bail, Result};
use crate::user::process::syscall::args::{
    EpollEvent, EpollEvents, FileMode, FileType, FileTypeAndMode, OpenFlags, Stat, Timespec,
};

use super::{Events, FileDescriptor, FileLock, OpenFileDescription};

pub struct Epoll {
    ino: u64,
    internal: Mutex<EpollInternal>,
    file_lock: FileLock,
}

struct EpollInternal {
    interest_list: Vec<InterestListEntry>,
    ownership: Ownership,
}

impl Epoll {
    pub fn new(uid: Uid, gid: Gid) -> Self {
        Self {
            ino: new_ino(),
            internal: Mutex::new(EpollInternal {
                interest_list: Vec::new(),
                ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
            }),
            file_lock: FileLock::anonymous(),
        }
    }
}

#[async_trait]
impl OpenFileDescription for Epoll {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn path(&self) -> Path {
        Path::new(b"anon_inode:[eventpoll]".to_vec()).unwrap()
    }

    async fn epoll_wait(&self, _maxevents: usize) -> Result<Vec<EpollEvent>> {
        let guard = self.internal.lock();
        let mut events = guard
            .interest_list
            .iter()
            .map(|e| async move {
                let events = e.fd.ready(Events::from(e.event.events)).await?;
                Result::<_>::Ok(EpollEvent::new(EpollEvents::from(events), e.event.data))
            })
            .collect::<FuturesUnordered<_>>();
        let event = events.next().await.unwrap()?;

        Ok(vec![event])
    }

    fn epoll_add(&self, fd: FileDescriptor, event: EpollEvent) -> Result<()> {
        let mut guard = self.internal.lock();

        // Register the file descriptor.
        guard.interest_list.push(InterestListEntry { fd, event });

        Ok(())
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
    }

    #[inline]
    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Unknown, guard.ownership.mode()),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        bail!(BadF)
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & Events::empty()
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

struct InterestListEntry {
    fd: FileDescriptor,
    event: EpollEvent,
}
