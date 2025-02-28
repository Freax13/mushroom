use core::future::pending;

use crate::fs::FileSystem;
use crate::fs::node::{FileAccessContext, new_ino};
use crate::fs::ownership::Ownership;
use crate::fs::path::Path;
use crate::spin::mutex::Mutex;
use crate::user::process::thread::{Gid, Uid};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::{vec, vec::Vec};
use async_trait::async_trait;
use futures::FutureExt;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::error::{Result, bail, ensure, err};
use crate::user::process::syscall::args::{
    EpollEvent, EpollEvents, FileMode, FileType, FileTypeAndMode, OpenFlags, Stat, Timespec,
};

use super::{Events, FileDescriptor, FileLock, NonEmptyEvents, OpenFileDescription};

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

    fn path(&self) -> Result<Path> {
        Path::new(b"anon_inode:[eventpoll]".to_vec())
    }

    async fn epoll_wait(&self, _maxevents: usize) -> Result<Vec<EpollEvent>> {
        let guard = self.internal.lock();
        let mut futures = guard
            .interest_list
            .iter()
            .map(|e| {
                let fd = e.fd.clone();
                let events = e.event.events;
                let data = e.event.data;
                async move {
                    let events = fd.ready(Events::from(events)).await;
                    EpollEvent::new(EpollEvents::from(Events::from(events)), data)
                }
            })
            .collect::<FuturesUnordered<_>>();
        drop(guard);

        if futures.is_empty() {
            return Ok(Vec::new());
        }

        // Wait for the first event.
        let event = futures.next().await.unwrap();
        let mut events = vec![event];

        // Check if any more futures are ready, but don't wait.
        while let Some(event) = futures.next().now_or_never().flatten() {
            events.push(event);
        }

        Ok(events)
    }

    fn epoll_add(&self, fd: FileDescriptor, event: EpollEvent) -> Result<()> {
        let mut guard = self.internal.lock();

        // Make sure that the file descriptor is not already registered.
        ensure!(
            !guard.interest_list.iter().any(|entry| entry.fd == fd),
            Exist
        );

        // Register the file descriptor.
        guard.interest_list.push(InterestListEntry { fd, event });

        Ok(())
    }

    fn epoll_del(&self, fd: &dyn OpenFileDescription) -> Result<()> {
        let mut guard = self.internal.lock();
        let idx = guard
            .interest_list
            .iter()
            .position(|entry| entry.fd == *fd)
            .ok_or(err!(NoEnt))?;
        guard.interest_list.swap_remove(idx);
        Ok(())
    }

    fn epoll_mod(&self, fd: &dyn OpenFileDescription, event: EpollEvent) -> Result<()> {
        let mut guard = self.internal.lock();
        let entry = guard
            .interest_list
            .iter_mut()
            .find(|entry| entry.fd == *fd)
            .ok_or(err!(NoEnt))?;
        entry.event = event;
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

    fn poll_ready(&self, _events: Events) -> Option<NonEmptyEvents> {
        None
    }

    async fn ready(&self, _events: Events) -> NonEmptyEvents {
        pending().await
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

struct InterestListEntry {
    fd: FileDescriptor,
    event: EpollEvent,
}
