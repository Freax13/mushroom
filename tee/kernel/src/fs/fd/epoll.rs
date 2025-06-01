use core::future::pending;

use crate::fs::FileSystem;
use crate::fs::node::{FileAccessContext, new_ino};
use crate::fs::ownership::Ownership;
use crate::fs::path::Path;
use crate::rt::notify::Notify;
use crate::spin::mutex::Mutex;
use crate::user::process::thread::{Gid, Uid};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use futures::FutureExt;
use futures::future::{Either, select};
use futures::stream::{FuturesUnordered, StreamExt};

use crate::error::{Result, bail, ensure, err};
use crate::user::process::syscall::args::{
    EpollEvent, EpollEvents, FileMode, FileType, FileTypeAndMode, OpenFlags, Stat, Timespec,
};

use super::{Events, FileDescriptor, FileLock, NonEmptyEvents, OpenFileDescription};

pub struct Epoll {
    ino: u64,
    internal: Mutex<EpollInternal>,
    /// The wakers on this notify are woken every time the interest list is updated.
    notify: Notify,
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
            notify: Notify::new(),
            file_lock: FileLock::anonymous(),
        }
    }

    /// Returns an iterator over futures that wait for a fd to be come ready.
    fn ready_futures(&self) -> impl Iterator<Item = impl Future<Output = EpollEvent>> {
        let mut guard = self.internal.lock();
        let mut i = 0;
        core::iter::from_fn(move || {
            loop {
                let entry = guard.interest_list.get(i)?;
                // Remove closed fds.
                if entry.fd.is_closed() {
                    guard.interest_list.swap_remove(i);
                    continue;
                }

                i += 1;
                let fd = entry.fd.clone();
                let events = entry.event.events;
                let data = entry.event.data;
                return Some(async move {
                    let events = fd.ready(Events::from(events)).await;
                    // If the fd was closed, stall.
                    if fd.is_closed() {
                        pending::<()>().await;
                    }
                    EpollEvent::new(EpollEvents::from(Events::from(events)), data)
                });
            }
        })
    }

    /// Waits for an fd to become ready and also returns a non-blocking iterator to may return more ready fds.
    async fn poll(&self) -> (EpollEvent, impl Iterator<Item = EpollEvent>) {
        let mut futures = FuturesUnordered::new();
        loop {
            let wait = self.notify.wait();

            futures.clear();
            futures.extend(self.ready_futures());

            let ready = futures.next();

            let Either::Left((res, wait)) = select(ready, wait).await else {
                // The interested list was modified. Start over.
                continue;
            };
            let Some(ready_fd) = res else {
                // There are no file descriptors at all. Wait for the
                // interested list to change and start over.
                wait.await;
                continue;
            };

            let more = core::iter::from_fn(move || futures.next().now_or_never().flatten());
            return (ready_fd, more);
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

    async fn epoll_wait(&self, maxevents: usize) -> Result<Vec<EpollEvent>> {
        let (first, more) = self.poll().await;
        let events = core::iter::once(first)
            .chain(more)
            .take(maxevents)
            .collect();
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
        drop(guard);
        self.notify.notify();
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
        drop(guard);
        self.notify.notify();
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
        drop(guard);
        self.notify.notify();
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

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        if !events.contains(Events::READ) {
            return None;
        }
        let ready = self.ready_futures().any(|fut| fut.now_or_never().is_some());
        ready.then_some(NonEmptyEvents::READ)
    }

    fn epoll_ready(&self, events: Events) -> Result<Option<NonEmptyEvents>> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        if !events.contains(Events::READ) {
            return pending().await;
        }
        let (_, _) = self.poll().await;
        NonEmptyEvents::READ
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

struct InterestListEntry {
    fd: FileDescriptor,
    event: EpollEvent,
}
