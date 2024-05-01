use crate::fs::node::new_ino;
use crate::spin::mutex::Mutex;
use alloc::boxed::Box;
use alloc::{vec, vec::Vec};
use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::error::Result;
use crate::user::process::syscall::args::{
    EpollEvent, EpollEvents, FileMode, FileType, FileTypeAndMode, OpenFlags, Stat, Timespec,
};

use super::{Events, FileDescriptor, OpenFileDescription};

pub struct Epoll {
    ino: u64,
    interest_list: Mutex<Vec<InterestListEntry>>,
}

impl Epoll {
    pub fn new() -> Self {
        Self {
            ino: new_ino(),
            interest_list: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl OpenFileDescription for Epoll {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    async fn epoll_wait(&self, _maxevents: usize) -> Result<Vec<EpollEvent>> {
        let guard = self.interest_list.lock();
        let mut events = guard
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
        let mut guard = self.interest_list.lock();

        // Register the file descriptor.
        guard.push(InterestListEntry { fd, event });

        Ok(())
    }

    #[inline]
    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Unknown, FileMode::from_bits_truncate(0o600)),
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & Events::empty()
    }
}

struct InterestListEntry {
    fd: FileDescriptor,
    event: EpollEvent,
}
