use alloc::boxed::Box;
use alloc::{vec, vec::Vec};
use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use spin::Mutex;

use crate::error::Result;
use crate::user::process::syscall::args::{EpollEvent, EpollEvents};

use super::{Events, FileDescriptor, OpenFileDescription};

pub struct Epoll {
    interest_list: Mutex<Vec<InterestListEntry>>,
}

impl Epoll {
    pub fn new() -> Self {
        Self {
            interest_list: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl OpenFileDescription for Epoll {
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
}

struct InterestListEntry {
    fd: FileDescriptor,
    event: EpollEvent,
}
