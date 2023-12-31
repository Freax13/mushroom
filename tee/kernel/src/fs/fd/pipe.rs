use core::iter::from_fn;

use crate::{spin::mutex::Mutex, user::process::syscall::args::OpenFlags};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc};
use async_trait::async_trait;

use super::{Events, OpenFileDescription};
use crate::{
    error::{Error, Result},
    rt::notify::{Notify, NotifyOnDrop},
    user::process::syscall::args::{FileMode, FileType, FileTypeAndMode, Stat, Timespec},
};

struct State {
    buffer: Mutex<VecDeque<u8>>,
}

pub struct ReadHalf {
    notify: Arc<Notify>,
    state: Arc<State>,
}

#[async_trait]
impl OpenFileDescription for ReadHalf {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut guard = self.state.buffer.lock();

        // Check if there is data to receive.
        if guard.is_empty() {
            // Check if the write half has been closed.
            if Arc::strong_count(&self.state) == 1 {
                return Ok(0);
            }

            return Err(Error::again(()));
        }

        let mut read = 0;
        for (dest, src) in buf.iter_mut().zip(from_fn(|| guard.pop_front())) {
            *dest = src;
            read += 1;
        }

        Ok(read)
    }

    fn poll_ready(&self, events: Events) -> Result<Events> {
        let guard = self.state.buffer.lock();

        let mut ready_events = Events::empty();

        ready_events.set(
            Events::READ,
            !guard.is_empty() || Arc::strong_count(&self.state) == 1,
        );

        ready_events &= events;
        Ok(ready_events)
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        loop {
            let wait = self.notify.wait();

            let events = self.poll_ready(events)?;
            if !events.is_empty() {
                return Ok(events);
            }

            wait.await;
        }
    }

    fn stat(&self) -> Stat {
        Stat {
            dev: 0,
            ino: 0,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Fifo, FileMode::ALL),
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        }
    }
}

pub struct WriteHalf {
    state: Arc<State>,
    notify: NotifyOnDrop,
}

impl OpenFileDescription for WriteHalf {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut guard = self.state.buffer.lock();
        guard.extend(buf.iter().copied());
        drop(guard);

        self.notify.notify();

        Ok(buf.len())
    }

    fn stat(&self) -> Stat {
        Stat {
            dev: 0,
            ino: 0,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Fifo, FileMode::ALL),
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        }
    }
}

pub fn new() -> (ReadHalf, WriteHalf) {
    let state = Arc::new(State {
        buffer: Mutex::new(VecDeque::new()),
    });
    let notify = Arc::new(Notify::new());

    (
        ReadHalf {
            state: state.clone(),
            notify: notify.clone(),
        },
        WriteHalf {
            state,
            notify: NotifyOnDrop(notify),
        },
    )
}
