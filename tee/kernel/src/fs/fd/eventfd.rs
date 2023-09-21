use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytemuck::pod_read_unaligned;

use super::{Events, OpenFileDescription};
use crate::{
    error::{Error, Result},
    fs::node::new_ino,
    rt::notify::Notify,
    user::process::syscall::args::{FileMode, FileType, FileTypeAndMode, Stat, Timespec},
};

pub struct EventFd {
    ino: u64,
    notify: Notify,
    counter: AtomicU64,
}

impl EventFd {
    pub fn new(initval: u32) -> Self {
        Self {
            ino: new_ino(),
            notify: Notify::new(),
            counter: AtomicU64::new(u64::from(initval)),
        }
    }
}

#[async_trait]
impl OpenFileDescription for EventFd {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() != 8 {
            return Err(Error::inval(()));
        }

        let value = self.counter.swap(0, Ordering::SeqCst);
        if value == 0 {
            return Err(Error::again(()));
        }

        buf.copy_from_slice(&value.to_ne_bytes());
        Ok(8)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        if buf.len() != 8 {
            return Err(Error::inval(()));
        }

        let add = pod_read_unaligned::<u64>(buf);
        if add != 0 {
            let mut old_value = self.counter.load(Ordering::SeqCst);
            loop {
                let new_value = old_value.checked_add(add).ok_or_else(|| Error::again(()))?;
                let res = self.counter.compare_exchange(
                    old_value,
                    new_value,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                match res {
                    Ok(_) => break,
                    Err(new_value) => old_value = new_value,
                }
            }

            // If the READ readiness changed send a notification.
            if old_value == 0 {
                self.notify.notify();
            }
        }

        Ok(8)
    }

    fn poll_ready(&self, events: Events) -> Result<Events> {
        let counter_value = self.counter.load(Ordering::SeqCst);

        let mut ready_events = Events::empty();

        ready_events.set(Events::READ, counter_value != 0);
        ready_events.set(Events::WRITE, counter_value != !0);

        ready_events &= events;
        Ok(ready_events)
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        loop {
            let wait = self.notify.wait();

            let ready_events = self.poll_ready(events)?;
            if !ready_events.is_empty() {
                return Ok(ready_events);
            }

            wait.await;
        }
    }

    #[inline]
    fn stat(&self) -> Stat {
        Stat {
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
        }
    }
}
