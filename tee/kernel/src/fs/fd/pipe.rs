use core::{cmp, iter::from_fn};

use crate::{
    spin::mutex::Mutex,
    user::process::{
        memory::ActiveVirtualMemory,
        syscall::args::{OpenFlags, Pipe2Flags, Pointer},
    },
};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc};
use async_trait::async_trait;
use usize_conversions::FromUsize;

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
    flags: Mutex<OpenFlags>,
}

#[async_trait]
impl OpenFileDescription for ReadHalf {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock()
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.flags.lock().update(flags);
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

    fn read_to_user(
        &self,
        vm: &mut ActiveVirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let mut guard = self.state.buffer.lock();

        // Check if there is data to receive.
        if guard.is_empty() {
            // Check if the write half has been closed.
            if Arc::strong_count(&self.state) == 1 {
                return Ok(0);
            }

            return Err(Error::again(()));
        }

        let len = cmp::min(len, guard.len());
        let (slice1, slice2) = guard.as_slices();
        let len1 = cmp::min(len, slice1.len());
        let len2 = len - len1;
        let slice1 = &slice1[..len1];
        let slice2 = &slice2[..len2];

        // Copy the bytes to userspace.
        vm.write_bytes(pointer.get(), slice1)?;
        if !slice2.is_empty() {
            vm.write_bytes(pointer.get() + u64::from_usize(len1), slice2)?;
        }

        // Remove the bytes from the VecDeque.
        guard.drain(..len);

        Ok(len)
    }

    fn poll_ready(&self, events: Events) -> Events {
        let guard = self.state.buffer.lock();

        let mut ready_events = Events::empty();

        ready_events.set(
            Events::READ,
            !guard.is_empty() || Arc::strong_count(&self.state) == 1,
        );

        ready_events &= events;
        ready_events
    }

    fn epoll_ready(&self, events: Events) -> Result<Events> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        loop {
            let wait = self.notify.wait();

            let events = self.epoll_ready(events)?;
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
    flags: Mutex<OpenFlags>,
}

impl OpenFileDescription for WriteHalf {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock()
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.flags.lock().update(flags);
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut guard = self.state.buffer.lock();
        guard.extend(buf.iter().copied());
        drop(guard);

        self.notify.notify();

        Ok(buf.len())
    }

    fn write_from_user(
        &self,
        vm: &mut ActiveVirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let mut guard = self.state.buffer.lock();

        let start_idx = guard.len();
        // Reserve some space for the new bytes.
        guard.resize(start_idx + len, 0);

        let (first, second) = guard.as_mut_slices();
        let res = {
            if second.len() >= len {
                let second_len = second.len();
                vm.read_bytes(pointer.get(), &mut second[second_len - len..])
            } else {
                let first_write_len = len - second.len();
                let first_len = first.len();
                vm.read_bytes(pointer.get(), &mut first[first_len - first_write_len..])
                    .and_then(|_| {
                        vm.read_bytes(pointer.get() + u64::from_usize(first_write_len), second)
                    })
            }
        };

        // Rollback all bytes if an error occured.
        // FIXME: We should not roll back all bytes.
        if res.is_err() {
            guard.truncate(start_idx);
        }

        drop(guard);

        if res.is_ok() {
            self.notify.notify();
        }

        Ok(len)
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

    fn poll_ready(&self, events: Events) -> Events {
        events & Events::WRITE
    }
}

pub fn new(flags: Pipe2Flags) -> (ReadHalf, WriteHalf) {
    let state = Arc::new(State {
        buffer: Mutex::new(VecDeque::new()),
    });
    let notify = Arc::new(Notify::new());
    let flags = flags.into();

    (
        ReadHalf {
            state: state.clone(),
            notify: notify.clone(),
            flags: Mutex::new(flags),
        },
        WriteHalf {
            state,
            notify: NotifyOnDrop(notify),
            flags: Mutex::new(flags),
        },
    )
}
