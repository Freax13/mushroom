use core::{cmp, iter::from_fn};

use crate::{
    error::{bail, ensure},
    fs::{
        node::{new_ino, FileAccessContext},
        ownership::Ownership,
        path::Path,
    },
    spin::mutex::Mutex,
    user::process::{
        memory::VirtualMemory,
        syscall::args::{OpenFlags, Pipe2Flags, Pointer},
        thread::{Gid, Uid},
    },
};
use alloc::{boxed::Box, collections::VecDeque, format, sync::Arc};
use async_trait::async_trait;
use usize_conversions::FromUsize;

use super::{Events, FileLock, OpenFileDescription};
use crate::{
    error::Result,
    rt::notify::{Notify, NotifyOnDrop},
    user::process::syscall::args::{FileMode, FileType, FileTypeAndMode, Stat, Timespec},
};

const CAPACITY: usize = 0x10000;

fn path(ino: u64) -> Path {
    Path::new(format!("pipe:[{ino}]",).into_bytes()).unwrap()
}

struct Internal {
    buffer: VecDeque<u8>,
    ownership: Ownership,
}

pub struct ReadHalf {
    ino: u64,
    internal: Arc<Mutex<Internal>>,
    notify: NotifyOnDrop,
    flags: Mutex<OpenFlags>,
    file_lock: FileLock,
}

#[async_trait]
impl OpenFileDescription for ReadHalf {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock()
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.flags.lock().update(flags);
    }

    fn path(&self) -> Path {
        path(self.ino)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut guard = self.internal.lock();

        // Check if there is data to receive.
        if guard.buffer.is_empty() {
            // Check if the write half has been closed.
            if Arc::strong_count(&self.internal) == 1 {
                return Ok(0);
            }

            bail!(Again);
        }

        let was_full = guard.buffer.len() == CAPACITY;

        let mut read = 0;
        for (dest, src) in buf.iter_mut().zip(from_fn(|| guard.buffer.pop_front())) {
            *dest = src;
            read += 1;
        }

        let is_full = guard.buffer.len() == CAPACITY;
        if was_full && !is_full {
            self.notify.notify();
        }

        Ok(read)
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let mut guard = self.internal.lock();

        // Check if there is data to receive.
        if guard.buffer.is_empty() {
            // Check if the write half has been closed.
            if Arc::strong_count(&self.internal) == 1 {
                return Ok(0);
            }

            bail!(Again);
        }

        let was_full = guard.buffer.len() == CAPACITY;

        let len = cmp::min(len, guard.buffer.len());
        let (slice1, slice2) = guard.buffer.as_slices();
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
        guard.buffer.drain(..len);

        let is_full = guard.buffer.len() == CAPACITY;
        if was_full && !is_full {
            self.notify.notify();
        }

        Ok(len)
    }

    fn poll_ready(&self, events: Events) -> Events {
        let guard = self.internal.lock();

        let mut ready_events = Events::empty();

        ready_events.set(
            Events::READ,
            !guard.buffer.is_empty() || Arc::strong_count(&self.internal) == 1,
        );
        ready_events.set(Events::HUP, Arc::strong_count(&self.internal) == 1);

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

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        Ok(Stat {
            dev: 0,
            ino: 0,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Fifo, guard.ownership.mode()),
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

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

pub struct WriteHalf {
    ino: u64,
    internal: Arc<Mutex<Internal>>,
    notify: NotifyOnDrop,
    flags: Mutex<OpenFlags>,
    file_lock: FileLock,
}

#[async_trait::async_trait]
impl OpenFileDescription for WriteHalf {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock()
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.flags.lock().update(flags);
    }

    fn path(&self) -> Path {
        path(self.ino)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        // Check if the write half has been closed.
        ensure!(Arc::strong_count(&self.internal) > 1, Pipe);

        if buf.is_empty() {
            return Ok(0);
        }

        let mut guard = self.internal.lock();

        let max_remaining_capacity = CAPACITY - guard.buffer.len();
        ensure!(max_remaining_capacity > 0, Again);
        let len = cmp::min(buf.len(), max_remaining_capacity);
        let buf = &buf[..len];

        guard.buffer.extend(buf.iter().copied());
        drop(guard);

        self.notify.notify();

        Ok(buf.len())
    }

    fn write_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        // Check if the write half has been closed.
        ensure!(Arc::strong_count(&self.internal) > 1, Pipe);

        if len == 0 {
            return Ok(0);
        }

        let mut guard = self.internal.lock();

        let max_remaining_capacity = CAPACITY - guard.buffer.len();
        ensure!(max_remaining_capacity > 0, Again);
        let len = cmp::min(len, max_remaining_capacity);

        let start_idx = guard.buffer.len();
        // Reserve some space for the new bytes.
        guard.buffer.resize(start_idx + len, 0);

        let (first, second) = guard.buffer.as_mut_slices();
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
            guard.buffer.truncate(start_idx);
        }

        drop(guard);

        if res.is_ok() {
            self.notify.notify();
        }

        Ok(len)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        Ok(Stat {
            dev: 0,
            ino: 0,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Fifo, guard.ownership.mode()),
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

    fn poll_ready(&self, events: Events) -> Events {
        let mut ready_events = Events::empty();

        let guard = self.internal.lock();
        ready_events.set(
            Events::WRITE,
            guard.buffer.len() < CAPACITY || Arc::strong_count(&self.internal) == 1,
        );
        ready_events.set(Events::ERR, Arc::strong_count(&self.internal) == 1);
        drop(guard);

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

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

pub fn new(flags: Pipe2Flags, uid: Uid, gid: Gid) -> (ReadHalf, WriteHalf) {
    let ino = new_ino();
    let internal = Arc::new(Mutex::new(Internal {
        buffer: VecDeque::new(),
        ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
    }));
    let notify = Arc::new(Notify::new());
    let flags = flags.into();

    (
        ReadHalf {
            ino,
            internal: internal.clone(),
            notify: NotifyOnDrop(notify.clone()),
            flags: Mutex::new(flags),
            file_lock: FileLock::anonymous(),
        },
        WriteHalf {
            ino,
            internal,
            notify: NotifyOnDrop(notify),
            flags: Mutex::new(flags | OpenFlags::WRONLY),
            file_lock: FileLock::anonymous(),
        },
    )
}
