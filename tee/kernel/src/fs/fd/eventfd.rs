use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytemuck::pod_read_unaligned;

use super::{Events, FileLock, OpenFileDescription};
use crate::{
    error::{ensure, err, Result},
    fs::{
        node::{new_ino, FileAccessContext},
        ownership::Ownership,
        path::Path,
        FileSystem, ANON_INODE_FS,
    },
    rt::notify::Notify,
    spin::mutex::Mutex,
    user::process::{
        memory::VirtualMemory,
        syscall::args::{FileMode, FileType, FileTypeAndMode, OpenFlags, Pointer, Stat, Timespec},
        thread::{Gid, Uid},
    },
};

pub struct EventFd {
    ino: u64,
    internal: Mutex<EventFdInternal>,
    notify: Notify,
    counter: AtomicU64,
    file_lock: FileLock,
}

struct EventFdInternal {
    ownership: Ownership,
}

impl EventFd {
    pub fn new(initval: u32, uid: Uid, gid: Gid) -> Self {
        Self {
            ino: new_ino(),
            internal: Mutex::new(EventFdInternal {
                ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
            }),
            notify: Notify::new(),
            counter: AtomicU64::new(u64::from(initval)),
            file_lock: FileLock::anonymous(),
        }
    }
}

#[async_trait]
impl OpenFileDescription for EventFd {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn path(&self) -> Result<Path> {
        Path::new(b"anon_inode:[eventfd]".to_vec())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let buf = buf.get_mut(0..8).ok_or(err!(Inval))?;

        let value = self.counter.swap(0, Ordering::SeqCst);
        ensure!(value != 0, Again);

        buf.copy_from_slice(&value.to_ne_bytes());
        Ok(8)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let buf = buf.get(0..8).ok_or(err!(Inval))?;
        let add = pod_read_unaligned::<u64>(buf);
        ensure!(add != !0, Inval);
        if add != 0 {
            let mut old_value = self.counter.load(Ordering::SeqCst);
            loop {
                let new_value = old_value.checked_add(add).ok_or(err!(Again))?;
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

    fn write_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        ensure!(len >= 8, Inval);

        let mut buf = [0; 8];
        vm.read_bytes(pointer.get(), &mut buf)?;
        self.write(&buf)
    }

    fn poll_ready(&self, events: Events) -> Events {
        let counter_value = self.counter.load(Ordering::SeqCst);

        let mut ready_events = Events::empty();

        ready_events.set(Events::READ, counter_value != 0);
        ready_events.set(Events::WRITE, counter_value != !0);

        ready_events &= events;
        ready_events
    }

    fn epoll_ready(&self, events: Events) -> Result<Events> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        loop {
            let wait = self.notify.wait();

            let ready_events = self.epoll_ready(events)?;
            if !ready_events.is_empty() {
                return Ok(ready_events);
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
        Ok(ANON_INODE_FS.clone())
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}
