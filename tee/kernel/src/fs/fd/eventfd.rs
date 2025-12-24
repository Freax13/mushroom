use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

use crate::{
    error::{Result, ensure, err},
    fs::{
        ANON_INODE_FS, FileSystem,
        fd::{
            BsdFileLock, Events, NonEmptyEvents, OpenFileDescription, OpenFileDescriptionData,
            ReadBuf, WriteBuf,
            epoll::{AtomicEventCounter, EpollReady, EpollRequest, EpollResult, WeakEpollReady},
        },
        node::{FileAccessContext, new_ino},
        ownership::Ownership,
        path::Path,
    },
    rt::notify::Notify,
    spin::mutex::Mutex,
    user::{
        syscall::args::{
            EventFdFlags, FileMode, FileType, FileTypeAndMode, OpenFlags, Stat, Timespec,
        },
        thread::{Gid, Uid},
    },
};

pub struct EventFd {
    ino: u64,
    semaphore: bool,
    internal: Mutex<EventFdInternal>,
    notify: Notify,
    counter: AtomicU64,
    read_event_counter: AtomicEventCounter,
    write_event_counter: AtomicEventCounter,
    bsd_file_lock: BsdFileLock,
}

struct EventFdInternal {
    flags: OpenFlags,
    ownership: Ownership,
}

impl EventFd {
    pub fn new(initval: u32, flags: EventFdFlags, uid: Uid, gid: Gid) -> Self {
        let semaphore = flags.contains(EventFdFlags::SEMAPHORE);
        Self {
            ino: new_ino(),
            semaphore,
            internal: Mutex::new(EventFdInternal {
                flags: flags.into(),
                ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
            }),
            notify: Notify::new(),
            counter: AtomicU64::new(u64::from(initval)),
            read_event_counter: AtomicEventCounter::new(),
            write_event_counter: AtomicEventCounter::new(),
            bsd_file_lock: BsdFileLock::anonymous(),
        }
    }
}

#[async_trait]
impl OpenFileDescription for EventFd {
    fn flags(&self) -> OpenFlags {
        self.internal.lock().flags
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.internal.lock().flags.update(flags);
    }

    fn set_non_blocking(&self, non_blocking: bool) {
        self.internal
            .lock()
            .flags
            .set(OpenFlags::NONBLOCK, non_blocking);
    }

    fn path(&self) -> Result<Path> {
        Path::new(b"anon_inode:[eventfd]".to_vec())
    }

    fn read(&self, buf: &mut dyn ReadBuf, _: &FileAccessContext) -> Result<usize> {
        ensure!(buf.buffer_len() >= 8, Inval);

        let value = if !self.semaphore {
            let value = self.counter.swap(0, Ordering::SeqCst);
            ensure!(value != 0, Again);
            value
        } else {
            self.counter
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                    value.checked_sub(1)
                })
                .map_err(|_| err!(Again))?;
            1
        };
        buf.write(0, &value.to_ne_bytes())?;

        self.write_event_counter.inc();
        self.notify.notify();

        Ok(8)
    }

    fn write(&self, buf: &dyn WriteBuf, _: &FileAccessContext) -> Result<usize> {
        ensure!(buf.buffer_len() >= 8, Inval);

        let mut bytes = [0; 8];
        buf.read(0, &mut bytes)?;
        let add = u64::from_ne_bytes(bytes);
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
        }

        self.read_event_counter.inc();
        self.notify.notify();

        Ok(8)
    }

    fn poll_ready(&self, events: Events, _: &FileAccessContext) -> Option<NonEmptyEvents> {
        let counter_value = self.counter.load(Ordering::SeqCst);

        let mut ready_events = Events::empty();

        ready_events.set(Events::READ, counter_value != 0);
        ready_events.set(Events::WRITE, counter_value != !0);

        ready_events &= events;
        NonEmptyEvents::new(ready_events)
    }

    async fn ready(&self, events: Events, ctx: &FileAccessContext) -> NonEmptyEvents {
        self.notify
            .wait_until(|| self.poll_ready(events, ctx))
            .await
    }

    fn epoll_ready(
        self: Arc<OpenFileDescriptionData<Self>>,
        _: &FileAccessContext,
    ) -> Result<Box<dyn WeakEpollReady>> {
        Ok(Box::new(Arc::downgrade(&self)))
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

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
        Ok(&self.bsd_file_lock)
    }
}

#[async_trait]
impl EpollReady for EventFd {
    async fn epoll_ready(&self, req: &EpollRequest) -> EpollResult {
        self.notify
            .epoll_loop(req, || {
                let mut result = EpollResult::new();
                let counter_value = self.counter.load(Ordering::SeqCst);
                if counter_value != 0 {
                    result.set_ready(Events::READ);
                    result.add_atomic_counter(Events::READ, &self.read_event_counter);
                }
                if counter_value != !0 {
                    result.set_ready(Events::WRITE);
                    result.add_atomic_counter(Events::WRITE, &self.write_event_counter);
                }
                result
            })
            .await
    }
}
