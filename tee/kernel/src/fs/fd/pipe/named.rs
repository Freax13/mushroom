use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
};
use core::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use futures::future;

use crate::{
    error::{Result, ensure},
    fs::{
        FileSystem,
        fd::{
            BsdFileLock, Events, NonEmptyEvents, OpenFileDescription, ReadBuf,
            StrongFileDescriptor, WriteBuf,
            pipe::{CAPACITY, PIPE_BUF},
            stream_buffer,
        },
        node::{FileAccessContext, Link},
        path::Path,
    },
    rt::notify::Notify,
    spin::mutex::Mutex,
    user::{
        syscall::args::{FileMode, OpenFlags, Stat},
        thread::{Gid, Uid},
    },
};

pub struct NamedPipe {
    internal: Mutex<NamedPipeInternal>,
    read_open_counter: AtomicU64,
    write_open_counter: AtomicU64,
    notify: Notify,
}

struct NamedPipeInternal {
    read_half: Weak<stream_buffer::ReadHalf>,
    write_half: Weak<stream_buffer::WriteHalf>,
}

impl NamedPipe {
    pub fn new() -> Self {
        Self {
            internal: Mutex::new(NamedPipeInternal {
                read_half: Weak::new(),
                write_half: Weak::new(),
            }),
            read_open_counter: AtomicU64::new(0),
            write_open_counter: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    pub async fn open(&self, flags: OpenFlags, link: Link) -> Result<StrongFileDescriptor> {
        let mut guard = self.internal.lock();

        Ok(if flags.contains(OpenFlags::WRONLY) {
            let write_half = if let Some(write_half) = guard.write_half.upgrade() {
                write_half
            } else if let Some(write_half) =
                guard.read_half.upgrade().map(|read| read.make_write_half())
            {
                let write_half = Arc::new(write_half);
                guard.write_half = Arc::downgrade(&write_half);

                write_half
            } else {
                let (read_half, write_half) = stream_buffer::new(
                    CAPACITY,
                    stream_buffer::Type::Pipe {
                        atomic_write_size: PIPE_BUF,
                    },
                );
                let read_half = Arc::new(read_half);
                let write_half = Arc::new(write_half);

                guard.read_half = Arc::downgrade(&read_half);
                guard.write_half = Arc::downgrade(&write_half);

                write_half
            };

            self.write_open_counter.fetch_add(1, Ordering::SeqCst);
            self.notify.notify();

            if flags.contains(OpenFlags::NONBLOCK) {
                ensure!(guard.read_half.strong_count() > 1, XDev);
            } else {
                // Wait until at least one reader exists.
                let counter_value = self.read_open_counter.load(Ordering::SeqCst);
                let mut wait = self.notify.wait();
                loop {
                    if guard.read_half.strong_count() > 0
                        || counter_value != self.read_open_counter.load(Ordering::SeqCst)
                    {
                        break;
                    }

                    drop(guard);
                    wait.next().await;
                    guard = self.internal.lock();
                }
            }

            let bsd_file_lock = BsdFileLock::new(link.node.bsd_file_lock_record().clone());
            StrongFileDescriptor::from(WriteHalf {
                link,
                write_half,
                flags: Mutex::new(flags),
                bsd_file_lock,
            })
        } else if flags.contains(OpenFlags::RDWR) {
            let (read_half, write_half) =
                match (guard.read_half.upgrade(), guard.write_half.upgrade()) {
                    (Some(read_half), Some(write_half)) => (read_half, write_half),
                    (None, Some(write_half)) => {
                        let read_half = write_half.make_read_half();
                        let read_half = Arc::new(read_half);
                        guard.read_half = Arc::downgrade(&read_half);
                        (read_half, write_half)
                    }
                    (Some(read_half), None) => {
                        let write_half = read_half.make_write_half();
                        let write_half = Arc::new(write_half);
                        guard.write_half = Arc::downgrade(&write_half);
                        (read_half, write_half)
                    }
                    (None, None) => {
                        let (read_half, write_half) = stream_buffer::new(
                            CAPACITY,
                            stream_buffer::Type::Pipe {
                                atomic_write_size: PIPE_BUF,
                            },
                        );
                        let read_half = Arc::new(read_half);
                        let write_half = Arc::new(write_half);

                        guard.read_half = Arc::downgrade(&read_half);
                        guard.write_half = Arc::downgrade(&write_half);

                        (read_half, write_half)
                    }
                };

            self.read_open_counter.fetch_add(1, Ordering::Relaxed);
            self.write_open_counter.fetch_add(1, Ordering::Relaxed);
            self.notify.notify();

            let bsd_file_lock = BsdFileLock::new(link.node.bsd_file_lock_record().clone());
            StrongFileDescriptor::from(FullReadWrite {
                link,
                read_half,
                write_half,
                flags: Mutex::new(flags),
                bsd_file_lock,
            })
        } else {
            let read_half = if let Some(read_half) = guard.read_half.upgrade() {
                read_half
            } else if let Some(read_half) = guard
                .write_half
                .upgrade()
                .map(|write| write.make_read_half())
            {
                let read_half = Arc::new(read_half);
                guard.read_half = Arc::downgrade(&read_half);

                read_half
            } else {
                let (read_half, write_half) = stream_buffer::new(
                    CAPACITY,
                    stream_buffer::Type::Pipe {
                        atomic_write_size: PIPE_BUF,
                    },
                );
                let read_half = Arc::new(read_half);
                let write_half = Arc::new(write_half);

                guard.read_half = Arc::downgrade(&read_half);
                guard.write_half = Arc::downgrade(&write_half);

                read_half
            };

            self.read_open_counter.fetch_add(1, Ordering::Relaxed);
            self.notify.notify();

            if !flags.contains(OpenFlags::NONBLOCK) {
                // Wait until at least one writer exists.
                let counter_value = self.write_open_counter.load(Ordering::SeqCst);
                let mut wait = self.notify.wait();
                loop {
                    if guard.write_half.strong_count() > 0
                        || counter_value != self.write_open_counter.load(Ordering::SeqCst)
                    {
                        break;
                    }

                    drop(guard);
                    wait.next().await;
                    guard = self.internal.lock();
                }
            }

            let bsd_file_lock = BsdFileLock::new(link.node.bsd_file_lock_record().clone());
            StrongFileDescriptor::from(ReadHalf {
                link,
                read_half,
                flags: Mutex::new(flags),
                bsd_file_lock,
            })
        })
    }
}

struct ReadHalf {
    link: Link,
    read_half: Arc<stream_buffer::ReadHalf>,
    flags: Mutex<OpenFlags>,
    bsd_file_lock: BsdFileLock,
}

#[async_trait]
impl OpenFileDescription for ReadHalf {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock()
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.flags.lock().update(flags);
        self.read_half.notify().notify();
    }

    fn set_non_blocking(&self, non_blocking: bool) {
        self.flags.lock().set(OpenFlags::NONBLOCK, non_blocking);
        self.read_half.notify().notify();
    }

    fn path(&self) -> Result<Path> {
        self.link.location.path()
    }

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        self.read_half.read(buf, false)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.link.node.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.link.node.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        self.link.node.stat()
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        self.link.node.fs()
    }

    fn as_pipe_read_half(&self) -> Option<&stream_buffer::ReadHalf> {
        Some(&self.read_half)
    }

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        self.read_half.poll_ready(events)
    }

    fn epoll_ready(&self, events: Events) -> Result<Option<NonEmptyEvents>> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        self.read_half
            .notify()
            .wait_until(|| self.poll_ready(events))
            .await
    }

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
        Ok(&self.bsd_file_lock)
    }
}

struct WriteHalf {
    link: Link,
    write_half: Arc<stream_buffer::WriteHalf>,
    flags: Mutex<OpenFlags>,
    bsd_file_lock: BsdFileLock,
}

#[async_trait]
impl OpenFileDescription for WriteHalf {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock()
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.flags.lock().update(flags);
        self.write_half.notify().notify();
    }

    fn set_non_blocking(&self, non_blocking: bool) {
        self.flags.lock().set(OpenFlags::NONBLOCK, non_blocking);
        self.write_half.notify().notify();
    }

    fn path(&self) -> Result<Path> {
        self.link.location.path()
    }

    fn write(&self, buf: &dyn WriteBuf, _: &FileAccessContext) -> Result<usize> {
        self.write_half.write(buf)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.link.node.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.link.node.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        self.link.node.stat()
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        self.link.node.fs()
    }

    fn as_pipe_write_half(&self) -> Option<&stream_buffer::WriteHalf> {
        Some(&self.write_half)
    }

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        self.write_half.poll_ready(events)
    }

    fn epoll_ready(&self, events: Events) -> Result<Option<NonEmptyEvents>> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        self.write_half
            .notify()
            .wait_until(|| self.poll_ready(events))
            .await
    }

    async fn ready_for_write(&self, count: usize) {
        self.write_half.ready_for_write(count).await
    }

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
        Ok(&self.bsd_file_lock)
    }
}

struct FullReadWrite {
    link: Link,
    read_half: Arc<stream_buffer::ReadHalf>,
    write_half: Arc<stream_buffer::WriteHalf>,
    flags: Mutex<OpenFlags>,
    bsd_file_lock: BsdFileLock,
}

#[async_trait]
impl OpenFileDescription for FullReadWrite {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock()
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.flags.lock().update(flags);
        self.read_half.notify().notify();
        self.write_half.notify().notify();
    }

    fn set_non_blocking(&self, non_blocking: bool) {
        self.flags.lock().set(OpenFlags::NONBLOCK, non_blocking);
        self.read_half.notify().notify();
        self.write_half.notify().notify();
    }

    fn path(&self) -> Result<Path> {
        self.link.location.path()
    }

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        self.read_half.read(buf, false)
    }

    fn write(&self, buf: &dyn WriteBuf, _: &FileAccessContext) -> Result<usize> {
        self.write_half.write(buf)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.link.node.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.link.node.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        self.link.node.stat()
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        self.link.node.fs()
    }

    fn as_pipe_read_half(&self) -> Option<&stream_buffer::ReadHalf> {
        Some(&self.read_half)
    }

    fn as_pipe_write_half(&self) -> Option<&stream_buffer::WriteHalf> {
        Some(&self.write_half)
    }

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        NonEmptyEvents::zip(
            self.read_half.poll_ready(events),
            self.write_half.poll_ready(events),
        )
    }

    fn epoll_ready(&self, events: Events) -> Result<Option<NonEmptyEvents>> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        let mut read_wait = self.read_half.notify().wait();
        let mut write_wait = self.write_half.notify().wait();
        loop {
            let events = self.poll_ready(events);
            if let Some(events) = events {
                return events;
            }
            future::select(read_wait.next(), write_wait.next()).await;
        }
    }

    async fn ready_for_write(&self, count: usize) {
        self.write_half.ready_for_write(count).await
    }

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
        Ok(&self.bsd_file_lock)
    }
}
