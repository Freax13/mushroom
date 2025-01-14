use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
};
use async_trait::async_trait;

use crate::{
    error::{ensure, Result},
    fs::{
        fd::{stream_buffer, Events, FileDescriptor, FileLock, OpenFileDescription},
        node::{DynINode, FileAccessContext},
        path::Path,
        FileSystem,
    },
    rt::notify::Notify,
    spin::mutex::Mutex,
    user::process::{
        memory::VirtualMemory,
        syscall::args::{FileMode, OpenFlags, Pointer, Stat},
        thread::{Gid, Uid},
    },
};

use super::{CAPACITY, PIPE_BUF};

pub struct NamedPipe {
    internal: Mutex<NamedPipeInternal>,
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
            notify: Notify::new(),
        }
    }

    pub async fn open(
        &self,
        flags: OpenFlags,
        node: DynINode,
        path: Path,
    ) -> Result<FileDescriptor> {
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

            self.notify.notify();

            if flags.contains(OpenFlags::NONBLOCK) {
                ensure!(guard.read_half.strong_count() > 1, XDev);
            } else {
                // Wait until at least one reader exists.
                loop {
                    let wait = self.notify.wait();
                    if guard.read_half.strong_count() > 0 {
                        break;
                    }

                    drop(guard);
                    wait.await;
                    guard = self.internal.lock();
                }
            }

            let file_lock = FileLock::new(node.file_lock_record().clone());
            FileDescriptor::from(WriteHalf {
                node,
                path,
                write_half,
                flags: Mutex::new(flags),
                file_lock,
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

            let file_lock = FileLock::new(node.file_lock_record().clone());
            FileDescriptor::from(FullReadWrite {
                node,
                path,
                read_half,
                write_half,
                flags: Mutex::new(flags),
                file_lock,
            })
        } else {
            let read_half = if let Some(read_half) = guard.read_half.upgrade() {
                read_half
            } else if let Some(read_half) =
                guard.write_half.upgrade().map(|read| read.make_read_half())
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

            self.notify.notify();

            if !flags.contains(OpenFlags::NONBLOCK) {
                // Wait until at least one writer exists.
                loop {
                    let wait = self.notify.wait();
                    if guard.write_half.strong_count() > 0 {
                        break;
                    }

                    drop(guard);
                    wait.await;
                    guard = self.internal.lock();
                }
            }

            let file_lock = FileLock::new(node.file_lock_record().clone());
            FileDescriptor::from(ReadHalf {
                node,
                path,
                read_half,
                flags: Mutex::new(flags),
                file_lock,
            })
        })
    }
}

struct ReadHalf {
    node: DynINode,
    path: Path,
    read_half: Arc<stream_buffer::ReadHalf>,
    flags: Mutex<OpenFlags>,
    file_lock: FileLock,
}

#[async_trait]
impl OpenFileDescription for ReadHalf {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock()
    }

    fn set_flags(&self, flags: OpenFlags) {
        *self.flags.lock() = flags;
        self.read_half.notify();
    }

    fn set_non_blocking(&self, non_blocking: bool) {
        self.flags.lock().set(OpenFlags::NONBLOCK, non_blocking);
        self.read_half.notify();
    }

    fn path(&self) -> Result<Path> {
        Ok(self.path.clone())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.read_half.read(buf)
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        self.read_half.read_to_user(vm, pointer, len)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.node.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.node.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        self.node.stat()
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        self.node.fs()
    }

    fn as_pipe_read_half(&self) -> Option<&stream_buffer::ReadHalf> {
        Some(&self.read_half)
    }

    fn poll_ready(&self, events: Events) -> Events {
        self.read_half.poll_ready(events)
    }

    fn epoll_ready(&self, events: Events) -> Result<Events> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        loop {
            let wait = self.read_half.wait();

            let events = self.poll_ready(events);
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

struct WriteHalf {
    node: DynINode,
    path: Path,
    write_half: Arc<stream_buffer::WriteHalf>,
    flags: Mutex<OpenFlags>,
    file_lock: FileLock,
}

#[async_trait]
impl OpenFileDescription for WriteHalf {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock()
    }

    fn set_flags(&self, flags: OpenFlags) {
        *self.flags.lock() = flags;
        self.write_half.notify();
    }

    fn set_non_blocking(&self, non_blocking: bool) {
        self.flags.lock().set(OpenFlags::NONBLOCK, non_blocking);
        self.write_half.notify();
    }

    fn path(&self) -> Result<Path> {
        Ok(self.path.clone())
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.write_half.write(buf)
    }

    fn write_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        self.write_half.write_from_user(vm, pointer, len)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.node.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.node.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        self.node.stat()
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        self.node.fs()
    }

    fn as_pipe_write_half(&self) -> Option<&stream_buffer::WriteHalf> {
        Some(&self.write_half)
    }

    fn poll_ready(&self, events: Events) -> Events {
        self.write_half.poll_ready(events)
    }

    fn epoll_ready(&self, events: Events) -> Result<Events> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        loop {
            let wait = self.write_half.wait();

            let events = self.poll_ready(events);
            if !events.is_empty() {
                return Ok(events);
            }

            wait.await;
        }
    }

    async fn ready_for_write(&self, count: usize) -> Result<()> {
        self.write_half.ready_for_write(count).await
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

struct FullReadWrite {
    node: DynINode,
    path: Path,
    read_half: Arc<stream_buffer::ReadHalf>,
    write_half: Arc<stream_buffer::WriteHalf>,
    flags: Mutex<OpenFlags>,
    file_lock: FileLock,
}

#[async_trait]
impl OpenFileDescription for FullReadWrite {
    fn flags(&self) -> OpenFlags {
        *self.flags.lock()
    }

    fn set_flags(&self, flags: OpenFlags) {
        *self.flags.lock() = flags;
        self.read_half.notify();
        self.write_half.notify();
    }

    fn set_non_blocking(&self, non_blocking: bool) {
        self.flags.lock().set(OpenFlags::NONBLOCK, non_blocking);
        self.read_half.notify();
        self.write_half.notify();
    }

    fn path(&self) -> Result<Path> {
        Ok(self.path.clone())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.read_half.read(buf)
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        self.read_half.read_to_user(vm, pointer, len)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.write_half.write(buf)
    }

    fn write_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        self.write_half.write_from_user(vm, pointer, len)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.node.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.node.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        self.node.stat()
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        self.node.fs()
    }

    fn as_pipe_read_half(&self) -> Option<&stream_buffer::ReadHalf> {
        Some(&self.read_half)
    }

    fn as_pipe_write_half(&self) -> Option<&stream_buffer::WriteHalf> {
        Some(&self.write_half)
    }

    fn poll_ready(&self, events: Events) -> Events {
        self.read_half.poll_ready(events) | self.write_half.poll_ready(events)
    }

    fn epoll_ready(&self, events: Events) -> Result<Events> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        loop {
            let read_wait = self.read_half.wait();
            let write_wait = self.write_half.wait();

            let events = self.poll_ready(events);
            if !events.is_empty() {
                return Ok(events);
            }

            read_wait.await;
            write_wait.await;
        }
    }

    async fn ready_for_write(&self, count: usize) -> Result<()> {
        self.write_half.ready_for_write(count).await
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}
