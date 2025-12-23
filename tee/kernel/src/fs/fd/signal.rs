use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
};
use core::{future::pending, pin::Pin};

use async_trait::async_trait;
use bytemuck::bytes_of;
use futures::{FutureExt, future::select, select_biased};

use crate::{
    error::{Result, ensure, err},
    fs::{
        FileSystem,
        fd::{
            BsdFileLock, Events, NonEmptyEvents, OpenFileDescription, OpenFileDescriptionData,
            ReadBuf, WeakFileDescriptor,
            epoll::{EpollRequest, EpollResult, WeakEpollReady},
        },
        node::{FileAccessContext, new_ino},
        path::Path,
    },
    rt::notify::Notify,
    spin::mutex::Mutex,
    user::{
        syscall::args::{
            FileMode, FileType, FileTypeAndMode, OpenFlags, SignalFdFlags, SignalfdSiginfo, Stat,
            Timespec,
        },
        thread::{Gid, Sigset, Thread, Uid},
    },
};

pub struct SignalFd {
    ino: u64,
    internal: Mutex<SignalFdInternal>,
    notify: Notify,
}

struct SignalFdInternal {
    flags: OpenFlags,
    mask: Sigset,
}

impl SignalFd {
    pub fn new(mask: Sigset, flags: SignalFdFlags) -> Self {
        Self {
            ino: new_ino(),
            internal: Mutex::new(SignalFdInternal {
                flags: flags.into(),
                mask,
            }),
            notify: Notify::new(),
        }
    }

    async fn epoll_ready(&self, thread: &Thread, req: &EpollRequest) -> EpollResult {
        let mut mask_change_wait = self.notify.wait();
        let mut thread_wait = thread.signal_notify.wait();
        let mut process_wait = thread.process().signals_notify.wait();

        let mut mask = self.internal.lock().mask;
        let (mut thread_pending, mut thread_counter) = thread.pending_signals_with_counter();
        let (mut process_pending, mut process_counter) =
            thread.process().pending_signals_with_counter();

        loop {
            let mut result = EpollResult::new();
            if !((thread_pending | process_pending) & mask).is_empty() {
                result.set_ready(Events::READ);
            }
            result.add_counter(Events::READ, &thread_counter);
            result.add_counter(Events::READ, &process_counter);
            if let Some(result) = result.if_matches(req) {
                return result;
            }

            select_biased! {
                _ = mask_change_wait.next().fuse() => mask = self.internal.lock().mask,
                _ = thread_wait.next().fuse() => (thread_pending, thread_counter) = thread.pending_signals_with_counter(),
                _ = process_wait.next().fuse() => (process_pending, process_counter) = thread.process().pending_signals_with_counter(),
            }
        }
    }
}

#[async_trait]
impl OpenFileDescription for SignalFd {
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

    fn poll_ready(&self, events: Events, ctx: &FileAccessContext) -> Option<NonEmptyEvents> {
        let thread = ctx.thread()?;
        let mut ready_events = Events::empty();
        let mask = self.internal.lock().mask;
        ready_events.set(
            Events::READ,
            !((thread.pending_signals() | thread.process().pending_signals()) & mask).is_empty(),
        );
        ready_events &= events;
        NonEmptyEvents::new(ready_events)
    }

    async fn ready(&self, events: Events, ctx: &FileAccessContext) -> NonEmptyEvents {
        let Some(thread) = ctx.thread() else {
            return pending().await;
        };
        let mut thread_wait = thread.signal_notify.wait();
        let mut process_wait = thread.process().signals_notify.wait();
        loop {
            if let Some(events) = self.poll_ready(events, ctx) {
                return events;
            }
            select(thread_wait.next(), process_wait.next()).await;
        }
    }

    fn epoll_ready(
        self: Arc<OpenFileDescriptionData<Self>>,
        ctx: &FileAccessContext,
    ) -> Result<Box<dyn WeakEpollReady>> {
        Ok(Box::new(SignalFdEpollReady {
            fd: Arc::downgrade(&self),
            thread: Arc::downgrade(ctx.thread().unwrap()),
        }))
    }

    fn read(&self, buf: &mut dyn ReadBuf, ctx: &FileAccessContext) -> Result<usize> {
        ensure!(buf.buffer_len() >= size_of::<SignalfdSiginfo>(), Inval);

        let mask = self.internal.lock().mask;

        let thread = ctx.thread().unwrap();
        let sig_info = thread.lock().get_signal(!mask).ok_or(err!(Again))?;

        let sig_info = SignalfdSiginfo::from(sig_info);
        buf.write(0, bytes_of(&sig_info))?;

        Ok(size_of::<SignalfdSiginfo>())
    }

    fn update_signal_mask(&self, mask: Sigset) -> Result<()> {
        self.internal.lock().mask = mask;
        self.notify.notify();
        Ok(())
    }

    fn path(&self) -> Result<Path> {
        Ok(Path::new(b"anon_inode:[signalfd]".to_vec()).unwrap())
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(
                FileType::Unknown,
                FileMode::OWNER_READ | FileMode::OWNER_WRITE,
            ),
            uid: Uid::SUPER_USER,
            gid: Gid::SUPER_USER,
            rdev: 0,
            size: 0,
            blksize: 0x1000,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        todo!()
    }

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
        todo!()
    }
}

#[derive(Clone)]
struct SignalFdEpollReady {
    fd: Weak<OpenFileDescriptionData<SignalFd>>,
    thread: Weak<Thread>,
}

impl WeakEpollReady for SignalFdEpollReady {
    fn epoll_ready(
        &self,
        req: EpollRequest,
    ) -> Option<Pin<Box<dyn Future<Output = EpollResult> + Send>>> {
        let fd = self.fd.upgrade()?;
        let thread = self.thread.upgrade()?;
        Some(Box::pin(async move { (*fd).epoll_ready(&thread, &req).await }) as Pin<Box<_>>)
    }

    fn fd(&self) -> WeakFileDescriptor {
        WeakFileDescriptor::from(self.fd.clone() as Weak<_>)
    }

    fn clone_epoll_ready(&self) -> Box<dyn WeakEpollReady> {
        Box::new(self.clone())
    }
}
