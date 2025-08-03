use core::{
    num::{NonZeroU32, Wrapping},
    sync::atomic::{AtomicU32, Ordering},
};

use alloc::{
    boxed::Box,
    collections::{
        btree_map::{BTreeMap, Entry},
        vec_deque::VecDeque,
    },
    sync::{Arc, Weak},
    vec::Vec,
};
use async_trait::async_trait;
use bytemuck::{NoUninit, bytes_of};
use usize_conversions::usize_from;

use crate::{
    error::{Result, ensure, err},
    fs::{
        FileSystem,
        node::{DynINode, FileAccessContext, INode, new_ino},
        ownership::Ownership,
        path::{FileName, Path},
    },
    rt::notify::Notify,
    spin::{lazy::Lazy, mutex::Mutex},
    user::process::{
        syscall::args::{
            FileMode, FileType, FileTypeAndMode, InotifyMask, OpenFlags, Stat, Timespec,
        },
        thread::{Gid, Uid},
    },
};

use super::{
    Events, FileLock, NonEmptyEvents, OpenFileDescription, OpenFileDescriptionData, ReadBuf,
    StrongFileDescriptor,
};

pub struct Inotify {
    this: Weak<OpenFileDescriptionData<Self>>,
    ino: u64,
    internal: Mutex<InotifyInternal>,
    registrations: Mutex<RegistrationData>,
    queue: Mutex<VecDeque<InotifyEvent>>,
    notify: Notify,
}

struct InotifyInternal {
    flags: OpenFlags,
    ownership: Ownership,
}

struct RegistrationData {
    registration_counter: Wrapping<u32>,
    registrations: BTreeMap<u32, Weak<dyn INode>>,
}

impl Inotify {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(flags: OpenFlags, uid: Uid, gid: Gid) -> StrongFileDescriptor {
        StrongFileDescriptor::new_cyclic(|this| Self {
            this: this.clone(),
            ino: new_ino(),
            internal: Mutex::new(InotifyInternal {
                flags,
                ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
            }),
            registrations: Mutex::new(RegistrationData {
                registration_counter: Wrapping(0),
                registrations: BTreeMap::new(),
            }),
            queue: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
        })
    }

    fn send_event(
        &self,
        wd: u32,
        mask: InotifyMask,
        cookie: Option<NonZeroU32>,
        name: Option<&FileName>,
    ) {
        self.queue.lock().push_back(InotifyEvent {
            wd,
            mask,
            cookie,
            name: name.map(|name| name.clone().into_owned()),
        });
        self.notify.notify();
    }
}

#[async_trait]
impl OpenFileDescription for Inotify {
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
        todo!()
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
        todo!()
    }

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        let guard = self.queue.lock();
        let mut ready = Events::empty();
        ready.set(Events::READ, !guard.is_empty());
        NonEmptyEvents::new(ready & events)
    }

    fn epoll_ready(&self, events: Events) -> Result<Option<NonEmptyEvents>> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        self.notify.wait_until(|| self.poll_ready(events)).await
    }

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        let mut guard = self.queue.lock();
        ensure!(!guard.is_empty(), Again);

        let mut offset = 0;
        while let Some(event) = guard.pop_front_if(|e| e.len() < buf.buffer_len() - offset) {
            let header = InotifyEventHeader {
                wd: event.wd,
                mask: event.mask.bits() as u32,
                cookie: event.cookie.map_or(0, NonZeroU32::get),
                len: event
                    .name
                    .as_ref()
                    .map_or(0, |name| name.as_bytes().len() + 1) as u32,
            };
            buf.write(offset, bytes_of(&header))?;
            offset += 16;

            if let Some(name) = event.name {
                buf.write(offset, name.as_bytes())?;
                offset += name.as_bytes().len();
                buf.write(offset, &[0])?;
                offset += 1;
            }
        }

        ensure!(offset != 0, Inval);
        Ok(offset)
    }

    fn add_watch(&self, node: DynINode, mask: InotifyMask) -> Result<u32> {
        let watchers = node.watchers();

        let mut guard = watchers.0.lock();
        if let Some(existing) = guard
            .registrations
            .iter_mut()
            .find(|r| r.inotify.ptr_eq(&self.this))
        {
            existing.mask = mask;
            Ok(existing.wd)
        } else {
            let mut self_guard = self.registrations.lock();
            let internal = &mut *self_guard;
            ensure!(internal.registrations.len() < usize_from(u32::MAX), NoSpc);
            let entry = loop {
                match internal
                    .registrations
                    .entry(internal.registration_counter.0)
                {
                    Entry::Vacant(entry) => break entry,
                    Entry::Occupied(_) => internal.registration_counter += 1,
                }
            };
            let wd = *entry.key();
            entry.insert(Arc::downgrade(&node));
            drop(self_guard);

            guard.registrations.push(WatchRegistration {
                inotify: self.this.clone(),
                mask,
                wd,
            });
            Ok(wd)
        }
    }

    fn rm_watch(&self, wd: u32) -> Result<()> {
        let mut guard = self.registrations.lock();
        let node = guard.registrations.remove(&wd).ok_or(err!(Inval))?;
        let Some(node) = node.upgrade() else {
            return Ok(());
        };

        let watchers = node.watchers();
        let mut guard = watchers.0.lock();
        let idx = guard
            .registrations
            .iter()
            .position(|i| i.inotify.ptr_eq(&self.this))
            .unwrap();
        guard.registrations.swap_remove(idx);

        Ok(())
    }

    fn file_lock(&self) -> Result<&FileLock> {
        todo!()
    }
}

#[derive(Clone, Copy, NoUninit)]
#[repr(C)]
struct InotifyEventHeader {
    wd: u32,
    mask: u32,
    cookie: u32,
    len: u32,
}

struct InotifyEvent {
    wd: u32,
    mask: InotifyMask,
    cookie: Option<NonZeroU32>,
    name: Option<FileName<'static>>,
}

impl InotifyEvent {
    fn len(&self) -> usize {
        16 + self
            .name
            .as_ref()
            .map_or(0, |name| name.as_bytes().len() + 1)
    }
}

pub struct Watchers(Lazy<Mutex<WatchData>>);

#[derive(Default)]
struct WatchData {
    registrations: Vec<WatchRegistration>,
}

struct WatchRegistration {
    inotify: Weak<OpenFileDescriptionData<Inotify>>,
    mask: InotifyMask,
    wd: u32,
}

impl Watchers {
    pub const fn new() -> Self {
        Self(Lazy::new(Default::default))
    }

    pub fn send_event(
        &self,
        mask: InotifyMask,
        cookie: Option<NonZeroU32>,
        name: Option<FileName>,
    ) {
        let Some(lock) = self.0.try_get() else {
            return;
        };

        let mut guard = lock.lock();
        let mut i = 0;
        let mut inotifies = Vec::new();
        while let Some(reg) = guard.registrations.get(i) {
            if !reg.mask.intersects(mask) {
                i += 1;
                continue;
            }
            let Some(inotify) = reg.inotify.upgrade() else {
                guard.registrations.swap_remove(i);
                continue;
            };
            inotifies.push((inotify, reg.wd));
            i += 1;
        }
        drop(guard);

        for (inotify, wd) in inotifies {
            inotify.send_event(wd, mask, cookie, name.as_ref());
        }
    }
}

impl Default for Watchers {
    fn default() -> Self {
        Self::new()
    }
}

pub fn next_cookie() -> NonZeroU32 {
    static COOKIE_COUNTER: AtomicU32 = AtomicU32::new(0);
    loop {
        let value = COOKIE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let Some(value) = NonZeroU32::new(value) else {
            continue;
        };
        return value;
    }
}
