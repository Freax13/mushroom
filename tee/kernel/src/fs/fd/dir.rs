use core::future::pending;

use crate::{
    error::{bail, ensure},
    fs::{
        FileSystem,
        node::{FileAccessContext, Link, directory::Directory},
        path::Path,
    },
    spin::mutex::Mutex,
    user::process::{
        syscall::args::{FileMode, OpenFlags, Timespec},
        thread::{Gid, Uid},
    },
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use async_trait::async_trait;

use crate::{error::Result, fs::node::DirEntry, user::process::syscall::args::Stat};

use super::{
    Events, FileLock, NonEmptyEvents, OpenFileDescription, ReadBuf, StrongFileDescriptor, WriteBuf,
};

pub fn open_dir(dir: Arc<dyn Directory>, flags: OpenFlags) -> Result<StrongFileDescriptor> {
    ensure!(!flags.contains(OpenFlags::WRONLY), IsDir);
    ensure!(!flags.contains(OpenFlags::RDWR), IsDir);
    let file_lock = FileLock::new(dir.file_lock_record().clone());
    Ok(StrongFileDescriptor::from(DirectoryFileDescription {
        flags,
        dir,
        entries: Mutex::new(None),
        file_lock,
    }))
}

struct DirectoryFileDescription {
    flags: OpenFlags,
    dir: Arc<dyn Directory>,
    entries: Mutex<Option<Vec<DirEntry>>>,
    file_lock: FileLock,
}

#[async_trait]
impl OpenFileDescription for DirectoryFileDescription {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Result<Path> {
        self.dir.location().path()
    }

    fn read(&self, _: &mut dyn ReadBuf) -> Result<usize> {
        bail!(IsDir)
    }

    fn write(&self, _: &dyn WriteBuf) -> Result<usize> {
        bail!(IsDir)
    }

    fn pread(&self, _pos: usize, _: &mut dyn ReadBuf) -> Result<usize> {
        bail!(IsDir)
    }

    fn pwrite(&self, _pos: usize, _: &dyn WriteBuf) -> Result<usize> {
        bail!(IsDir)
    }

    fn update_times(&self, ctime: Timespec, atime: Option<Timespec>, mtime: Option<Timespec>) {
        self.dir.update_times(ctime, atime, mtime);
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.dir.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.dir.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        self.dir.stat()
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        self.dir.fs()
    }

    fn as_dir(&self, _ctx: &mut FileAccessContext) -> Result<Link> {
        Ok(Link {
            location: self.dir.location().clone(),
            node: self.dir.clone(),
        })
    }

    fn getdents64(
        &self,
        mut capacity: usize,
        ctx: &mut FileAccessContext,
    ) -> Result<Vec<DirEntry>> {
        let mut guard = self.entries.lock();
        if guard.is_none() {
            *guard = Some(Directory::list_entries(&*self.dir, ctx)?);
        }
        let entries = guard.as_mut().unwrap();

        let mut ret = Vec::new();
        while let Some(last) = entries.last() {
            if let Some(new_capacity) = capacity.checked_sub(last.len()) {
                ret.push(entries.pop().unwrap());
                capacity = new_capacity;
            } else {
                ensure!(!ret.is_empty(), Inval);
                break;
            }
        }

        Ok(ret)
    }

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        NonEmptyEvents::new(events & Events::READ)
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        if let Some(events) = self.poll_ready(events) {
            events
        } else {
            pending().await
        }
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}
