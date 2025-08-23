use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::future::pending;

use async_trait::async_trait;
use usize_conversions::FromUsize;

use crate::{
    error::{Result, bail, ensure, err},
    fs::{
        FileSystem,
        fd::{
            BsdFileLock, Events, NonEmptyEvents, OpenFileDescription, ReadBuf,
            StrongFileDescriptor, WriteBuf,
        },
        node::{DirEntry, FileAccessContext, Link, OffsetDirEntry, directory::Directory},
        path::Path,
    },
    spin::mutex::Mutex,
    user::process::{
        syscall::args::{FileMode, OpenFlags, Stat, Timespec, Whence},
        thread::{Gid, Uid},
    },
};

pub fn open_dir(dir: Arc<dyn Directory>, flags: OpenFlags) -> Result<StrongFileDescriptor> {
    ensure!(!flags.contains(OpenFlags::WRONLY), IsDir);
    ensure!(!flags.contains(OpenFlags::RDWR), IsDir);
    let bsd_file_lock = BsdFileLock::new(dir.bsd_file_lock_record().clone());
    Ok(StrongFileDescriptor::from(DirectoryFileDescription {
        flags,
        dir,
        internal: Mutex::new(InternalDirectoryFileDescription {
            entries: None,
            offset: 0,
        }),
        bsd_file_lock,
    }))
}

struct DirectoryFileDescription {
    flags: OpenFlags,
    dir: Arc<dyn Directory>,
    internal: Mutex<InternalDirectoryFileDescription>,
    bsd_file_lock: BsdFileLock,
}

struct InternalDirectoryFileDescription {
    entries: Option<Vec<DirEntry>>,
    offset: usize,
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

    fn seek(&self, offset: usize, whence: Whence, ctx: &mut FileAccessContext) -> Result<usize> {
        let mut guard = self.internal.lock();
        match whence {
            Whence::Set | Whence::Data => guard.offset = offset,
            Whence::Cur => {
                guard.offset = guard
                    .offset
                    .checked_add_signed(offset as isize)
                    .ok_or(err!(Inval))?
            }
            Whence::End => {
                if guard.entries.is_none() {
                    guard.entries = Some(Directory::list_entries(&*self.dir, ctx)?);
                }
                let entries = guard.entries.as_ref().unwrap();

                let size = entries.len();
                guard.offset = size
                    .checked_add_signed(offset as isize)
                    .ok_or(err!(Inval))?
            }
            Whence::Hole => bail!(Inval),
        }

        // When the offset is at the start, remove the cached entries.
        if guard.offset == 0 {
            guard.entries = None;
        }

        Ok(guard.offset)
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
    ) -> Result<Vec<OffsetDirEntry>> {
        let mut guard = self.internal.lock();
        if guard.entries.is_none() {
            guard.entries = Some(Directory::list_entries(&*self.dir, ctx)?);
        }
        let entries = guard.entries.as_ref().unwrap();
        let entries = entries
            .iter()
            .enumerate()
            .skip(guard.offset)
            .map(|(i, entry)| OffsetDirEntry {
                entry: entry.clone(),
                offset: u64::from_usize(i),
            })
            .take_while(|entry| {
                let Some(new_capacity) = capacity.checked_sub(entry.len()) else {
                    return false;
                };
                capacity = new_capacity;
                true
            })
            .collect::<Vec<_>>();
        guard.offset += entries.len();
        Ok(entries)
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

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
        Ok(&self.bsd_file_lock)
    }
}
