use crate::{
    error::ensure,
    fs::{
        node::{directory::Directory, DynINode, FileAccessContext},
        path::Path,
        FileSystem,
    },
    spin::mutex::Mutex,
    user::process::{
        syscall::args::{FileMode, OpenFlags, Timespec},
        thread::{Gid, Uid},
    },
};
use alloc::{sync::Arc, vec::Vec};

use crate::{error::Result, fs::node::DirEntry, user::process::syscall::args::Stat};

use super::{Events, FileDescriptor, FileLock, OpenFileDescription};

pub fn open_dir(dir: Arc<dyn Directory>, flags: OpenFlags) -> Result<FileDescriptor> {
    let file_lock = FileLock::new(dir.file_lock_record().clone());
    Ok(FileDescriptor::from(DirectoryFileDescription {
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

impl OpenFileDescription for DirectoryFileDescription {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Path {
        Directory::path(&*self.dir, &mut FileAccessContext::root())
            .unwrap_or_else(|_| Path::new(b"(deleted)".to_vec()).unwrap())
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

    fn as_dir(&self, _ctx: &mut FileAccessContext) -> Result<DynINode> {
        Ok(self.dir.clone())
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

    fn poll_ready(&self, events: Events) -> Events {
        events & Events::READ
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}
