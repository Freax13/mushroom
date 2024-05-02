use crate::{
    error::ensure,
    fs::{
        node::{directory::Directory, DynINode, FileAccessContext},
        path::Path,
    },
    spin::mutex::Mutex,
    user::process::syscall::args::{OpenFlags, Timespec},
};
use alloc::{sync::Arc, vec::Vec};

use crate::{error::Result, fs::node::DirEntry, user::process::syscall::args::Stat};

use super::{Events, FileDescriptor, OpenFileDescription};

pub fn open_dir(path: Path, dir: Arc<dyn Directory>, flags: OpenFlags) -> Result<FileDescriptor> {
    Ok(FileDescriptor::from(DirectoryFileDescription {
        flags,
        path,
        dir,
        entries: Mutex::new(None),
    }))
}

struct DirectoryFileDescription {
    flags: OpenFlags,
    path: Path,
    dir: Arc<dyn Directory>,
    entries: Mutex<Option<Vec<DirEntry>>>,
}

impl OpenFileDescription for DirectoryFileDescription {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Path {
        self.path.clone()
    }

    fn update_times(&self, ctime: Timespec, atime: Option<Timespec>, mtime: Option<Timespec>) {
        self.dir.update_times(ctime, atime, mtime);
    }

    fn stat(&self) -> Result<Stat> {
        self.dir.stat()
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
}
