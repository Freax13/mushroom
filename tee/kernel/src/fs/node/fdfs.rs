use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};

use super::{new_ino, DirEntry, DynINode, FileAccessContext, INode};
use crate::{
    dir_impls,
    error::{Error, Result},
    fs::{
        fd::{
            dir::{open_dir, Directory},
            FileDescriptor,
        },
        path::{FileName, Path},
    },
    spin::mutex::Mutex,
    user::process::syscall::args::{
        FdNum, FileMode, FileType, FileTypeAndMode, OpenFlags, Stat, Timespec,
    },
};

pub fn new(parent: Weak<dyn Directory>, mode: FileMode) -> DynINode {
    Arc::new_cyclic(|this| FdFsRoot {
        ino: new_ino(),
        this: this.clone(),
        parent: Mutex::new(parent),
        mode: Mutex::new(mode),
    })
}

struct FdFsRoot {
    ino: u64,
    this: Weak<Self>,
    parent: Mutex<Weak<dyn INode>>,
    mode: Mutex<FileMode>,
}

impl INode for FdFsRoot {
    dir_impls!();

    fn stat(&self) -> Stat {
        let mode = *self.mode.lock();
        let mode = FileTypeAndMode::new(FileType::Dir, mode);

        Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        }
    }

    fn open(&self, flags: OpenFlags) -> Result<FileDescriptor> {
        open_dir(self.this.upgrade().unwrap(), flags)
    }

    fn set_mode(&self, mode: FileMode) {
        *self.mode.lock() = mode;
    }

    fn mount(&self, _file_name: FileName<'static>, _node: DynINode) -> Result<()> {
        Err(Error::no_ent(()))
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}
}

impl Directory for FdFsRoot {
    fn parent(&self) -> Result<DynINode> {
        self.parent
            .lock()
            .clone()
            .upgrade()
            .ok_or_else(|| Error::no_ent(()))
    }

    fn set_parent(&self, parent: Weak<dyn INode>) {
        *self.parent.lock() = parent;
    }

    fn get_node(&self, file_name: &FileName, ctx: &FileAccessContext) -> Result<DynINode> {
        let file_name = file_name.as_bytes();
        let file_name = core::str::from_utf8(file_name).map_err(|_| Error::no_ent(()))?;
        let fd_num = file_name.parse().map_err(|_| Error::no_ent(()))?;
        let fd_num = FdNum::new(fd_num);
        let fd = ctx.fdtable.get(fd_num)?;
        Ok(Arc::new(FdINode(fd)))
    }

    fn create_file(
        &self,
        _file_name: FileName<'static>,
        _mode: FileMode,
        _create_new: bool,
        _ctx: &mut FileAccessContext,
    ) -> Result<DynINode> {
        Err(Error::no_ent(()))
    }

    fn create_dir(&self, _file_name: FileName<'static>, _mode: FileMode) -> Result<DynINode> {
        Err(Error::no_ent(()))
    }

    fn create_link(
        &self,
        _file_name: FileName<'static>,
        _target: Path,
        _create_new: bool,
    ) -> Result<DynINode> {
        Err(Error::no_ent(()))
    }

    fn hard_link(&self, _file_name: FileName<'static>, _node: DynINode) -> Result<()> {
        Err(Error::no_ent(()))
    }

    fn list_entries(&self, ctx: &mut FileAccessContext) -> Vec<DirEntry> {
        ctx.fdtable.list_entries()
    }

    fn delete(&self, _file_name: FileName<'static>) -> Result<()> {
        Err(Error::no_ent(()))
    }

    fn delete_non_dir(&self, _file_name: FileName<'static>) -> Result<()> {
        Err(Error::no_ent(()))
    }

    fn delete_dir(&self, _file_name: FileName<'static>) -> Result<()> {
        Err(Error::no_ent(()))
    }
}

#[derive(Clone)]
pub struct FdINode(FileDescriptor);

impl INode for FdINode {
    fn stat(&self) -> Stat {
        todo!()
    }

    fn open(&self, _flags: OpenFlags) -> Result<FileDescriptor> {
        Ok(self.0.clone())
    }

    fn set_mode(&self, _mode: FileMode) {}

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}
}
