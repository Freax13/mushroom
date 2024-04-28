use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};

use super::{
    directory::{dir_impls, Directory, MountLocation},
    new_ino, DirEntry, DynINode, FileAccessContext, INode,
};
use crate::{
    error::{bail, err, Result},
    fs::{
        fd::{dir::open_dir, FileDescriptor},
        path::{FileName, Path},
    },
    spin::mutex::Mutex,
    user::process::syscall::args::{
        FdNum, FileMode, FileType, FileTypeAndMode, OpenFlags, Stat, Timespec,
    },
};

pub fn new(location: MountLocation, mode: FileMode) -> DynINode {
    Arc::new_cyclic(|this| FdFsRoot {
        ino: new_ino(),
        this: this.clone(),
        location,
        mode: Mutex::new(mode),
    })
}

struct FdFsRoot {
    ino: u64,
    this: Weak<Self>,
    location: MountLocation,
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
        bail!(NoEnt)
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}
}

impl Directory for FdFsRoot {
    fn location(&self) -> Result<Option<(DynINode, FileName<'static>)>> {
        self.location.get()
    }

    fn get_node(&self, file_name: &FileName, ctx: &FileAccessContext) -> Result<DynINode> {
        let file_name = file_name.as_bytes();
        let file_name = core::str::from_utf8(file_name).map_err(|_| err!(NoEnt))?;
        let fd_num = file_name.parse().map_err(|_| err!(NoEnt))?;
        let fd_num = FdNum::new(fd_num);
        ctx.fdtable.get_node(fd_num)
    }

    fn create_file(
        &self,
        _file_name: FileName<'static>,
        _mode: FileMode,
    ) -> Result<Result<DynINode, DynINode>> {
        bail!(NoEnt)
    }

    fn create_dir(&self, _file_name: FileName<'static>, _mode: FileMode) -> Result<DynINode> {
        bail!(NoEnt)
    }

    fn create_link(
        &self,
        _file_name: FileName<'static>,
        _target: Path,
        _create_new: bool,
    ) -> Result<DynINode> {
        bail!(NoEnt)
    }

    fn create_char_dev(
        &self,
        _file_name: FileName<'static>,
        _major: u16,
        _minor: u8,
    ) -> Result<DynINode> {
        bail!(NoEnt)
    }

    fn hard_link(&self, _file_name: FileName<'static>, _node: DynINode) -> Result<()> {
        bail!(NoEnt)
    }

    fn list_entries(&self, ctx: &mut FileAccessContext) -> Vec<DirEntry> {
        ctx.fdtable.list_entries()
    }

    fn delete(&self, _file_name: FileName<'static>) -> Result<()> {
        bail!(NoEnt)
    }

    fn delete_non_dir(&self, _file_name: FileName<'static>) -> Result<()> {
        bail!(NoEnt)
    }

    fn delete_dir(&self, _file_name: FileName<'static>) -> Result<()> {
        bail!(NoEnt)
    }
}

#[derive(Clone)]
pub struct FdINode {
    ino: u64,
    fd: FileDescriptor,
}

impl FdINode {
    pub fn new(ino: u64, fd: FileDescriptor) -> Self {
        Self { ino, fd }
    }
}

impl INode for FdINode {
    fn stat(&self) -> Stat {
        Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Link, FileMode::OWNER_ALL),
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

    fn open(&self, _flags: OpenFlags) -> Result<FileDescriptor> {
        Ok(self.fd.clone())
    }

    fn set_mode(&self, _mode: FileMode) {}

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}
}
