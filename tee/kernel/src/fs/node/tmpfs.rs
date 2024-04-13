use crate::{
    dir_impls,
    error::{bail, ensure, err},
    fs::fd::{
        dir::{open_dir, Directory},
        file::{open_file, File},
        FileDescriptor,
    },
    memory::page::{Buffer, KernelPage},
    spin::mutex::Mutex,
    time::now,
    user::process::syscall::args::OpenFlags,
};
use alloc::{
    collections::{btree_map::Entry, BTreeMap},
    sync::{Arc, Weak},
    vec::Vec,
};

use super::{
    lookup_node_with_parent, new_ino, DirEntry, DirEntryName, DynINode, FileAccessContext, INode,
};
use crate::{
    error::Result,
    fs::path::{FileName, Path},
    user::process::{
        memory::VirtualMemory,
        syscall::args::{FileMode, FileType, FileTypeAndMode, Pointer, Stat, Timespec},
    },
};

pub struct TmpFsDir {
    ino: u64,
    this: Weak<Self>,
    parent: Mutex<Weak<dyn INode>>,
    internal: Mutex<DevTmpFsDirInternal>,
}

struct DevTmpFsDirInternal {
    mode: FileMode,
    items: BTreeMap<FileName<'static>, DynINode>,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
}

impl TmpFsDir {
    pub fn root(mode: FileMode) -> Arc<Self> {
        let now = now();

        Arc::new_cyclic(|this_weak| Self {
            ino: new_ino(),
            this: this_weak.clone(),
            parent: Mutex::new(this_weak.clone()),
            internal: Mutex::new(DevTmpFsDirInternal {
                mode,
                items: BTreeMap::new(),
                atime: now,
                mtime: now,
                ctime: now,
            }),
        })
    }

    pub fn new(parent: Weak<dyn INode>, mode: FileMode) -> Arc<Self> {
        let now = now();

        Arc::new_cyclic(|this_weak| Self {
            ino: new_ino(),
            this: this_weak.clone(),
            parent: Mutex::new(parent),
            internal: Mutex::new(DevTmpFsDirInternal {
                mode,
                items: BTreeMap::new(),
                atime: now,
                mtime: now,
                ctime: now,
            }),
        })
    }
}

impl INode for TmpFsDir {
    dir_impls!();

    fn stat(&self) -> Stat {
        let guard = self.internal.lock();
        let mode = FileTypeAndMode::new(FileType::Dir, guard.mode);
        // FIXME: Fill in more values.
        Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: (2 + guard.items.len()) as i64,
            blksize: 0,
            blocks: 0,
            atime: guard.atime,
            mtime: guard.mtime,
            ctime: guard.ctime,
        }
    }

    fn open(&self, flags: OpenFlags) -> Result<FileDescriptor> {
        open_dir(self.this.upgrade().unwrap(), flags)
    }

    fn set_mode(&self, mode: FileMode) {
        self.internal.lock().mode = mode;
    }

    fn mount(&self, file_name: FileName<'static>, node: DynINode) -> Result<()> {
        node.set_parent(self.this.clone());
        self.internal.lock().items.insert(file_name.clone(), node);
        Ok(())
    }

    fn update_times(&self, ctime: Timespec, atime: Option<Timespec>, mtime: Option<Timespec>) {
        let mut guard = self.internal.lock();
        guard.ctime = ctime;
        if let Some(atime) = atime {
            guard.atime = atime;
        }
        if let Some(mtime) = mtime {
            guard.mtime = mtime;
        }
    }
}

impl Directory for TmpFsDir {
    fn parent(&self) -> Result<DynINode> {
        self.parent.lock().clone().upgrade().ok_or(err!(NoEnt))
    }

    fn set_parent(&self, parent: Weak<dyn INode>) {
        *self.parent.lock() = parent;
    }

    fn get_node(&self, path_segment: &FileName, _ctx: &FileAccessContext) -> Result<DynINode> {
        self.internal
            .lock()
            .items
            .get(path_segment)
            .cloned()
            .ok_or(err!(NoEnt))
    }

    fn create_dir(&self, file_name: FileName<'static>, mode: FileMode) -> Result<DynINode> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name);
        match entry {
            Entry::Vacant(entry) => {
                let dir = TmpFsDir::new(self.this.clone(), mode);
                entry.insert(dir.clone());
                Ok(dir)
            }
            Entry::Occupied(_) => bail!(Exist),
        }
    }

    fn create_file(
        &self,
        path_segment: FileName<'static>,
        mode: FileMode,
    ) -> Result<Result<DynINode, DynINode>> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(path_segment);
        match entry {
            Entry::Vacant(entry) => {
                let node = TmpFsFile::new(mode);
                entry.insert(node.clone());
                Ok(Ok(node))
            }
            Entry::Occupied(entry) => Ok(Err(entry.get().clone())),
        }
    }

    fn create_link(
        &self,
        file_name: FileName<'static>,
        target: Path,
        create_new: bool,
    ) -> Result<DynINode> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name);
        match entry {
            Entry::Vacant(entry) => {
                let link = Arc::new(TmpFsSymlink {
                    ino: new_ino(),
                    target,
                });
                entry.insert(link.clone());
                Ok(link)
            }
            Entry::Occupied(mut entry) => {
                ensure!(!create_new, Exist);
                let link = Arc::new(TmpFsSymlink {
                    ino: new_ino(),
                    target,
                });
                entry.insert(link.clone());
                Ok(link)
            }
        }
    }

    fn hard_link(&self, file_name: FileName<'static>, node: DynINode) -> Result<()> {
        self.internal.lock().items.insert(file_name.clone(), node);
        Ok(())
    }

    fn list_entries(&self, _ctx: &mut FileAccessContext) -> Vec<DirEntry> {
        let parent_ino = Directory::parent(self).ok().map(|parent| parent.stat().ino);

        let guard = self.internal.lock();

        let mut entries = Vec::with_capacity(2 + guard.items.len());
        entries.push(DirEntry {
            ino: self.ino,
            ty: FileType::Dir,
            name: DirEntryName::Dot,
        });
        if let Some(ino) = parent_ino {
            entries.push(DirEntry {
                ino,
                ty: FileType::Dir,
                name: DirEntryName::DotDot,
            });
        }
        for (name, node) in guard.items.iter() {
            let stat = node.stat();
            entries.push(DirEntry {
                ino: stat.ino,
                ty: stat.mode.ty(),
                name: DirEntryName::from(name.clone()),
            })
        }
        entries
    }

    fn delete(&self, file_name: FileName<'static>) -> Result<()> {
        let mut guard = self.internal.lock();
        guard.items.remove(&file_name).ok_or(err!(NoEnt))?;
        Ok(())
    }

    fn delete_non_dir(&self, file_name: FileName<'static>) -> Result<()> {
        let mut guard = self.internal.lock();
        let node = guard.items.entry(file_name);
        let Entry::Occupied(entry) = node else {
            bail!(NoEnt);
        };
        ensure!(entry.get().ty() != FileType::Dir, IsDir);
        entry.remove();
        Ok(())
    }

    fn delete_dir(&self, file_name: FileName<'static>) -> Result<()> {
        let mut guard = self.internal.lock();
        let node = guard.items.entry(file_name);
        let Entry::Occupied(entry) = node else {
            bail!(NoEnt);
        };
        ensure!(entry.get().ty() == FileType::Dir, NotDir);
        entry.remove();
        Ok(())
    }
}

pub struct TmpFsFile {
    ino: u64,
    this: Weak<Self>,
    internal: Mutex<TmpFsFileInternal>,
}

struct TmpFsFileInternal {
    buffer: Buffer,
    mode: FileMode,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
}

impl TmpFsFile {
    pub fn new(mode: FileMode) -> Arc<Self> {
        let now = now();

        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            ino: new_ino(),
            internal: Mutex::new(TmpFsFileInternal {
                buffer: Buffer::new(),
                mode,
                atime: now,
                mtime: now,
                ctime: now,
            }),
        })
    }
}

impl INode for TmpFsFile {
    fn stat(&self) -> Stat {
        let guard = self.internal.lock();
        let mode = FileTypeAndMode::new(FileType::File, guard.mode);
        let size = guard.buffer.len() as i64;

        // FIXME: Fill in more values.
        Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode,
            uid: 0,
            gid: 0,
            rdev: 0,
            size,
            blksize: 0,
            blocks: 0,
            atime: guard.atime,
            mtime: guard.mtime,
            ctime: guard.ctime,
        }
    }

    fn open(&self, flags: OpenFlags) -> Result<FileDescriptor> {
        open_file(self.this.upgrade().unwrap(), flags)
    }

    fn set_mode(&self, mode: FileMode) {
        let mut guard = self.internal.lock();
        guard.ctime = now();
        guard.mode = mode;
    }

    fn update_times(&self, ctime: Timespec, atime: Option<Timespec>, mtime: Option<Timespec>) {
        let mut guard = self.internal.lock();
        guard.ctime = ctime;
        if let Some(atime) = atime {
            guard.atime = atime;
        }
        if let Some(mtime) = mtime {
            guard.mtime = mtime;
        }
    }
}

impl File for TmpFsFile {
    fn get_page(&self, page_idx: usize) -> Result<KernelPage> {
        let mut guard = self.internal.lock();
        guard.buffer.get_page(page_idx)
    }

    fn read(&self, offset: usize, buf: &mut [u8], no_atime: bool) -> Result<usize> {
        let mut guard = self.internal.lock();
        if !no_atime {
            guard.atime = now();
        }
        guard.buffer.read(offset, buf)
    }

    fn read_to_user(
        &self,
        offset: usize,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
        no_atime: bool,
    ) -> Result<usize> {
        let mut guard = self.internal.lock();
        if !no_atime {
            guard.atime = now();
        }
        guard.buffer.read_to_user(offset, vm, pointer, len)
    }

    fn write(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        let mut guard = self.internal.lock();
        let now = now();
        guard.ctime = now;
        guard.mtime = now;
        guard.buffer.write(offset, buf)
    }

    fn write_from_user(
        &self,
        offset: usize,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let mut guard = self.internal.lock();
        let now = now();
        guard.ctime = now;
        guard.mtime = now;
        guard.buffer.write_from_user(offset, vm, pointer, len)
    }

    fn append(&self, buf: &[u8]) -> Result<usize> {
        let mut guard = self.internal.lock();
        let now = now();
        guard.ctime = now;
        guard.mtime = now;
        let offset = guard.buffer.len();
        guard.buffer.write(offset, buf)
    }

    fn append_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let mut guard = self.internal.lock();
        let now = now();
        guard.ctime = now;
        guard.mtime = now;
        let offset = guard.buffer.len();
        guard.buffer.write_from_user(offset, vm, pointer, len)
    }

    fn truncate(&self, len: usize) -> Result<()> {
        let mut guard = self.internal.lock();
        let now = now();
        guard.ctime = now;
        guard.mtime = now;
        guard.buffer.truncate(len)
    }
}

#[derive(Clone)]
pub struct TmpFsSymlink {
    ino: u64,
    target: Path,
}

impl INode for TmpFsSymlink {
    fn stat(&self) -> Stat {
        Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Link, FileMode::ALL),
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
        bail!(Loop)
    }

    fn set_mode(&self, _mode: FileMode) {
        todo!()
    }

    fn read_link(&self) -> Result<Path> {
        Ok(self.target.clone())
    }

    fn try_resolve_link(
        &self,
        start_dir: DynINode,
        ctx: &mut FileAccessContext,
    ) -> Result<Option<(DynINode, DynINode)>> {
        ctx.follow_symlink()?;
        lookup_node_with_parent(start_dir, &self.target, ctx).map(Some)
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}
}
