use core::cmp;

use crate::{
    dir_impls,
    fs::fd::{
        dir::{open_dir, Directory},
        file::{open_file, File},
        FileDescriptor,
    },
    spin::mutex::Mutex,
    user::process::syscall::args::OpenFlags,
};
use alloc::{
    borrow::Cow,
    collections::{btree_map::Entry, BTreeMap},
    sync::{Arc, Weak},
    vec::Vec,
};

use super::{
    lookup_node_with_parent, new_ino, DirEntry, DirEntryName, DynINode, FileAccessContext,
    FileSnapshot, INode,
};
use crate::{
    error::{Error, Result},
    fs::path::{FileName, Path},
    user::process::{
        memory::ActiveVirtualMemory,
        syscall::args::{FileMode, FileType, FileTypeAndMode, Pointer, Stat, Timespec},
    },
};

pub struct TmpFsDir {
    ino: u64,
    this: Weak<Self>,
    parent: Weak<dyn INode>,
    internal: Mutex<DevTmpFsDirInternal>,
}

struct DevTmpFsDirInternal {
    mode: FileMode,
    items: BTreeMap<FileName<'static>, DynINode>,
}

impl TmpFsDir {
    pub fn root(mode: FileMode) -> Arc<Self> {
        Arc::new_cyclic(|this_weak| Self {
            ino: new_ino(),
            this: this_weak.clone(),
            parent: this_weak.clone(),
            internal: Mutex::new(DevTmpFsDirInternal {
                mode,
                items: BTreeMap::new(),
            }),
        })
    }

    pub fn new(parent: Weak<dyn INode>, mode: FileMode) -> Arc<Self> {
        Arc::new_cyclic(|this_weak| Self {
            ino: new_ino(),
            this: this_weak.clone(),
            parent,
            internal: Mutex::new(DevTmpFsDirInternal {
                mode,
                items: BTreeMap::new(),
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
        self.internal.lock().mode = mode;
    }

    fn mount(&self, file_name: FileName<'static>, node: DynINode) -> Result<()> {
        self.internal.lock().items.insert(file_name.clone(), node);
        Ok(())
    }
}

impl Directory for TmpFsDir {
    fn parent(&self) -> Result<DynINode> {
        self.parent
            .clone()
            .upgrade()
            .ok_or_else(|| Error::no_ent(()))
    }

    fn get_node(&self, path_segment: &FileName, _ctx: &FileAccessContext) -> Result<DynINode> {
        self.internal
            .lock()
            .items
            .get(path_segment)
            .cloned()
            .ok_or(Error::no_ent(()))
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
            Entry::Occupied(_) => Err(Error::exist(())),
        }
    }

    fn create_file(
        &self,
        path_segment: FileName<'static>,
        mode: FileMode,
        create_new: bool,
    ) -> Result<DynINode> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(path_segment);
        match entry {
            Entry::Vacant(entry) => {
                let node = TmpFsFile::new(mode, &[]);
                entry.insert(node.clone());
                Ok(node)
            }
            Entry::Occupied(entry) => {
                if create_new {
                    return Err(Error::exist(()));
                }
                if entry.get().ty() != FileType::File {
                    return Err(Error::exist(()));
                }
                Ok(entry.get().clone())
            }
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
                if create_new {
                    return Err(Error::exist(()));
                }
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
        let guard = self.internal.lock();

        let mut entries = Vec::with_capacity(2 + guard.items.len());
        entries.push(DirEntry {
            ino: 0,
            ty: FileType::Dir,
            name: DirEntryName::Dot,
        });
        entries.push(DirEntry {
            ino: 0,
            ty: FileType::Dir,
            name: DirEntryName::DotDot,
        });
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

    fn delete_non_dir(&self, file_name: FileName<'static>) -> Result<()> {
        let mut guard = self.internal.lock();
        let node = guard.items.entry(file_name);
        let Entry::Occupied(entry) = node else {
            return Err(Error::no_ent(()));
        };
        if entry.get().ty() == FileType::Dir {
            return Err(Error::is_dir(()));
        }
        entry.remove();
        Ok(())
    }

    fn delete_dir(&self, file_name: FileName<'static>) -> Result<()> {
        let mut guard = self.internal.lock();
        let node = guard.items.entry(file_name);
        let Entry::Occupied(entry) = node else {
            return Err(Error::no_ent(()));
        };
        if entry.get().ty() != FileType::Dir {
            return Err(Error::is_dir(()));
        }
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
    content: Arc<Cow<'static, [u8]>>,
    mode: FileMode,
}

impl TmpFsFile {
    pub fn new(mode: FileMode, content: &'static [u8]) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            ino: new_ino(),
            internal: Mutex::new(TmpFsFileInternal {
                content: Arc::new(Cow::Borrowed(content)),
                mode,
            }),
        })
    }
}

impl INode for TmpFsFile {
    fn stat(&self) -> Stat {
        let guard = self.internal.lock();
        let mode = FileTypeAndMode::new(FileType::File, guard.mode);
        let size = guard.content.len() as i64;

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
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        }
    }

    fn open(&self, flags: OpenFlags) -> Result<FileDescriptor> {
        open_file(self.this.upgrade().unwrap(), flags)
    }

    fn set_mode(&self, mode: FileMode) {
        self.internal.lock().mode = mode;
    }

    fn read_snapshot(&self) -> Result<FileSnapshot> {
        let content = self.internal.lock().content.clone();
        Ok(FileSnapshot(content))
    }
}

impl File for TmpFsFile {
    fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let guard = self.internal.lock();
        let slice = guard.content.get(offset..).ok_or(Error::inval(()))?;
        let len = cmp::min(slice.len(), buf.len());
        buf[..len].copy_from_slice(&slice[..len]);
        Ok(len)
    }

    fn read_to_user(
        &self,
        offset: usize,
        vm: &mut ActiveVirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let guard = self.internal.lock();
        let slice = guard.content.get(offset..).ok_or(Error::inval(()))?;
        let len = cmp::min(slice.len(), len);
        vm.write_bytes(pointer.get(), &slice[..len])?;
        Ok(len)
    }

    fn write(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        let mut guard = self.internal.lock();
        let bytes = Arc::make_mut(&mut guard.content);
        let bytes = bytes.to_mut();

        // Grow the file to be able to hold at least `offset+buf.len()` bytes.
        let new_min_len = offset + buf.len();
        if bytes.len() < new_min_len {
            bytes.resize(new_min_len, 0);
        }

        // Copy the buffer into the file.
        bytes[offset..][..buf.len()].copy_from_slice(buf);

        Ok(buf.len())
    }

    fn write_from_user(
        &self,
        offset: usize,
        vm: &mut ActiveVirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let mut guard = self.internal.lock();
        let bytes = Arc::make_mut(&mut guard.content);
        let bytes = bytes.to_mut();

        // Grow the file to be able to hold at least `offset+buf.len()` bytes.
        let new_min_len = offset + len;
        if bytes.len() < new_min_len {
            bytes.resize(new_min_len, 0);
        }

        // Read from userspace into the file.
        vm.read_bytes(pointer.get(), &mut bytes[offset..][..len])?;

        Ok(len)
    }

    fn append(&self, buf: &[u8]) -> Result<usize> {
        let mut guard = self.internal.lock();
        let bytes = Arc::make_mut(&mut guard.content);
        let bytes = bytes.to_mut();
        bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn append_from_user(
        &self,
        vm: &mut ActiveVirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let mut guard = self.internal.lock();
        let bytes = Arc::make_mut(&mut guard.content);
        let bytes = bytes.to_mut();

        let prev_len = bytes.len();
        bytes.resize(bytes.len() + len, 0);

        // Copy the buffer into the file.
        vm.read_bytes(pointer.get(), &mut bytes[prev_len..])?;

        Ok(len)
    }

    fn truncate(&self) -> Result<()> {
        let mut guard = self.internal.lock();
        guard.content = Arc::new(Cow::Borrowed(&[]));
        Ok(())
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
        Err(Error::r#loop(()))
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
}
