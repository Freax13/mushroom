use core::{any::Any, ops::Deref};

use crate::{
    char_dev,
    error::{bail, ensure, err},
    fs::fd::{
        dir::open_dir,
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
    directory::{dir_impls, Directory, DirectoryLocation, Location},
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
    dev: u64,
    ino: u64,
    this: Weak<Self>,
    location: Location<Self>,
    internal: Mutex<TmpFsDirInternal>,
}

struct TmpFsDirInternal {
    mode: FileMode,
    items: BTreeMap<FileName<'static>, TmpFsDirEntry>,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
}

impl TmpFsDir {
    pub fn new(dev: u64, location: impl Into<Location<Self>>, mode: FileMode) -> Arc<Self> {
        let now = now();

        Arc::new_cyclic(|this_weak| Self {
            dev,
            ino: new_ino(),
            this: this_weak.clone(),
            location: location.into(),
            internal: Mutex::new(TmpFsDirInternal {
                mode,
                items: BTreeMap::new(),
                atime: now,
                mtime: now,
                ctime: now,
            }),
        })
    }

    pub fn create_file(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
    ) -> Result<Result<Arc<TmpFsFile>, DynINode>> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name);
        match entry {
            Entry::Vacant(entry) => {
                let node = TmpFsFile::new(mode);
                entry.insert(TmpFsDirEntry::File(node.clone()));
                Ok(Ok(node))
            }
            Entry::Occupied(entry) => Ok(Err(entry.get().clone().into())),
        }
    }
}

impl INode for TmpFsDir {
    dir_impls!();

    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        let mode = FileTypeAndMode::new(FileType::Dir, guard.mode);
        // FIXME: Fill in more values.
        Ok(Stat {
            dev: self.dev,
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
        })
    }

    fn open(&self, flags: OpenFlags) -> Result<FileDescriptor> {
        open_dir(self.this.upgrade().unwrap(), flags)
    }

    fn set_mode(&self, mode: FileMode) {
        self.internal.lock().mode = mode;
    }

    fn mount(&self, file_name: FileName<'static>, node: DynINode) -> Result<()> {
        self.internal
            .lock()
            .items
            .insert(file_name.clone(), TmpFsDirEntry::Mount(node));
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
    fn location(&self) -> Result<Option<(DynINode, FileName<'static>)>> {
        self.location.get()
    }

    fn get_node(&self, path_segment: &FileName, _ctx: &FileAccessContext) -> Result<DynINode> {
        self.internal
            .lock()
            .items
            .get(path_segment)
            .cloned()
            .map(Into::into)
            .ok_or(err!(NoEnt))
    }

    fn create_dir(&self, file_name: FileName<'static>, mode: FileMode) -> Result<DynINode> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name.clone());
        match entry {
            Entry::Vacant(entry) => {
                let parent = DirectoryLocation::new(self.this.clone(), file_name);
                let dir = TmpFsDir::new(self.dev, parent, mode);
                entry.insert(TmpFsDirEntry::Dir(dir.clone()));
                Ok(dir)
            }
            Entry::Occupied(_) => bail!(Exist),
        }
    }

    fn create_file(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
    ) -> Result<Result<DynINode, DynINode>> {
        self.create_file(file_name, mode)
            .map(|res| res.map(|file| file as _))
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
                entry.insert(TmpFsDirEntry::Symlink(link.clone()));
                Ok(link)
            }
            Entry::Occupied(mut entry) => {
                ensure!(!create_new, Exist);
                let link = Arc::new(TmpFsSymlink {
                    ino: new_ino(),
                    target,
                });
                entry.insert(TmpFsDirEntry::Symlink(link.clone()));
                Ok(link)
            }
        }
    }

    fn create_char_dev(
        &self,
        file_name: FileName<'static>,
        major: u16,
        minor: u8,
    ) -> Result<DynINode> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name);
        match entry {
            Entry::Vacant(entry) => {
                let char_dev = Arc::new(TmpFsCharDev::new(major, minor));
                entry.insert(TmpFsDirEntry::CharDev(char_dev.clone()));
                Ok(char_dev)
            }
            Entry::Occupied(_) => bail!(Exist),
        }
    }

    fn list_entries(&self, _ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
        let parent_ino = self
            .location
            .get()
            .ok()
            .flatten()
            .and_then(|(parent, _)| parent.stat().ok().map(|stat| stat.ino));

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
            let Ok(stat) = node.stat() else {
                continue;
            };
            entries.push(DirEntry {
                ino: stat.ino,
                ty: stat.mode.ty(),
                name: DirEntryName::from(name.clone()),
            })
        }
        Ok(entries)
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
        ensure!(entry.get().ty()? != FileType::Dir, IsDir);
        entry.remove();
        Ok(())
    }

    fn delete_dir(&self, file_name: FileName<'static>) -> Result<()> {
        let mut guard = self.internal.lock();
        let node = guard.items.entry(file_name);
        let Entry::Occupied(entry) = node else {
            bail!(NoEnt);
        };
        ensure!(entry.get().ty()? == FileType::Dir, NotDir);
        entry.remove();
        Ok(())
    }

    fn rename(
        &self,
        oldname: FileName<'static>,
        check_is_dir: bool,
        new_dir: DynINode,
        newname: FileName<'static>,
    ) -> Result<()> {
        let new_dir =
            Arc::<dyn Any + Send + Sync>::downcast::<Self>(new_dir).map_err(|_| err!(XDev))?;
        ensure!(new_dir.dev == self.dev, XDev);

        fn can_rename(
            old: &TmpFsDirEntry,
            new: Option<&TmpFsDirEntry>,
            check_is_dir: bool,
        ) -> Result<()> {
            ensure!(
                !check_is_dir || matches!(old, TmpFsDirEntry::Dir(_)),
                NotDir
            );

            if let Some(new) = new {
                match (old, new) {
                    (
                        TmpFsDirEntry::File(_)
                        | TmpFsDirEntry::Symlink(_)
                        | TmpFsDirEntry::CharDev(_),
                        TmpFsDirEntry::File(_)
                        | TmpFsDirEntry::Symlink(_)
                        | TmpFsDirEntry::CharDev(_),
                    ) => {}
                    (
                        TmpFsDirEntry::File(_)
                        | TmpFsDirEntry::Symlink(_)
                        | TmpFsDirEntry::CharDev(_),
                        TmpFsDirEntry::Dir(_),
                    ) => {
                        bail!(IsDir)
                    }
                    (
                        TmpFsDirEntry::Dir(_),
                        TmpFsDirEntry::File(_)
                        | TmpFsDirEntry::Symlink(_)
                        | TmpFsDirEntry::CharDev(_),
                    ) => bail!(NotDir),
                    (TmpFsDirEntry::Dir(_), TmpFsDirEntry::Dir(new)) => {
                        let guard = new.internal.lock();
                        ensure!(guard.items.is_empty(), NotEmpty);
                    }
                    (TmpFsDirEntry::Mount(_), _) | (_, TmpFsDirEntry::Mount(_)) => bail!(Busy),
                }
            }
            Ok(())
        }

        if core::ptr::eq(self, &*new_dir) {
            if newname == oldname {
                let guard = self.internal.lock();

                // Look up the entries.
                let Some(old) = guard.items.get(&oldname) else {
                    bail!(NoEnt);
                };

                // Make sure that we can rename the old entry over the missing entry.
                can_rename(old, None, check_is_dir)?;

                Ok(())
            } else {
                let mut guard = self.internal.lock();

                // Look up the entries.
                let Some(old) = guard.items.get(&oldname) else {
                    bail!(NoEnt);
                };
                let new = guard.items.get(&newname);

                // Make sure that we can rename the old entry over the new entry.
                can_rename(old, new, check_is_dir)?;

                // Do the rename.
                let entry = guard.items.remove(&oldname).unwrap();
                guard.items.insert(newname, entry);

                Ok(())
            }
        } else {
            let (mut old_guard, mut new_guard) = self.internal.lock_two(&new_dir.internal);

            // Look up the entries.
            let Entry::Occupied(old_entry) = old_guard.items.entry(oldname) else {
                bail!(NoEnt);
            };
            let new_entry = new_guard.items.entry(newname);
            let new = match &new_entry {
                Entry::Vacant(_) => None,
                Entry::Occupied(entry) => Some(entry.get()),
            };

            // Make sure that we can rename the old entry over the new entry.
            can_rename(old_entry.get(), new, check_is_dir)?;

            // Do the rename.
            match new_entry {
                Entry::Vacant(entry) => {
                    entry.insert(old_entry.remove());
                }
                Entry::Occupied(mut entry) => {
                    entry.insert(old_entry.remove());
                }
            }

            Ok(())
        }
    }

    fn hard_link(
        &self,
        oldname: FileName<'static>,
        follow_symlink: bool,
        new_dir: DynINode,
        newname: FileName<'static>,
    ) -> Result<Option<Path>> {
        let new_dir =
            Arc::<dyn Any + Send + Sync>::downcast::<Self>(new_dir).map_err(|_| err!(XDev))?;
        ensure!(new_dir.dev == self.dev, XDev);

        if core::ptr::eq(self, &*new_dir) {
            let mut guard = self.internal.lock();
            let entry = guard.items.get(&oldname).ok_or(err!(NoEnt))?.clone();

            if follow_symlink {
                if let TmpFsDirEntry::Symlink(symlink) = entry {
                    return Ok(Some(symlink.target.clone()));
                }
            }
            if let TmpFsDirEntry::Mount(_) = entry {
                bail!(Busy);
            }

            match guard.items.entry(newname) {
                Entry::Vacant(e) => {
                    e.insert(entry);
                }
                Entry::Occupied(_) => bail!(Exist),
            }
        } else {
            let (old_guard, mut new_guard) = self.internal.lock_two(&new_dir.internal);
            let entry = old_guard.items.get(&oldname).ok_or(err!(NoEnt))?.clone();

            if follow_symlink {
                if let TmpFsDirEntry::Symlink(symlink) = entry {
                    return Ok(Some(symlink.target.clone()));
                }
            }
            if let TmpFsDirEntry::Mount(_) = entry {
                bail!(Busy);
            }

            match new_guard.items.entry(newname) {
                Entry::Vacant(e) => {
                    e.insert(entry);
                }
                Entry::Occupied(_) => bail!(Exist),
            }
        }

        Ok(None)
    }
}

#[derive(Clone)]
enum TmpFsDirEntry {
    File(Arc<TmpFsFile>),
    Dir(Arc<TmpFsDir>),
    Symlink(Arc<TmpFsSymlink>),
    CharDev(Arc<TmpFsCharDev>),
    Mount(DynINode),
}

impl Deref for TmpFsDirEntry {
    type Target = dyn INode;

    fn deref(&self) -> &Self::Target {
        match self {
            TmpFsDirEntry::File(file) => &**file,
            TmpFsDirEntry::Dir(dir) => &**dir,
            TmpFsDirEntry::Symlink(symlink) => &**symlink,
            TmpFsDirEntry::CharDev(char_dev) => &**char_dev,
            TmpFsDirEntry::Mount(mount) => &**mount,
        }
    }
}

impl From<TmpFsDirEntry> for DynINode {
    fn from(value: TmpFsDirEntry) -> Self {
        match value {
            TmpFsDirEntry::File(file) => file,
            TmpFsDirEntry::Dir(dir) => dir,
            TmpFsDirEntry::Symlink(symlink) => symlink,
            TmpFsDirEntry::CharDev(char_dev) => char_dev,
            TmpFsDirEntry::Mount(node) => node,
        }
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
    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        let mode = FileTypeAndMode::new(FileType::File, guard.mode);
        let size = guard.buffer.len() as i64;

        // FIXME: Fill in more values.
        Ok(Stat {
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
        })
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
    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
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
        })
    }

    fn open(&self, _flags: OpenFlags) -> Result<FileDescriptor> {
        bail!(Loop)
    }

    fn set_mode(&self, _mode: FileMode) {
        todo!()
    }

    fn read_link(&self, _ctx: &FileAccessContext) -> Result<Path> {
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

pub struct TmpFsCharDev {
    ino: u64,
    major: u16,
    minor: u8,
}

impl TmpFsCharDev {
    pub fn new(major: u16, minor: u8) -> Self {
        Self {
            ino: new_ino(),
            major,
            minor,
        }
    }
}

impl INode for TmpFsCharDev {
    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Char, FileMode::from_bits_retain(0o666)),
            uid: 0,
            gid: 0,
            rdev: u64::from(self.major) << 8 | u64::from(self.minor),
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn open(&self, flags: OpenFlags) -> Result<FileDescriptor> {
        char_dev::open(flags, self.stat()?)
    }

    fn set_mode(&self, _mode: FileMode) {}

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}
}
