use core::{any::Any, ops::Deref};

use crate::{
    char_dev,
    error::{bail, ensure, err},
    fs::{
        fd::{
            dir::open_dir,
            file::{open_file, File},
            FileDescriptor, FileLockRecord, LazyFileLockRecord,
        },
        ownership::Ownership,
    },
    memory::page::{Buffer, KernelPage},
    spin::mutex::Mutex,
    time::now,
    user::process::{
        syscall::args::OpenFlags,
        thread::{Gid, Uid},
    },
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
    file_lock_record: LazyFileLockRecord,
    internal: Mutex<TmpFsDirInternal>,
}

struct TmpFsDirInternal {
    ownership: Ownership,
    items: BTreeMap<FileName<'static>, TmpFsDirEntry>,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
}

impl TmpFsDir {
    pub fn new(
        dev: u64,
        location: impl Into<Location<Self>>,
        mode: FileMode,
        uid: Uid,
        gid: Gid,
    ) -> Arc<Self> {
        let now = now();

        Arc::new_cyclic(|this_weak| Self {
            dev,
            ino: new_ino(),
            this: this_weak.clone(),
            location: location.into(),
            file_lock_record: LazyFileLockRecord::new(),
            internal: Mutex::new(TmpFsDirInternal {
                ownership: Ownership::new(mode, uid, gid),
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
        uid: Uid,
        gid: Gid,
    ) -> Result<Result<Arc<TmpFsFile>, DynINode>> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name);
        match entry {
            Entry::Vacant(entry) => {
                let node = TmpFsFile::new(mode, uid, gid);
                entry.insert(TmpFsDirEntry::File(node.clone()));
                Ok(Ok(node))
            }
            Entry::Occupied(entry) => Ok(Err(entry.get().node())),
        }
    }
}

impl INode for TmpFsDir {
    dir_impls!();

    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        // FIXME: Fill in more values.
        Ok(Stat {
            dev: self.dev,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Dir, guard.ownership.mode()),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
            rdev: 0,
            size: (2 + guard.items.len()) as i64,
            blksize: 0,
            blocks: 0,
            atime: guard.atime,
            mtime: guard.mtime,
            ctime: guard.ctime,
        })
    }

    fn open(&self, _path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        open_dir(self.this.upgrade().unwrap(), flags)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
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

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        self.file_lock_record.get()
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
            .map(TmpFsDirEntry::node)
            .ok_or(err!(NoEnt))
    }

    fn create_dir(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
        uid: Uid,
        gid: Gid,
    ) -> Result<DynINode> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name.clone());
        match entry {
            Entry::Vacant(entry) => {
                let parent = DirectoryLocation::new(self.this.clone(), file_name);
                let dir = TmpFsDir::new(self.dev, parent, mode, uid, gid);
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
        uid: Uid,
        gid: Gid,
    ) -> Result<Result<DynINode, DynINode>> {
        self.create_file(file_name, mode, uid, gid)
            .map(|res| res.map(|file| file as _))
    }

    fn create_link(
        &self,
        file_name: FileName<'static>,
        target: Path,
        uid: Uid,
        gid: Gid,
        create_new: bool,
    ) -> Result<DynINode> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name);
        match entry {
            Entry::Vacant(entry) => {
                let now = now();
                let link = Arc::new(TmpFsSymlink {
                    ino: new_ino(),
                    target,
                    internal: Mutex::new(TmpFsSymlinkInternal {
                        ownership: Ownership::new(FileMode::ALL, uid, gid),
                        atime: now,
                        mtime: now,
                        ctime: now,
                    }),
                    file_lock_record: Arc::new(FileLockRecord::new()),
                });
                entry.insert(TmpFsDirEntry::Symlink(link.clone()));
                Ok(link)
            }
            Entry::Occupied(mut entry) => {
                ensure!(!create_new, Exist);
                let now = now();
                let link = Arc::new(TmpFsSymlink {
                    ino: new_ino(),
                    target,
                    internal: Mutex::new(TmpFsSymlinkInternal {
                        ownership: Ownership::new(FileMode::ALL, uid, gid),
                        atime: now,
                        mtime: now,
                        ctime: now,
                    }),
                    file_lock_record: Arc::new(FileLockRecord::new()),
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
        mode: FileMode,
        uid: Uid,
        gid: Gid,
    ) -> Result<DynINode> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name);
        match entry {
            Entry::Vacant(entry) => {
                let char_dev = Arc::new(TmpFsCharDev::new(major, minor, mode, uid, gid));
                entry.insert(TmpFsDirEntry::CharDev(char_dev.clone()));
                Ok(char_dev)
            }
            Entry::Occupied(_) => bail!(Exist),
        }
    }

    fn is_empty(&self) -> bool {
        let guard = self.internal.lock();
        guard.items.is_empty()
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
        ensure!(entry.get().is_empty_dir(), NotEmpty);
        entry.remove();
        Ok(())
    }

    fn rename(
        &self,
        oldname: FileName<'static>,
        check_is_dir: bool,
        new_dir: DynINode,
        newname: FileName<'static>,
        no_replace: bool,
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

                ensure!(!no_replace, Exist);

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

                ensure!(!no_replace || new.is_none(), Exist);

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

            // Make sure that the old_entry isn't new_dir or any of its parents.
            let mut parent = new_dir.clone() as DynINode;
            loop {
                ensure!(!core::ptr::addr_eq(&**old_entry.get(), &*parent), Inval);
                let new_parent = parent.clone().parent()?;
                let old_parent = core::mem::replace(&mut parent, new_parent);

                // Exit the loop if we've reached the root node.
                if Arc::ptr_eq(&parent, &old_parent) {
                    break;
                }
            }

            let new_entry = new_guard.items.entry(newname);
            let new = match &new_entry {
                Entry::Vacant(_) => None,
                Entry::Occupied(entry) => Some(entry.get()),
            };

            // Make sure that we can rename the old entry over the new entry.
            can_rename(old_entry.get(), new, check_is_dir)?;

            ensure!(!no_replace || new.is_none(), Exist);

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

    fn exchange(
        &self,
        oldname: FileName<'static>,
        new_dir: DynINode,
        newname: FileName<'static>,
    ) -> Result<()> {
        let new_dir =
            Arc::<dyn Any + Send + Sync>::downcast::<Self>(new_dir).map_err(|_| err!(XDev))?;
        ensure!(new_dir.dev == self.dev, XDev);

        if core::ptr::eq(self, &*new_dir) {
            if newname == oldname {
                Ok(())
            } else {
                let mut guard = self.internal.lock();

                // Do the exchange.
                let entry = guard
                    .items
                    .get(&oldname)
                    .ok_or_else(|| err!(NoEnt))?
                    .clone();
                let Entry::Occupied(mut map_entry) = guard.items.entry(newname) else {
                    bail!(NoEnt);
                };
                let entry = map_entry.insert(entry);
                guard.items.insert(oldname, entry);

                Ok(())
            }
        } else {
            let (mut old_guard, mut new_guard) = self.internal.lock_two(&new_dir.internal);

            // Do the exchange.
            let entry = old_guard.items.get(&oldname).ok_or_else(|| err!(NoEnt))?;
            let Entry::Occupied(mut map_entry) = new_guard.items.entry(newname) else {
                bail!(NoEnt);
            };

            // Make sure that the old_entry isn't new_dir or any of its parents.
            let mut parent = new_dir.clone() as DynINode;
            loop {
                ensure!(!core::ptr::addr_eq(&**map_entry.get(), &*parent), Inval);
                let new_parent = parent.clone().parent()?;
                let old_parent = core::mem::replace(&mut parent, new_parent);

                // Exit the loop if we've reached the root node.
                if Arc::ptr_eq(&parent, &old_parent) {
                    break;
                }
            }

            let entry = map_entry.insert(entry.clone());
            old_guard.items.insert(oldname, entry);

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
                if let TmpFsDirEntry::Symlink(symlink) = &entry {
                    return Ok(Some(symlink.target.clone()));
                }
            }
            match entry {
                TmpFsDirEntry::Dir(_) => bail!(Perm),
                TmpFsDirEntry::Mount(_) => bail!(Busy),
                _ => {}
            }

            match guard.items.entry(newname) {
                Entry::Vacant(e) => {
                    let node = e.insert(entry);
                    node.update_times(now(), None, None);
                }
                Entry::Occupied(_) => bail!(Exist),
            }
        } else {
            let (old_guard, mut new_guard) = self.internal.lock_two(&new_dir.internal);
            let entry = old_guard.items.get(&oldname).ok_or(err!(NoEnt))?.clone();

            if follow_symlink {
                if let TmpFsDirEntry::Symlink(symlink) = &entry {
                    return Ok(Some(symlink.target.clone()));
                }
            }
            match entry {
                TmpFsDirEntry::Dir(_) => bail!(Perm),
                TmpFsDirEntry::Mount(_) => bail!(Busy),
                _ => {}
            }

            match new_guard.items.entry(newname) {
                Entry::Vacant(e) => {
                    let node = e.insert(entry);
                    node.update_times(now(), None, None);
                }
                Entry::Occupied(_) => bail!(Exist),
            }
        }

        Ok(None)
    }
}

enum TmpFsDirEntry {
    File(Arc<TmpFsFile>),
    Dir(Arc<TmpFsDir>),
    Symlink(Arc<TmpFsSymlink>),
    CharDev(Arc<TmpFsCharDev>),
    Mount(DynINode),
}

impl TmpFsDirEntry {
    fn node(&self) -> DynINode {
        match self {
            TmpFsDirEntry::File(file) => file.clone(),
            TmpFsDirEntry::Dir(dir) => dir.clone(),
            TmpFsDirEntry::Symlink(symlink) => symlink.clone(),
            TmpFsDirEntry::CharDev(char_dev) => char_dev.clone(),
            TmpFsDirEntry::Mount(node) => node.clone(),
        }
    }
}

impl Clone for TmpFsDirEntry {
    fn clone(&self) -> Self {
        match self {
            Self::File(file) => {
                file.increase_link_count();
                Self::File(file.clone())
            }
            Self::Dir(dir) => Self::Dir(dir.clone()),
            Self::Symlink(symlink) => Self::Symlink(symlink.clone()),
            Self::CharDev(char_dev) => Self::CharDev(char_dev.clone()),
            Self::Mount(mount) => Self::Mount(mount.clone()),
        }
    }
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

impl Drop for TmpFsDirEntry {
    fn drop(&mut self) {
        if let Self::File(file) = self {
            file.decrease_link_count();
        }
    }
}

pub struct TmpFsFile {
    ino: u64,
    this: Weak<Self>,
    internal: Mutex<TmpFsFileInternal>,
    file_lock_record: LazyFileLockRecord,
}

struct TmpFsFileInternal {
    buffer: Buffer,
    ownership: Ownership,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
    links: u64,
}

impl TmpFsFile {
    pub fn new(mode: FileMode, uid: Uid, gid: Gid) -> Arc<Self> {
        let now = now();

        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            ino: new_ino(),
            internal: Mutex::new(TmpFsFileInternal {
                buffer: Buffer::new(),
                ownership: Ownership::new(mode, uid, gid),
                atime: now,
                mtime: now,
                ctime: now,
                links: 1,
            }),
            file_lock_record: LazyFileLockRecord::new(),
        })
    }

    fn increase_link_count(&self) {
        self.internal.lock().links += 1;
    }

    fn decrease_link_count(&self) {
        self.internal.lock().links -= 1;
    }
}

impl INode for TmpFsFile {
    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        // FIXME: Fill in more values.
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: guard.links,
            mode: FileTypeAndMode::new(FileType::File, guard.ownership.mode()),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
            rdev: 0,
            size: guard.buffer.len() as i64,
            blksize: 0,
            blocks: 0,
            atime: guard.atime,
            mtime: guard.mtime,
            ctime: guard.ctime,
        })
    }

    fn open(&self, path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        open_file(path, self.this.upgrade().unwrap(), flags)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
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

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        self.file_lock_record.get()
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
    file_lock_record: Arc<FileLockRecord>,
    internal: Mutex<TmpFsSymlinkInternal>,
}

#[derive(Clone)]
struct TmpFsSymlinkInternal {
    ownership: Ownership,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
}

impl INode for TmpFsSymlink {
    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Link, FileMode::ALL),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: guard.atime,
            mtime: guard.mtime,
            ctime: guard.ctime,
        })
    }

    fn open(&self, _path: Path, _flags: OpenFlags) -> Result<FileDescriptor> {
        bail!(Loop)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
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

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        &self.file_lock_record
    }
}

pub struct TmpFsCharDev {
    ino: u64,
    major: u16,
    minor: u8,
    internal: Mutex<TmpFsCharDevInternal>,
    file_lock_record: Arc<FileLockRecord>,
}

struct TmpFsCharDevInternal {
    ownership: Ownership,
}

impl TmpFsCharDev {
    pub fn new(major: u16, minor: u8, mode: FileMode, uid: Uid, gid: Gid) -> Self {
        Self {
            ino: new_ino(),
            major,
            minor,
            internal: Mutex::new(TmpFsCharDevInternal {
                ownership: Ownership::new(mode, uid, gid),
            }),
            file_lock_record: Arc::new(FileLockRecord::new()),
        }
    }
}

impl INode for TmpFsCharDev {
    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Char, guard.ownership.mode()),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
            rdev: u64::from(self.major) << 8 | u64::from(self.minor),
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn open(&self, path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        char_dev::open(path, flags, self.stat()?)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        &self.file_lock_record
    }
}
