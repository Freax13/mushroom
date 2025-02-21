use core::{any::Any, cmp, ops::Deref};

use crate::{
    char_dev,
    error::{bail, ensure, err},
    fs::{
        FileSystem, StatFs,
        fd::{
            FileDescriptor, FileLockRecord, LazyFileLockRecord, PipeBlocked,
            dir::open_dir,
            file::{File, open_file},
            pipe::named::NamedPipe,
            stream_buffer,
        },
        ownership::Ownership,
    },
    memory::page::{Buffer, KernelPage},
    spin::{mutex::Mutex, rwlock::RwLock},
    time::now,
    user::process::{
        syscall::args::{ClockId, OpenFlags},
        thread::{Gid, Uid},
    },
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, btree_map::Entry},
    sync::{Arc, Weak},
    vec::Vec,
};
use async_trait::async_trait;

use super::{
    DirEntry, DirEntryName, DynINode, FileAccessContext, INode,
    directory::{Directory, DirectoryLocation, Location, dir_impls},
    lookup_node_with_parent, new_dev, new_ino,
};
use crate::{
    error::Result,
    fs::path::{FileName, Path},
    user::process::{
        memory::VirtualMemory,
        syscall::args::{FileMode, FileType, FileTypeAndMode, Pointer, Stat, Timespec},
    },
};

pub struct TmpFs {
    dev: u64,
}

impl TmpFs {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { dev: new_dev() })
    }
}

impl FileSystem for TmpFs {
    fn stat(&self) -> StatFs {
        StatFs {
            ty: 0x01021994,
            bsize: 0x1000,
            blocks: 0x200000,
            bfree: 0x1c0000,
            bavail: 0x1c0000,
            files: 0x100000,
            ffree: 0xc0000,
            fsid: bytemuck::cast(self.dev),
            namelen: 255,
            frsize: 0x1000,
            flags: 0,
        }
    }
}

pub struct TmpFsDir {
    fs: Arc<TmpFs>,
    ino: u64,
    this: Weak<Self>,
    location: Mutex<Location<Self>>,
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
        fs: Arc<TmpFs>,
        location: impl Into<Location<Self>>,
        mode: FileMode,
        uid: Uid,
        gid: Gid,
    ) -> Arc<Self> {
        let now = now(ClockId::Realtime);

        Arc::new_cyclic(|this_weak| Self {
            fs,
            ino: new_ino(),
            this: this_weak.clone(),
            location: Mutex::new(location.into()),
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
                let node = TmpFsFile::new(self.fs.clone(), mode, uid, gid);
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
            dev: self.fs.dev,
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

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(self.fs.clone())
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
        self.location.lock().get()
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
                let dir = TmpFsDir::new(self.fs.clone(), parent, mode, uid, gid);
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
                let now = now(ClockId::Realtime);
                let link = Arc::new(TmpFsSymlink {
                    fs: self.fs.clone(),
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
                let now = now(ClockId::Realtime);
                let link = Arc::new(TmpFsSymlink {
                    fs: self.fs.clone(),
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
                let char_dev = Arc::new(TmpFsCharDev::new(
                    self.fs.clone(),
                    major,
                    minor,
                    mode,
                    uid,
                    gid,
                ));
                entry.insert(TmpFsDirEntry::CharDev(char_dev.clone()));
                Ok(char_dev)
            }
            Entry::Occupied(_) => bail!(Exist),
        }
    }

    fn create_fifo(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
        uid: Uid,
        gid: Gid,
    ) -> Result<()> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name);
        match entry {
            Entry::Vacant(entry) => {
                let char_dev = Arc::new(TmpFsFifo::new(self.fs.clone(), mode, uid, gid));
                entry.insert(TmpFsDirEntry::Fifo(char_dev.clone()));
                Ok(())
            }
            Entry::Occupied(_) => bail!(Exist),
        }
    }

    fn is_empty(&self) -> bool {
        let guard = self.internal.lock();
        guard.items.is_empty()
    }

    fn list_entries(&self, _ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
        let location = self.location.lock().get();
        let parent_ino = location
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
        ensure!(Arc::ptr_eq(&new_dir.fs, &self.fs), XDev);

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
                        | TmpFsDirEntry::CharDev(_)
                        | TmpFsDirEntry::Fifo(_),
                        TmpFsDirEntry::File(_)
                        | TmpFsDirEntry::Symlink(_)
                        | TmpFsDirEntry::CharDev(_)
                        | TmpFsDirEntry::Fifo(_),
                    ) => {}
                    (
                        TmpFsDirEntry::File(_)
                        | TmpFsDirEntry::Symlink(_)
                        | TmpFsDirEntry::CharDev(_)
                        | TmpFsDirEntry::Fifo(_),
                        TmpFsDirEntry::Dir(_),
                    ) => {
                        bail!(IsDir)
                    }
                    (
                        TmpFsDirEntry::Dir(_),
                        TmpFsDirEntry::File(_)
                        | TmpFsDirEntry::Symlink(_)
                        | TmpFsDirEntry::CharDev(_)
                        | TmpFsDirEntry::Fifo(_),
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

                if let TmpFsDirEntry::Dir(ref dir) = entry {
                    // If the entry is a directory, change it's location to the new location.
                    let parent = DirectoryLocation::new(self.this.clone(), newname.clone());
                    *dir.location.lock() = parent.into();
                }

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

            let new_entry = new_guard.items.entry(newname.clone());
            let new = match &new_entry {
                Entry::Vacant(_) => None,
                Entry::Occupied(entry) => Some(entry.get()),
            };

            // Make sure that we can rename the old entry over the new entry.
            can_rename(old_entry.get(), new, check_is_dir)?;

            ensure!(!no_replace || new.is_none(), Exist);

            // Do the rename.
            let node = old_entry.remove();

            if let TmpFsDirEntry::Dir(ref dir) = node {
                // If the entry is a directory, change it's location to the new location.
                let parent = DirectoryLocation::new(new_dir.this.clone(), newname);
                *dir.location.lock() = parent.into();
            }

            match new_entry {
                Entry::Vacant(entry) => {
                    entry.insert(node);
                }
                Entry::Occupied(mut entry) => {
                    entry.insert(node);
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
        ensure!(Arc::ptr_eq(&new_dir.fs, &self.fs), XDev);

        if core::ptr::eq(self, &*new_dir) {
            if newname == oldname {
                Ok(())
            } else {
                let mut guard = self.internal.lock();

                // Do the exchange.
                let entry = guard.items.get(&oldname).ok_or(err!(NoEnt))?.clone();
                let Entry::Occupied(mut map_entry) = guard.items.entry(newname.clone()) else {
                    bail!(NoEnt);
                };
                let entry = map_entry.insert(entry);

                if let TmpFsDirEntry::Dir(ref dir) = entry {
                    // If the entry is a directory, change it's location to the new location.
                    let parent = DirectoryLocation::new(self.this.clone(), newname);
                    *dir.location.lock() = parent.into();
                }

                guard.items.insert(oldname, entry);

                Ok(())
            }
        } else {
            let (mut old_guard, mut new_guard) = self.internal.lock_two(&new_dir.internal);

            // Do the exchange.
            let entry = old_guard.items.get(&oldname).ok_or(err!(NoEnt))?;
            let Entry::Occupied(mut map_entry) = new_guard.items.entry(newname.clone()) else {
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

            if let TmpFsDirEntry::Dir(ref dir) = entry {
                // If the entry is a directory, change it's location to the new location.
                let parent = DirectoryLocation::new(new_dir.this.clone(), newname);
                *dir.location.lock() = parent.into();
            }

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
        ensure!(Arc::ptr_eq(&new_dir.fs, &self.fs), XDev);

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
                    node.update_times(now(ClockId::Realtime), None, None);
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
                    node.update_times(now(ClockId::Realtime), None, None);
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
    Fifo(Arc<TmpFsFifo>),
    Mount(DynINode),
}

impl TmpFsDirEntry {
    fn node(&self) -> DynINode {
        match self {
            TmpFsDirEntry::File(file) => file.clone(),
            TmpFsDirEntry::Dir(dir) => dir.clone(),
            TmpFsDirEntry::Symlink(symlink) => symlink.clone(),
            TmpFsDirEntry::CharDev(char_dev) => char_dev.clone(),
            TmpFsDirEntry::Fifo(fifo) => fifo.clone(),
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
            Self::Fifo(fifo) => Self::Fifo(fifo.clone()),
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
            TmpFsDirEntry::Fifo(fifo) => &**fifo,
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
    fs: Arc<TmpFs>,
    ino: u64,
    this: Weak<Self>,
    internal: RwLock<TmpFsFileInternal>,
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
    pub fn new(fs: Arc<TmpFs>, mode: FileMode, uid: Uid, gid: Gid) -> Arc<Self> {
        let now = now(ClockId::Realtime);

        Arc::new_cyclic(|this| Self {
            fs,
            ino: new_ino(),
            this: this.clone(),
            internal: RwLock::new(TmpFsFileInternal {
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
        self.internal.write().links += 1;
    }

    fn decrease_link_count(&self) {
        self.internal.write().links -= 1;
    }
}

impl INode for TmpFsFile {
    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.read();
        // FIXME: Fill in more values.
        Ok(Stat {
            dev: self.fs.dev,
            ino: self.ino,
            nlink: guard.links,
            mode: FileTypeAndMode::new(FileType::File, guard.ownership.mode()),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
            rdev: 0,
            size: guard.buffer.len() as i64,
            blksize: 4096,
            blocks: guard.buffer.len().div_ceil(512) as i64,
            atime: guard.atime,
            mtime: guard.mtime,
            ctime: guard.ctime,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(self.fs.clone())
    }

    fn open(&self, path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        open_file(path, self.this.upgrade().unwrap(), flags)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.write().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.write().ownership.chown(uid, gid, ctx)
    }

    fn update_times(&self, ctime: Timespec, atime: Option<Timespec>, mtime: Option<Timespec>) {
        let mut guard = self.internal.write();
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
    fn get_page(&self, page_idx: usize, shared: bool) -> Result<KernelPage> {
        let mut guard = self.internal.write();
        guard.buffer.get_page(page_idx, shared)
    }

    fn read(&self, offset: usize, buf: &mut [u8], no_atime: bool) -> Result<usize> {
        let mut guard = self.internal.write();
        if !no_atime {
            guard.atime = now(ClockId::Realtime);
        }
        Ok(guard.buffer.read(offset, buf))
    }

    fn read_to_user(
        &self,
        offset: usize,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
        no_atime: bool,
    ) -> Result<usize> {
        let mut guard = self.internal.write();
        if !no_atime {
            guard.atime = now(ClockId::Realtime);
        }
        guard.buffer.read_to_user(offset, vm, pointer, len)
    }

    fn write(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        let mut guard = self.internal.write();
        let now = now(ClockId::Realtime);
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
        let mut guard = self.internal.write();
        let now = now(ClockId::Realtime);
        guard.ctime = now;
        guard.mtime = now;
        guard.buffer.write_from_user(offset, vm, pointer, len)
    }

    fn append(&self, buf: &[u8]) -> Result<usize> {
        let mut guard = self.internal.write();
        let now = now(ClockId::Realtime);
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
        let mut guard = self.internal.write();
        let now = now(ClockId::Realtime);
        guard.ctime = now;
        guard.mtime = now;
        let offset = guard.buffer.len();
        guard.buffer.write_from_user(offset, vm, pointer, len)
    }

    fn splice_from(
        &self,
        read_half: &stream_buffer::ReadHalf,
        offset: usize,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        read_half.splice_to(len, |buffer, len| {
            let (slice1, slice2) = buffer.as_slices();
            let len1 = cmp::min(len, slice1.len());
            let len2 = len - len1;
            let slice1 = &slice1[..len1];
            let slice2 = &slice2[..len2];

            let mut guard = self.internal.write();
            let now = now(ClockId::Realtime);
            guard.ctime = now;
            guard.mtime = now;
            guard.buffer.write(offset, slice1).unwrap();
            guard.buffer.write(offset + slice1.len(), slice2).unwrap();

            buffer.drain(..len);
        })
    }

    fn splice_to(
        &self,
        write_half: &stream_buffer::WriteHalf,
        mut offset: usize,
        len: usize,
        no_atime: bool,
    ) -> Result<Result<usize, PipeBlocked>> {
        let mut guard = self.internal.write();
        let len = cmp::min(len, guard.buffer.len().saturating_sub(offset));

        let len = write_half.splice_from(len, |buffer, mut len| {
            let mut chunk = [0; 128];
            while len > 0 {
                let chunk_len = cmp::min(len, chunk.len());
                let chunk = &mut chunk[..chunk_len];

                let n = guard.buffer.read(offset, chunk);
                debug_assert_eq!(n, chunk_len);

                buffer.extend(chunk.iter().copied());

                offset += n;
                len -= n;
            }
        })?;
        if !no_atime {
            guard.atime = now(ClockId::Realtime);
        }
        Ok(len)
    }

    fn copy_file_range(
        &self,
        mut offset_in: usize,
        out: &dyn File,
        mut offset_out: usize,
        mut len: usize,
    ) -> Result<usize> {
        // TODO: Update access times.

        if len == 0 {
            return Ok(0);
        }

        let mut copied = 0;

        if core::ptr::addr_eq(self, out) {
            // Make sure the range don't overlap.
            let range_in = offset_in..offset_in + len;
            let range_out = offset_out..offset_out + len;
            ensure!(
                !range_in.contains(&range_out.start)
                    && !range_in.contains(&range_out.end)
                    && !range_out.contains(&range_in.start)
                    && !range_out.contains(&range_in.end),
                Inval
            );

            let mut guard = self.internal.write();
            let mut chunk = [0; 0x1000];
            while len > 0 {
                let chunk_len = cmp::min(len, chunk.len());
                let chunk = &mut chunk[..chunk_len];

                // Copy bytes from the in file.
                let n = guard.buffer.read(offset_in, chunk);

                // Exit the loop if there are no more bytes to be copied.
                if n == 0 {
                    break;
                }

                // Copy bytes to the out file.
                let res = guard.buffer.write(offset_out, &chunk[..n]);
                let n = match res {
                    Ok(n) => n,
                    Err(err) => {
                        // If this is the first write operation, return the
                        // error.
                        if copied == 0 {
                            return Err(err);
                        }
                        // Otherwise exit the loop.
                        break;
                    }
                };

                // Advance all the counters.
                len -= n;
                offset_in += n;
                offset_out += n;
                copied += n;
            }
        } else {
            let out = <dyn Any>::downcast_ref::<Self>(out as &dyn Any).ok_or(err!(XDev))?;

            let (in_guard, mut out_guard) = self.internal.write_two(&out.internal);

            let mut chunk = [0; 0x1000];
            while len > 0 {
                let chunk_len = cmp::min(len, chunk.len());
                let chunk = &mut chunk[..chunk_len];

                // Copy bytes from the in file.
                let n = in_guard.buffer.read(offset_in, chunk);

                // Exit the loop if there are no more bytes to be copied.
                if n == 0 {
                    break;
                }

                // Copy bytes to the out file.
                let res = out_guard.buffer.write(offset_out, &chunk[..n]);
                let n = match res {
                    Ok(n) => n,
                    Err(err) => {
                        // If this is the first write operation, return the
                        // error.
                        if copied == 0 {
                            return Err(err);
                        }
                        // Otherwise exit the loop.
                        break;
                    }
                };

                // Advance all the counters.
                len -= n;
                offset_in += n;
                offset_out += n;
                copied += n;
            }
        }

        Ok(copied)
    }

    fn truncate(&self, len: usize) -> Result<()> {
        let mut guard = self.internal.write();
        let now = now(ClockId::Realtime);
        guard.ctime = now;
        guard.mtime = now;
        guard.buffer.truncate(len)
    }
}

#[derive(Clone)]
pub struct TmpFsSymlink {
    fs: Arc<TmpFs>,
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
            dev: self.fs.dev,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Link, FileMode::ALL),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
            rdev: 0,
            size: self.target.as_bytes().len() as i64,
            blksize: 0,
            blocks: 0,
            atime: guard.atime,
            mtime: guard.mtime,
            ctime: guard.ctime,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(self.fs.clone())
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
    fs: Arc<TmpFs>,
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
    pub fn new(fs: Arc<TmpFs>, major: u16, minor: u8, mode: FileMode, uid: Uid, gid: Gid) -> Self {
        Self {
            fs,
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
            dev: self.fs.dev,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Char, guard.ownership.mode()),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
            rdev: (u64::from(self.major) << 8) | u64::from(self.minor),
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(self.fs.clone())
    }

    fn open(&self, path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        char_dev::open(path, flags, self.stat()?, self.fs.clone())
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

pub struct TmpFsFifo {
    fs: Arc<TmpFs>,
    ino: u64,
    internal: Mutex<TmpFsFifoInternal>,
    file_lock_record: LazyFileLockRecord,
    named_pipe: NamedPipe,
}

struct TmpFsFifoInternal {
    ownership: Ownership,
}

impl TmpFsFifo {
    pub fn new(fs: Arc<TmpFs>, mode: FileMode, uid: Uid, gid: Gid) -> Self {
        Self {
            fs,
            ino: new_ino(),
            internal: Mutex::new(TmpFsFifoInternal {
                ownership: Ownership::new(mode, uid, gid),
            }),
            file_lock_record: LazyFileLockRecord::new(),
            named_pipe: NamedPipe::new(),
        }
    }
}

#[async_trait]
impl INode for TmpFsFifo {
    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        Ok(Stat {
            dev: self.fs.dev,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Fifo, guard.ownership.mode()),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(self.fs.clone())
    }

    fn open(&self, _: Path, _: OpenFlags) -> Result<FileDescriptor> {
        bail!(Perm)
    }

    async fn async_open(self: Arc<Self>, path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        self.named_pipe.open(flags, self.clone(), path).await
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        self.file_lock_record.get()
    }
}
