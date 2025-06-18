use core::{any::Any, cmp, ops::Deref};

use crate::{
    char_dev,
    error::{bail, ensure, err},
    fs::{
        FileSystem, StatFs,
        fd::{
            FileLockRecord, KernelReadBuf, KernelWriteBuf, LazyFileLockRecord,
            OpenFileDescriptionData, PipeBlocked, ReadBuf, StrongFileDescriptor, WriteBuf,
            dir::open_dir,
            file::{File, open_file},
            inotify::{Watchers, next_cookie},
            pipe::named::NamedPipe,
            stream_buffer,
            unix_socket::StreamUnixSocket,
        },
        ownership::Ownership,
    },
    memory::page::{Buffer, KernelPage},
    spin::{lazy::Lazy, mutex::Mutex, rwlock::RwLock},
    time::now,
    user::process::{
        futex::Futexes,
        syscall::args::{ClockId, InotifyMask, OpenFlags, UnixAddr},
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
    DirEntry, DirEntryName, DynINode, FileAccessContext, INode, Link, LinkLocation,
    directory::{Directory, dir_impls},
    lookup_link, new_dev, new_ino,
};
use crate::{
    error::Result,
    fs::path::{FileName, Path},
    user::process::syscall::args::{FileMode, FileType, FileTypeAndMode, Stat, Timespec},
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
    location: LinkLocation,
    file_lock_record: LazyFileLockRecord,
    watchers: Watchers,
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
        location: LinkLocation,
        mode: FileMode,
        uid: Uid,
        gid: Gid,
    ) -> Arc<Self> {
        let now = now(ClockId::Realtime);

        Arc::new_cyclic(|this_weak| Self {
            fs,
            ino: new_ino(),
            this: this_weak.clone(),
            location,
            file_lock_record: LazyFileLockRecord::new(),
            watchers: Watchers::new(),
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
    ) -> Result<Result<(LinkLocation, Arc<TmpFsFile>), Link>> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name.clone());
        match entry {
            Entry::Vacant(entry) => {
                let location = LinkLocation::new(self.this.upgrade().unwrap(), entry.key().clone());
                let node = TmpFsFile::new(self.fs.clone(), mode, uid, gid);
                entry.insert(TmpFsDirEntry::File(location.clone(), node.clone()));
                guard.update_times();
                drop(guard);

                self.watchers()
                    .send_event(InotifyMask::CREATE, None, Some(file_name));

                Ok(Ok((location, node)))
            }
            Entry::Occupied(entry) => Ok(Err(entry.get().link())),
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

    fn open(
        &self,
        _: LinkLocation,
        flags: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        open_dir(self.this.upgrade().unwrap(), flags)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        let mut guard = self.internal.lock();
        guard.ownership.chmod(mode, ctx)?;
        guard.ctime = now(ClockId::Realtime);
        Ok(())
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        let mut guard = self.internal.lock();
        guard.ownership.chown(uid, gid, ctx)?;
        guard.ctime = now(ClockId::Realtime);
        Ok(())
    }

    fn mount(
        &self,
        file_name: FileName<'static>,
        create_dir: fn(LinkLocation) -> Result<Arc<dyn Directory>>,
    ) -> Result<()> {
        let location = LinkLocation::new(self.this.upgrade().unwrap(), file_name.clone());
        let node = create_dir(location)?;
        let mut guard = self.internal.lock();
        guard.items.insert(file_name, TmpFsDirEntry::Mount(node));
        guard.update_times();
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

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl Directory for TmpFsDir {
    fn location(&self) -> &LinkLocation {
        &self.location
    }

    fn get_node(&self, path_segment: &FileName, _ctx: &FileAccessContext) -> Result<Link> {
        self.internal
            .lock()
            .items
            .get(path_segment)
            .map(TmpFsDirEntry::link)
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
                let location = LinkLocation::new(self.this.upgrade().unwrap(), file_name.clone());
                let dir = TmpFsDir::new(self.fs.clone(), location, mode, uid, gid);
                entry.insert(TmpFsDirEntry::Dir(dir.clone()));
                guard.update_times();
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
    ) -> Result<Result<Link, Link>> {
        self.create_file(file_name, mode, uid, gid).map(|res| {
            res.map(|(loc, file)| Link {
                location: loc,
                node: file,
            })
        })
    }

    fn create_link(
        &self,
        file_name: FileName<'static>,
        target: Path,
        uid: Uid,
        gid: Gid,
        create_new: bool,
    ) -> Result<()> {
        let create_link = || {
            let now = now(ClockId::Realtime);
            let location = LinkLocation::new(self.this.upgrade().unwrap(), file_name.clone());
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
                watchers: Watchers::new(),
            });
            TmpFsDirEntry::Symlink(location, link)
        };

        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name.clone());
        match entry {
            Entry::Vacant(entry) => {
                entry.insert(create_link());
                guard.update_times();
                Ok(())
            }
            Entry::Occupied(mut entry) => {
                ensure!(!create_new, Exist);
                entry.insert(create_link());
                guard.update_times();
                Ok(())
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
    ) -> Result<()> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name.clone());
        match entry {
            Entry::Vacant(entry) => {
                let loc = LinkLocation::new(self.this.upgrade().unwrap(), file_name);
                let char_dev = Arc::new(TmpFsCharDev::new(
                    self.fs.clone(),
                    major,
                    minor,
                    mode,
                    uid,
                    gid,
                ));
                entry.insert(TmpFsDirEntry::CharDev(loc, char_dev));
                guard.update_times();
                Ok(())
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
        let entry = guard.items.entry(file_name.clone());
        match entry {
            Entry::Vacant(entry) => {
                let loc = LinkLocation::new(self.this.upgrade().unwrap(), file_name);
                let char_dev = Arc::new(TmpFsFifo::new(self.fs.clone(), mode, uid, gid));
                entry.insert(TmpFsDirEntry::Fifo(loc, char_dev.clone()));
                guard.update_times();
                Ok(())
            }
            Entry::Occupied(_) => bail!(Exist),
        }
    }

    fn bind_socket(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
        uid: Uid,
        gid: Gid,
        socket: &StreamUnixSocket,
        socketname: &Path,
    ) -> Result<()> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name.clone());
        let Entry::Vacant(entry) = entry else {
            bail!(AddrInUse)
        };
        let loc = LinkLocation::new(self.this.upgrade().unwrap(), file_name);
        entry.insert(TmpFsDirEntry::Socket(
            loc,
            Arc::new(TmpFsSocket::new(
                self.fs.clone(),
                mode,
                uid,
                gid,
                socket.bind(UnixAddr::Pathname(socketname.clone()))?,
            )),
        ));
        guard.update_times();
        Ok(())
    }

    fn is_empty(&self) -> bool {
        let guard = self.internal.lock();
        guard.items.is_empty()
    }

    fn list_entries(&self, _ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
        let parent_ino = self
            .location
            .parent()
            .and_then(|entry| entry.stat().ok())
            .map(|stat| stat.ino);

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
        let (file_name, node) = entry.remove_entry();
        guard.update_times();
        drop(guard);

        node.watchers()
            .send_event(InotifyMask::DELETE_SELF, None, None);
        self.watchers()
            .send_event(InotifyMask::DELETE_SELF, None, Some(file_name));

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
        let (file_name, node) = entry.remove_entry();
        guard.update_times();
        drop(guard);

        node.watchers()
            .send_event(InotifyMask::DELETE_SELF, None, None);
        self.watchers()
            .send_event(InotifyMask::DELETE_SELF, None, Some(file_name));

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
                        TmpFsDirEntry::File(_, _)
                        | TmpFsDirEntry::Symlink(_, _)
                        | TmpFsDirEntry::CharDev(_, _)
                        | TmpFsDirEntry::Fifo(_, _)
                        | TmpFsDirEntry::Socket(_, _),
                        TmpFsDirEntry::File(_, _)
                        | TmpFsDirEntry::Symlink(_, _)
                        | TmpFsDirEntry::CharDev(_, _)
                        | TmpFsDirEntry::Fifo(_, _)
                        | TmpFsDirEntry::Socket(_, _),
                    ) => {}
                    (
                        TmpFsDirEntry::File(_, _)
                        | TmpFsDirEntry::Symlink(_, _)
                        | TmpFsDirEntry::CharDev(_, _)
                        | TmpFsDirEntry::Fifo(_, _)
                        | TmpFsDirEntry::Socket(_, _),
                        TmpFsDirEntry::Dir(_),
                    ) => {
                        bail!(IsDir)
                    }
                    (
                        TmpFsDirEntry::Dir(_),
                        TmpFsDirEntry::File(_, _)
                        | TmpFsDirEntry::Symlink(_, _)
                        | TmpFsDirEntry::CharDev(_, _)
                        | TmpFsDirEntry::Fifo(_, _)
                        | TmpFsDirEntry::Socket(_, _),
                    ) => bail!(NotDir),
                    (TmpFsDirEntry::Dir(_), TmpFsDirEntry::Dir(new)) => {
                        let guard = new.internal.lock();
                        ensure!(guard.items.is_empty(), NotEmpty);
                    }
                    (TmpFsDirEntry::Mount(_), _) | (_, TmpFsDirEntry::Mount(_)) => {
                        bail!(Busy)
                    }
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
                entry.update_link(self.this.upgrade().unwrap(), newname.clone());

                entry
                    .watchers()
                    .send_event(InotifyMask::MOVE_SELF, None, None);

                guard.items.insert(newname.clone(), entry);

                guard.update_times();
                drop(guard);

                let cookie = next_cookie();
                self.watchers()
                    .send_event(InotifyMask::MOVED_FROM, Some(cookie), Some(oldname));
                self.watchers()
                    .send_event(InotifyMask::MOVED_TO, Some(cookie), Some(newname));

                Ok(())
            }
        } else {
            let (mut old_guard, mut new_guard) = self.internal.lock_two(&new_dir.internal);

            // Look up the entries.
            let Entry::Occupied(old_entry) = old_guard.items.entry(oldname.clone()) else {
                bail!(NoEnt);
            };

            // Make sure that the old_entry isn't new_dir or any of its parents.
            let mut parent = new_dir.clone() as Arc<dyn Directory>;
            loop {
                ensure!(!core::ptr::addr_eq(&**old_entry.get(), &*parent), Inval);
                let new_parent = parent.location().parent().ok_or(err!(NoEnt))?;
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
            node.update_link(new_dir.clone(), newname.clone());

            node.watchers()
                .send_event(InotifyMask::MOVE_SELF, None, None);

            match new_entry {
                Entry::Vacant(entry) => {
                    entry.insert(node);
                }
                Entry::Occupied(mut entry) => {
                    entry.insert(node);
                }
            }

            old_guard.update_times();
            new_guard.update_times();
            drop(old_guard);
            drop(new_guard);

            let cookie = next_cookie();
            self.watchers()
                .send_event(InotifyMask::MOVED_FROM, Some(cookie), Some(oldname));
            new_dir
                .watchers()
                .send_event(InotifyMask::MOVED_TO, Some(cookie), Some(newname));

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

                ensure!(guard.items.contains_key(&oldname), NoEnt);
                ensure!(guard.items.contains_key(&newname), NoEnt);

                let old_entry = guard.items.remove(&oldname).unwrap();

                old_entry
                    .watchers()
                    .send_event(InotifyMask::MOVE_SELF, None, None);
                old_entry.update_link(self.this.upgrade().unwrap(), newname.clone());

                let new_entry = guard.items.insert(newname.clone(), old_entry).unwrap();

                new_entry
                    .watchers()
                    .send_event(InotifyMask::MOVE_SELF, None, None);
                new_entry.update_link(self.this.upgrade().unwrap(), oldname.clone());
                guard.items.insert(oldname.clone(), new_entry);

                guard.update_times();
                drop(guard);

                let cookie = next_cookie();
                self.watchers().send_event(
                    InotifyMask::MOVED_FROM,
                    Some(cookie),
                    Some(oldname.clone()),
                );
                new_dir.watchers().send_event(
                    InotifyMask::MOVED_TO,
                    Some(cookie),
                    Some(newname.clone()),
                );

                let cookie = next_cookie();
                new_dir
                    .watchers()
                    .send_event(InotifyMask::MOVED_FROM, Some(cookie), Some(newname));
                self.watchers()
                    .send_event(InotifyMask::MOVED_TO, Some(cookie), Some(oldname));

                Ok(())
            }
        } else {
            let (mut old_guard, mut new_guard) = self.internal.lock_two(&new_dir.internal);

            // Do the exchange.
            let Entry::Occupied(mut old_entry) = old_guard.items.entry(oldname.clone()) else {
                bail!(NoEnt);
            };
            let Entry::Occupied(mut new_entry) = new_guard.items.entry(newname.clone()) else {
                bail!(NoEnt);
            };

            // Make sure that the old_entry isn't new_dir or any of its parents.
            let mut parent = new_dir.clone() as Arc<dyn Directory>;
            loop {
                ensure!(!core::ptr::addr_eq(&**old_entry.get(), &*parent), Inval);
                let new_parent = parent.location().parent().ok_or(err!(NoEnt))?;
                let old_parent = core::mem::replace(&mut parent, new_parent);

                // Exit the loop if we've reached the root node.
                if Arc::ptr_eq(&parent, &old_parent) {
                    break;
                }
            }
            // ... and vice versa.
            let mut parent = self.this.upgrade().unwrap() as Arc<dyn Directory>;
            loop {
                ensure!(!core::ptr::addr_eq(&**new_entry.get(), &*parent), Inval);
                let new_parent = parent.location().parent().ok_or(err!(NoEnt))?;
                let old_parent = core::mem::replace(&mut parent, new_parent);

                // Exit the loop if we've reached the root node.
                if Arc::ptr_eq(&parent, &old_parent) {
                    break;
                }
            }

            // Swap the entries.
            core::mem::swap(old_entry.get_mut(), new_entry.get_mut());

            // If the entries are directories, change their locations.
            old_entry
                .get()
                .update_link(self.this.upgrade().unwrap(), oldname.clone());
            new_entry
                .get()
                .update_link(new_dir.clone(), newname.clone());

            old_guard.update_times();
            new_guard.update_times();
            drop(old_guard);
            drop(new_guard);

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
            let entry = guard.items.get(&oldname).ok_or(err!(NoEnt))?;
            if follow_symlink && let TmpFsDirEntry::Symlink(_, symlink) = &entry {
                return Ok(Some(symlink.target.clone()));
            }

            let entry = entry.clone(LinkLocation::new(
                self.this.upgrade().unwrap(),
                newname.clone(),
            ))?;

            match guard.items.entry(newname) {
                Entry::Vacant(e) => {
                    let node = e.insert(entry);
                    node.update_times(now(ClockId::Realtime), None, None);
                    guard.update_times();
                }
                Entry::Occupied(_) => bail!(Exist),
            }
        } else {
            let (old_guard, mut new_guard) = self.internal.lock_two(&new_dir.internal);
            let entry = old_guard.items.get(&oldname).ok_or(err!(NoEnt))?;

            if follow_symlink && let TmpFsDirEntry::Symlink(_, symlink) = &entry {
                return Ok(Some(symlink.target.clone()));
            }

            match new_guard.items.entry(newname) {
                Entry::Vacant(e) => {
                    let entry = entry.clone(LinkLocation::new(new_dir.clone(), e.key().clone()))?;
                    let node = e.insert(entry);
                    node.update_times(now(ClockId::Realtime), None, None);
                    new_guard.update_times();
                }
                Entry::Occupied(_) => bail!(Exist),
            }
        }

        Ok(None)
    }
}

impl TmpFsDirInternal {
    fn update_times(&mut self) {
        let now = now(ClockId::Realtime);
        self.ctime = now;
        self.mtime = now;
    }
}

enum TmpFsDirEntry {
    File(LinkLocation, Arc<TmpFsFile>),
    Dir(Arc<TmpFsDir>),
    Symlink(LinkLocation, Arc<TmpFsSymlink>),
    CharDev(LinkLocation, Arc<TmpFsCharDev>),
    Fifo(LinkLocation, Arc<TmpFsFifo>),
    Socket(LinkLocation, Arc<TmpFsSocket>),
    Mount(Arc<dyn Directory>),
}

impl TmpFsDirEntry {
    fn link(&self) -> Link {
        match self {
            TmpFsDirEntry::File(loc, node) => Link {
                location: loc.clone(),
                node: node.clone(),
            },
            TmpFsDirEntry::Dir(node) => Link {
                location: node.location().clone(),
                node: node.clone(),
            },
            TmpFsDirEntry::Symlink(loc, node) => Link {
                location: loc.clone(),
                node: node.clone(),
            },
            TmpFsDirEntry::CharDev(loc, node) => Link {
                location: loc.clone(),
                node: node.clone(),
            },
            TmpFsDirEntry::Fifo(loc, node) => Link {
                location: loc.clone(),
                node: node.clone(),
            },
            TmpFsDirEntry::Socket(loc, node) => Link {
                location: loc.clone(),
                node: node.clone(),
            },
            TmpFsDirEntry::Mount(node) => Link {
                location: node.location().clone(),
                node: node.clone(),
            },
        }
    }

    fn clone(&self, location: LinkLocation) -> Result<Self> {
        Ok(match self {
            Self::File(_, file) => {
                file.increase_link_count();
                Self::File(location, file.clone())
            }
            Self::Dir(_) => bail!(Perm),
            Self::Symlink(_, symlink) => Self::Symlink(location, symlink.clone()),
            Self::CharDev(_, char_dev) => Self::CharDev(location, char_dev.clone()),
            Self::Fifo(_, fifo) => Self::Fifo(location, fifo.clone()),
            Self::Socket(_, socket) => Self::Socket(location, socket.clone()),
            Self::Mount(_) => bail!(Busy),
        })
    }

    fn update_link(&self, parent: Arc<dyn Directory>, file_name: FileName<'static>) {
        match self {
            TmpFsDirEntry::File(loc, _) => loc.update(parent, file_name),
            TmpFsDirEntry::Dir(dir) => dir.location.update(parent, file_name),
            TmpFsDirEntry::Symlink(loc, _) => loc.update(parent, file_name),
            TmpFsDirEntry::CharDev(loc, _) => loc.update(parent, file_name),
            TmpFsDirEntry::Fifo(loc, _) => loc.update(parent, file_name),
            TmpFsDirEntry::Socket(loc, _) => loc.update(parent, file_name),
            TmpFsDirEntry::Mount(dir) => dir.location().update(parent, file_name),
        }
    }
}

impl Deref for TmpFsDirEntry {
    type Target = dyn INode;

    fn deref(&self) -> &Self::Target {
        match self {
            TmpFsDirEntry::File(_, file) => &**file,
            TmpFsDirEntry::Dir(dir) => &**dir,
            TmpFsDirEntry::Symlink(_, symlink) => &**symlink,
            TmpFsDirEntry::CharDev(_, char_dev) => &**char_dev,
            TmpFsDirEntry::Fifo(_, fifo) => &**fifo,
            TmpFsDirEntry::Socket(_, socket) => &**socket,
            TmpFsDirEntry::Mount(mount) => &**mount,
        }
    }
}

impl Drop for TmpFsDirEntry {
    fn drop(&mut self) {
        match self {
            TmpFsDirEntry::File(_, file) => file.decrease_link_count(),
            TmpFsDirEntry::Dir(dir) => dir.location().unlink(),
            TmpFsDirEntry::Mount(dir) => dir.location().unlink(),
            _ => {}
        }
    }
}

pub struct TmpFsFile {
    fs: Arc<TmpFs>,
    ino: u64,
    this: Weak<Self>,
    internal: RwLock<TmpFsFileInternal>,
    file_lock_record: LazyFileLockRecord,
    watchers: Watchers,
    futexes: Lazy<Arc<Futexes>>,
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
            watchers: Watchers::new(),
            futexes: Lazy::new(|| Arc::new(Futexes::new())),
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

    fn open(
        &self,
        location: LinkLocation,
        flags: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        open_file(self.this.upgrade().unwrap(), location, flags)
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

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl File for TmpFsFile {
    fn get_page(&self, page_idx: usize, shared: bool) -> Result<KernelPage> {
        let mut guard = self.internal.write();
        guard.buffer.get_page(page_idx, shared)
    }

    fn futexes(&self) -> Option<Arc<Futexes>> {
        Some(self.futexes.clone())
    }

    fn read(&self, offset: usize, buf: &mut dyn ReadBuf, no_atime: bool) -> Result<usize> {
        let mut guard = self.internal.write();
        if !no_atime {
            guard.atime = now(ClockId::Realtime);
        }
        guard.buffer.read(offset, buf)
    }

    fn write(&self, offset: usize, buf: &dyn WriteBuf) -> Result<usize> {
        let mut guard = self.internal.write();
        let now = now(ClockId::Realtime);
        guard.ctime = now;
        guard.mtime = now;
        guard.buffer.write(offset, buf)
    }

    fn append(&self, buf: &dyn WriteBuf) -> Result<(usize, usize)> {
        let mut guard = self.internal.write();
        let now = now(ClockId::Realtime);
        guard.ctime = now;
        guard.mtime = now;
        let offset = guard.buffer.len();
        let len = guard.buffer.write(offset, buf)?;
        Ok((len, offset + len))
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
            guard
                .buffer
                .write(offset, &KernelWriteBuf::new(slice1))
                .unwrap();
            guard
                .buffer
                .write(offset + slice1.len(), &KernelWriteBuf::new(slice2))
                .unwrap();

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

                let n = guard
                    .buffer
                    .read(offset, &mut KernelReadBuf::new(chunk))
                    .unwrap();
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
                let n = guard
                    .buffer
                    .read(offset_in, &mut KernelReadBuf::new(chunk))
                    .unwrap();

                // Exit the loop if there are no more bytes to be copied.
                if n == 0 {
                    break;
                }

                // Copy bytes to the out file.
                let res = guard
                    .buffer
                    .write(offset_out, &KernelWriteBuf::new(&chunk[..n]));
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
                let n = in_guard
                    .buffer
                    .read(offset_in, &mut KernelReadBuf::new(chunk))
                    .unwrap();

                // Exit the loop if there are no more bytes to be copied.
                if n == 0 {
                    break;
                }

                // Copy bytes to the out file.
                let res = out_guard
                    .buffer
                    .write(offset_out, &KernelWriteBuf::new(&chunk[..n]));
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

pub struct TmpFsSymlink {
    fs: Arc<TmpFs>,
    ino: u64,
    target: Path,
    file_lock_record: Arc<FileLockRecord>,
    watchers: Watchers,
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
            mode: FileTypeAndMode::new(FileType::Link, guard.ownership.mode()),
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

    fn open(
        &self,
        _: LinkLocation,
        _: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        bail!(Loop)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
    }

    fn read_link(&self, _ctx: &FileAccessContext) -> Result<Path> {
        Ok(self.target.clone())
    }

    fn try_resolve_link(
        &self,
        start_dir: Link,
        _location: LinkLocation,
        ctx: &mut FileAccessContext,
    ) -> Result<Option<Link>> {
        ctx.follow_symlink()?;
        lookup_link(start_dir, &self.target, ctx).map(Some)
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

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

pub struct TmpFsCharDev {
    fs: Arc<TmpFs>,
    ino: u64,
    major: u16,
    minor: u8,
    internal: Mutex<TmpFsCharDevInternal>,
    file_lock_record: Arc<FileLockRecord>,
    watchers: Watchers,
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
            watchers: Watchers::new(),
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

    fn open(
        &self,
        location: LinkLocation,
        flags: OpenFlags,
        ctx: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        char_dev::open(location, flags, self.stat()?, self.fs.clone(), ctx)
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

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

pub struct TmpFsFifo {
    fs: Arc<TmpFs>,
    ino: u64,
    internal: Mutex<TmpFsFifoInternal>,
    file_lock_record: LazyFileLockRecord,
    watchers: Watchers,
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
            watchers: Watchers::new(),
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

    fn open(
        &self,
        _: LinkLocation,
        _: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        bail!(Perm)
    }

    async fn async_open(
        self: Arc<Self>,
        location: LinkLocation,
        flags: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        let link = Link {
            location,
            node: self.clone(),
        };
        self.named_pipe.open(flags, link).await
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

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

pub struct TmpFsSocket {
    fs: Arc<TmpFs>,
    ino: u64,
    internal: Mutex<TmpFsSocketInternal>,
    file_lock_record: LazyFileLockRecord,
    watchers: Watchers,
    socket: Weak<OpenFileDescriptionData<StreamUnixSocket>>,
}

struct TmpFsSocketInternal {
    ownership: Ownership,
}

impl TmpFsSocket {
    pub fn new(
        fs: Arc<TmpFs>,
        mode: FileMode,
        uid: Uid,
        gid: Gid,
        socket: Weak<OpenFileDescriptionData<StreamUnixSocket>>,
    ) -> Self {
        Self {
            fs,
            ino: new_ino(),
            internal: Mutex::new(TmpFsSocketInternal {
                ownership: Ownership::new(mode, uid, gid),
            }),
            file_lock_record: LazyFileLockRecord::new(),
            watchers: Watchers::new(),
            socket,
        }
    }
}

#[async_trait]
impl INode for TmpFsSocket {
    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        Ok(Stat {
            dev: self.fs.dev,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Socket, guard.ownership.mode()),
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

    fn open(
        &self,
        _: LinkLocation,
        _: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        bail!(NxIo)
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

    fn get_socket(&self) -> Result<Arc<OpenFileDescriptionData<StreamUnixSocket>>> {
        self.socket.upgrade().ok_or(err!(ConnRefused))
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}
