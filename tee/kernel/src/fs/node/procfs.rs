use core::cmp;

use alloc::{
    boxed::Box,
    string::ToString,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use async_trait::async_trait;
use constants::MAX_APS_COUNT;

use crate::{
    error::{ErrorKind, Result, bail, ensure, err},
    fs::{
        FileSystem, StatFs,
        fd::{
            FileDescriptor, FileLockRecord, LazyFileLockRecord,
            dir::open_dir,
            file::{File, open_file},
        },
        node::DirEntryName,
        path::{FileName, Path},
    },
    memory::page::KernelPage,
    time::now,
    user::process::{
        Process,
        memory::{VirtualMemory, WriteToVec},
        syscall::args::{
            ClockId, FdNum, FileMode, FileType, FileTypeAndMode, OpenFlags, Pointer, Stat, Timespec,
        },
        thread::{Gid, Uid},
    },
};

use super::{
    DirEntry, DynINode, FileAccessContext, INode,
    directory::{Directory, MountLocation, StaticLocation, dir_impls},
    lookup_node_with_parent, new_dev, new_ino,
};

pub struct ProcFs {
    dev: u64,
}

impl FileSystem for ProcFs {
    fn stat(&self) -> StatFs {
        StatFs {
            ty: 0x9fa0,
            bsize: 0x1000,
            blocks: 0,
            bfree: 0,
            bavail: 0,
            files: 0,
            ffree: 0,
            fsid: bytemuck::cast(self.dev),
            namelen: 255,
            frsize: 0,
            flags: 0,
        }
    }
}

pub fn new(location: MountLocation) -> Result<DynINode> {
    let fs = Arc::new(ProcFs { dev: new_dev() });
    Ok(Arc::new_cyclic(|this| ProcFsRoot {
        this: this.clone(),
        fs: fs.clone(),
        ino: new_ino(),
        location,
        file_lock_record: LazyFileLockRecord::new(),
        self_link: Arc::new(SelfLink {
            parent: this.clone(),
            fs: fs.clone(),
            ino: new_ino(),
            file_lock_record: LazyFileLockRecord::new(),
        }),
        stat_file: StatFile::new(fs.clone()),
        uptime_file: UptimeFile::new(fs),
    }))
}

struct ProcFsRoot {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    ino: u64,
    location: MountLocation,
    file_lock_record: LazyFileLockRecord,
    self_link: Arc<SelfLink>,
    stat_file: Arc<StatFile>,
    uptime_file: Arc<UptimeFile>,
}

impl INode for ProcFsRoot {
    dir_impls!();

    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: self.fs.dev,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Dir, FileMode::from_bits_retain(0o777)),
            uid: Uid::SUPER_USER,
            gid: Gid::SUPER_USER,
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

    fn open(&self, _path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        open_dir(self.this.upgrade().unwrap(), flags)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        self.file_lock_record.get()
    }
}

impl Directory for ProcFsRoot {
    fn location(&self) -> Result<Option<(DynINode, FileName<'static>)>> {
        self.location.get()
    }

    fn get_node(&self, file_name: &FileName, _ctx: &FileAccessContext) -> Result<DynINode> {
        Ok(match file_name.as_bytes() {
            b"self" => self.self_link.clone(),
            b"stat" => self.stat_file.clone(),
            b"uptime" => self.uptime_file.clone(),
            _ => {
                let bytes = file_name.as_bytes();
                let str = core::str::from_utf8(bytes).map_err(|_| err!(NoEnt))?;
                let pid = str.parse().map_err(|_| err!(NoEnt))?;
                let process = Process::find_by_pid(pid).ok_or(err!(NoEnt))?;
                ProcessDir::new(
                    StaticLocation::new(
                        self.this.upgrade().unwrap(),
                        file_name.clone().into_owned(),
                    ),
                    self.fs.clone(),
                    Arc::downgrade(&process),
                )
            }
        })
    }

    fn create_file(
        &self,
        _: FileName<'static>,
        _: FileMode,
        _: Uid,
        _: Gid,
    ) -> Result<Result<DynINode, DynINode>> {
        bail!(NoEnt)
    }

    fn create_dir(&self, _: FileName<'static>, _: FileMode, _: Uid, _: Gid) -> Result<DynINode> {
        bail!(NoEnt)
    }

    fn create_link(
        &self,
        _file_name: FileName<'static>,
        _target: Path,
        _uid: Uid,
        _gid: Gid,
        _create_new: bool,
    ) -> Result<DynINode> {
        bail!(NoEnt)
    }

    fn create_char_dev(
        &self,
        _file_name: FileName<'static>,
        _major: u16,
        _minor: u8,
        _mode: FileMode,
        _uid: Uid,
        _gid: Gid,
    ) -> Result<DynINode> {
        bail!(NoEnt)
    }

    fn create_fifo(
        &self,
        _file_name: FileName<'static>,
        _mode: FileMode,
        _uid: Uid,
        _gid: Gid,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn is_empty(&self) -> bool {
        false
    }

    fn list_entries(&self, _ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
        let mut entries = vec![DirEntry {
            ino: self.ino,
            ty: FileType::Dir,
            name: DirEntryName::Dot,
        }];
        if let Some(entry) = self.location.parent_entry() {
            entries.push(entry);
        }
        entries.push(DirEntry {
            ino: self.self_link.ino,
            ty: FileType::Link,
            name: DirEntryName::FileName(FileName::new(b"self").unwrap()),
        });
        entries.push(DirEntry {
            ino: self.stat_file.ino,
            ty: FileType::File,
            name: DirEntryName::FileName(FileName::new(b"stat").unwrap()),
        });
        entries.push(DirEntry {
            ino: self.uptime_file.ino,
            ty: FileType::File,
            name: DirEntryName::FileName(FileName::new(b"uptime").unwrap()),
        });
        entries.extend(Process::all().map(|process| {
            DirEntry {
                ino: process.inos.root_dir,
                ty: FileType::Dir,
                name: DirEntryName::FileName(
                    FileName::new(process.pid().to_string().as_bytes())
                        .unwrap()
                        .into_owned(),
                ),
            }
        }));
        Ok(entries)
    }

    fn delete_non_dir(&self, _file_name: FileName<'static>) -> Result<()> {
        bail!(Perm)
    }

    fn delete_dir(&self, _file_name: FileName<'static>) -> Result<()> {
        bail!(Perm)
    }

    fn rename(
        &self,
        _oldname: FileName<'static>,
        _check_is_dir: bool,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _no_replace: bool,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn exchange(
        &self,
        _oldname: FileName<'static>,
        _new_dir: DynINode,
        _newname: FileName<'static>,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn hard_link(
        &self,
        _oldname: FileName<'static>,
        _follow_symlink: bool,
        _new_dir: DynINode,
        _newname: FileName<'static>,
    ) -> Result<Option<Path>> {
        bail!(NoEnt)
    }
}

struct SelfLink {
    parent: Weak<ProcFsRoot>,
    fs: Arc<ProcFs>,
    ino: u64,
    file_lock_record: LazyFileLockRecord,
}

impl INode for SelfLink {
    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: self.fs.dev,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Link, FileMode::from_bits_retain(0o777)),
            uid: Uid::SUPER_USER,
            gid: Gid::SUPER_USER,
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

    fn open(&self, _path: Path, _flags: OpenFlags) -> Result<FileDescriptor> {
        bail!(Loop)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn read_link(&self, ctx: &FileAccessContext) -> Result<Path> {
        Path::new(
            ctx.process
                .as_ref()
                .ok_or(err!(Srch))?
                .pid()
                .to_string()
                .into_bytes(),
        )
    }

    fn try_resolve_link(
        &self,
        start_dir: DynINode,
        ctx: &mut FileAccessContext,
    ) -> Result<Option<(DynINode, DynINode)>> {
        ctx.follow_symlink()?;
        let process = ctx.process.as_ref().ok_or(err!(Srch))?;
        let file_name = FileName::new(process.pid().to_string().as_bytes())
            .unwrap()
            .into_owned();
        Ok(Some((
            start_dir,
            ProcessDir::new(
                StaticLocation::new(self.parent.upgrade().unwrap(), file_name),
                self.fs.clone(),
                Arc::downgrade(process),
            ),
        )))
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        self.file_lock_record.get()
    }
}

pub struct ProcessInos {
    root_dir: u64,
    fd_dir: u64,
    exe_link: u64,
    maps_file: u64,
    stat_file: u64,
}

impl ProcessInos {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            root_dir: new_ino(),
            fd_dir: new_ino(),
            exe_link: new_ino(),
            maps_file: new_ino(),
            stat_file: new_ino(),
        }
    }
}

struct ProcessDir {
    this: Weak<Self>,
    location: StaticLocation<ProcFsRoot>,
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    file_lock_record: LazyFileLockRecord,
    fd_file_lock_record: LazyFileLockRecord,
    exe_link_lock_record: LazyFileLockRecord,
    maps_file_lock_record: LazyFileLockRecord,
    stat_file_lock_record: LazyFileLockRecord,
}

impl ProcessDir {
    pub fn new(
        location: StaticLocation<ProcFsRoot>,
        fs: Arc<ProcFs>,
        process: Weak<Process>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            location,
            fs,
            process,
            file_lock_record: LazyFileLockRecord::new(),
            fd_file_lock_record: LazyFileLockRecord::new(),
            exe_link_lock_record: LazyFileLockRecord::new(),
            maps_file_lock_record: LazyFileLockRecord::new(),
            stat_file_lock_record: LazyFileLockRecord::new(),
        })
    }
}

impl INode for ProcessDir {
    dir_impls!();

    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.fs.dev,
            ino: process.inos.root_dir,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Dir, FileMode::from_bits_retain(0o755)),
            uid: Uid::SUPER_USER,
            gid: Gid::SUPER_USER,
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

    fn open(&self, _path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        open_dir(self.this.upgrade().unwrap(), flags)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        self.file_lock_record.get()
    }
}

impl Directory for ProcessDir {
    fn location(&self) -> Result<Option<(DynINode, FileName<'static>)>> {
        self.location.get()
    }

    fn get_node(&self, file_name: &FileName, _ctx: &FileAccessContext) -> Result<DynINode> {
        Ok(match file_name.as_bytes() {
            b"fd" => FdDir::new(
                StaticLocation::new(self.this.upgrade().unwrap(), file_name.clone().into_owned()),
                self.fs.clone(),
                self.process.clone(),
                self.fd_file_lock_record.get().clone(),
            ),
            b"exe" => ExeLink::new(
                self.fs.clone(),
                self.process.clone(),
                self.exe_link_lock_record.get().clone(),
            ),
            b"maps" => MapsFile::new(
                self.fs.clone(),
                self.process.clone(),
                self.maps_file_lock_record.get().clone(),
            ),
            b"stat" => ProcessStatFile::new(
                self.fs.clone(),
                self.process.clone(),
                self.stat_file_lock_record.get().clone(),
            ),
            _ => bail!(NoEnt),
        })
    }

    fn create_file(
        &self,
        _: FileName<'static>,
        _: FileMode,
        _: Uid,
        _: Gid,
    ) -> Result<Result<DynINode, DynINode>> {
        bail!(NoEnt)
    }

    fn create_dir(&self, _: FileName<'static>, _: FileMode, _: Uid, _: Gid) -> Result<DynINode> {
        bail!(NoEnt)
    }

    fn create_link(
        &self,
        _file_name: FileName<'static>,
        _target: Path,
        _uid: Uid,
        _gid: Gid,
        _create_new: bool,
    ) -> Result<DynINode> {
        bail!(NoEnt)
    }

    fn create_char_dev(
        &self,
        _file_name: FileName<'static>,
        _major: u16,
        _minor: u8,
        _mode: FileMode,
        _uid: Uid,
        _gid: Gid,
    ) -> Result<DynINode> {
        bail!(NoEnt)
    }

    fn create_fifo(
        &self,
        _file_name: FileName<'static>,
        _mode: FileMode,
        _uid: Uid,
        _gid: Gid,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn is_empty(&self) -> bool {
        false
    }

    fn list_entries(&self, _ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let mut entries = vec![DirEntry {
            ino: process.inos.root_dir,
            ty: FileType::Dir,
            name: DirEntryName::Dot,
        }];
        if let Some(entry) = self.location.parent_entry() {
            entries.push(entry);
        }
        entries.push(DirEntry {
            ino: process.inos.fd_dir,
            ty: FileType::Dir,
            name: DirEntryName::FileName(FileName::new(b"fd").unwrap()),
        });
        entries.push(DirEntry {
            ino: process.inos.exe_link,
            ty: FileType::Link,
            name: DirEntryName::FileName(FileName::new(b"exe").unwrap()),
        });
        entries.push(DirEntry {
            ino: process.inos.maps_file,
            ty: FileType::File,
            name: DirEntryName::FileName(FileName::new(b"maps").unwrap()),
        });
        entries.push(DirEntry {
            ino: process.inos.stat_file,
            ty: FileType::File,
            name: DirEntryName::FileName(FileName::new(b"stat").unwrap()),
        });
        Ok(entries)
    }

    fn delete_non_dir(&self, _file_name: FileName<'static>) -> Result<()> {
        bail!(Perm)
    }

    fn delete_dir(&self, _file_name: FileName<'static>) -> Result<()> {
        bail!(Perm)
    }

    fn rename(
        &self,
        _oldname: FileName<'static>,
        _check_is_dir: bool,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _no_replace: bool,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn exchange(
        &self,
        _oldname: FileName<'static>,
        _new_dir: DynINode,
        _newname: FileName<'static>,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn hard_link(
        &self,
        _oldname: FileName<'static>,
        _follow_symlink: bool,
        _new_dir: DynINode,
        _newname: FileName<'static>,
    ) -> Result<Option<Path>> {
        bail!(NoEnt)
    }
}

struct FdDir {
    this: Weak<Self>,
    location: StaticLocation<ProcessDir>,
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    file_lock_record: Arc<FileLockRecord>,
}

impl FdDir {
    pub fn new(
        location: StaticLocation<ProcessDir>,
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        file_lock_record: Arc<FileLockRecord>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            location,
            fs,
            process,
            file_lock_record,
        })
    }
}

impl INode for FdDir {
    dir_impls!();

    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.fs.dev,
            ino: process.inos.fd_dir,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Dir, FileMode::from_bits_retain(0o755)),
            uid: Uid::SUPER_USER,
            gid: Gid::SUPER_USER,
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

    fn open(&self, _path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        open_dir(self.this.upgrade().unwrap(), flags)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        &self.file_lock_record
    }
}

impl Directory for FdDir {
    fn location(&self) -> Result<Option<(DynINode, FileName<'static>)>> {
        self.location.get()
    }

    fn get_node(&self, file_name: &FileName, _ctx: &FileAccessContext) -> Result<DynINode> {
        let file_name = file_name.as_bytes();
        let file_name = core::str::from_utf8(file_name).map_err(|_| err!(NoEnt))?;
        let fd_num = file_name.parse().map_err(|_| err!(NoEnt))?;
        let fd_num = FdNum::new(fd_num);

        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let guard = process.credentials.lock();
        let uid = guard.real_user_id;
        let gid = guard.real_group_id;
        drop(guard);

        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let fdtable = thread.fdtable.lock();
        fdtable.get_node(self.fs.clone(), fd_num, uid, gid)
    }

    fn create_file(
        &self,
        _: FileName<'static>,
        _: FileMode,
        _: Uid,
        _: Gid,
    ) -> Result<Result<DynINode, DynINode>> {
        bail!(NoEnt)
    }

    fn create_dir(&self, _: FileName<'static>, _: FileMode, _: Uid, _: Gid) -> Result<DynINode> {
        bail!(NoEnt)
    }

    fn create_link(
        &self,
        _file_name: FileName<'static>,
        _target: Path,
        _uid: Uid,
        _gid: Gid,
        _create_new: bool,
    ) -> Result<DynINode> {
        bail!(NoEnt)
    }

    fn create_char_dev(
        &self,
        _file_name: FileName<'static>,
        _major: u16,
        _minor: u8,
        _mode: FileMode,
        _uid: Uid,
        _gid: Gid,
    ) -> Result<DynINode> {
        bail!(NoEnt)
    }

    fn create_fifo(
        &self,
        _file_name: FileName<'static>,
        _mode: FileMode,
        _uid: Uid,
        _gid: Gid,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn is_empty(&self) -> bool {
        false
    }

    fn list_entries(&self, _ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let fdtable = thread.fdtable.lock();
        Ok(fdtable.list_entries())
    }

    fn delete_non_dir(&self, _file_name: FileName<'static>) -> Result<()> {
        bail!(Perm)
    }

    fn delete_dir(&self, _file_name: FileName<'static>) -> Result<()> {
        bail!(Perm)
    }

    fn rename(
        &self,
        _oldname: FileName<'static>,
        _check_is_dir: bool,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _no_replace: bool,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn exchange(
        &self,
        _oldname: FileName<'static>,
        _new_dir: DynINode,
        _newname: FileName<'static>,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn hard_link(
        &self,
        _oldname: FileName<'static>,
        _follow_symlink: bool,
        _new_dir: DynINode,
        _newname: FileName<'static>,
    ) -> Result<Option<Path>> {
        bail!(NoEnt)
    }
}

#[derive(Clone)]
pub struct FdINode {
    fs: Arc<ProcFs>,
    ino: u64,
    uid: Uid,
    gid: Gid,
    fd: FileDescriptor,
    file_lock_record: Arc<FileLockRecord>,
}

impl FdINode {
    pub fn new(
        fs: Arc<ProcFs>,
        ino: u64,
        uid: Uid,
        gid: Gid,
        fd: FileDescriptor,
        file_lock_record: Arc<FileLockRecord>,
    ) -> Self {
        Self {
            fs,
            ino,
            uid,
            gid,
            fd,
            file_lock_record,
        }
    }
}

impl INode for FdINode {
    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: self.fs.dev,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Link, FileMode::OWNER_ALL),
            uid: self.uid,
            gid: self.gid,
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
        bail!(Loop)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(OpNotSupp)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        ensure!(ctx.is_user(uid), Perm);
        ensure!(ctx.is_in_group(gid), Perm);
        Ok(())
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn read_link(&self, _ctx: &FileAccessContext) -> Result<Path> {
        self.fd.path()
    }

    fn try_resolve_link(
        &self,
        start_dir: DynINode,
        ctx: &mut FileAccessContext,
    ) -> Result<Option<(DynINode, DynINode)>> {
        ctx.follow_symlink()?;
        Ok(Some((
            start_dir,
            Arc::new(FollowedFdINode {
                fd: self.fd.clone(),
                file_lock_record: self.file_lock_record.clone(),
            }),
        )))
    }

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        &self.file_lock_record
    }
}

/// This is the INode that's returned after following the link at an fd inode.
struct FollowedFdINode {
    fd: FileDescriptor,
    file_lock_record: Arc<FileLockRecord>,
}

#[async_trait]
impl INode for FollowedFdINode {
    fn stat(&self) -> Result<Stat> {
        if let Some((_, node)) = self.fd.path_fd_node() {
            // Special case for path fds: Forward the stat call to the pointed
            // to node.
            node.stat()
        } else {
            self.fd.stat()
        }
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        if let Some((_, node)) = self.fd.path_fd_node() {
            // Special case for path fds: Forward the open call to the pointed
            // to node.
            node.fs()
        } else {
            self.fd.fs()
        }
    }

    fn open(&self, _: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        if let Some((path, node)) = self.fd.path_fd_node() {
            // Special case for path fds: Forward the open call to the pointed
            // to node.
            node.open(path, flags)
        } else {
            Ok(self.fd.clone())
        }
    }

    async fn async_open(self: Arc<Self>, _: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        if let Some((path, node)) = self.fd.path_fd_node() {
            // Special case for path fds: Forward the open call to the pointed
            // to node.
            node.async_open(path, flags).await
        } else {
            Ok(self.fd.clone())
        }
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        if let Some((_, node)) = self.fd.path_fd_node() {
            // Special case for path fds: Forward the chmod call to the pointed
            // to node, but rewrite ELOOP to EOPNOTSUPP.
            node.chmod(mode, ctx).map_err(|err| {
                if err.kind() == ErrorKind::Loop {
                    err!(OpNotSupp)
                } else {
                    err
                }
            })
        } else {
            self.fd.chmod(mode, ctx)
        }
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        if let Some((_, node)) = self.fd.path_fd_node() {
            // Special case for path fds: Forward the chown call to the pointed
            // to node.
            node.chown(uid, gid, ctx)
        } else {
            self.fd.chown(uid, gid, ctx)
        }
    }

    fn update_times(&self, ctime: Timespec, mtime: Option<Timespec>, atime: Option<Timespec>) {
        if let Some((_, node)) = self.fd.path_fd_node() {
            // Special case for path fds: Forward the chmod call to the pointed
            // to node, but rewrite ELOOP to EOPNOTSUPP.
            node.update_times(ctime, mtime, atime);
        } else {
            self.fd.update_times(ctime, mtime, atime);
        }
    }

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        &self.file_lock_record
    }
}

struct ExeLink {
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    file_lock_record: Arc<FileLockRecord>,
}

impl ExeLink {
    pub fn new(
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        file_lock_record: Arc<FileLockRecord>,
    ) -> Arc<Self> {
        Arc::new(Self {
            fs,
            process,
            file_lock_record,
        })
    }
}

impl INode for ExeLink {
    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.fs.dev,
            ino: process.inos.exe_link,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Link, FileMode::from_bits_retain(0o777)),
            uid: Uid::SUPER_USER,
            gid: Gid::SUPER_USER,
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

    fn open(&self, _path: Path, _flags: OpenFlags) -> Result<FileDescriptor> {
        bail!(Loop)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn read_link(&self, _ctx: &FileAccessContext) -> Result<Path> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let exe = process.exe();
        Ok(exe)
    }

    fn try_resolve_link(
        &self,
        start_dir: DynINode,
        ctx: &mut FileAccessContext,
    ) -> Result<Option<(DynINode, DynINode)>> {
        ctx.follow_symlink()?;
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let exe = process.exe();
        lookup_node_with_parent(start_dir, &exe, ctx).map(Some)
    }

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        &self.file_lock_record
    }
}

struct MapsFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    file_lock_record: Arc<FileLockRecord>,
}

impl MapsFile {
    pub fn new(
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        file_lock_record: Arc<FileLockRecord>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            fs,
            process,
            file_lock_record,
        })
    }
}

impl INode for MapsFile {
    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.fs.dev,
            ino: process.inos.maps_file,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::File, FileMode::from_bits_retain(0o444)),
            uid: Uid::SUPER_USER,
            gid: Gid::SUPER_USER,
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

    fn open(&self, path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        open_file(path, self.this.upgrade().unwrap(), flags)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        &self.file_lock_record
    }
}

impl File for MapsFile {
    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, offset: usize, buf: &mut [u8], _no_atime: bool) -> Result<usize> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let maps = thread.lock().virtual_memory().maps();
        let offset = cmp::min(offset, maps.len());
        let maps = &maps[offset..];
        let len = cmp::min(maps.len(), buf.len());
        buf[..len].copy_from_slice(&maps[..len]);
        Ok(len)
    }

    fn read_to_user(
        &self,
        offset: usize,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
        _no_atime: bool,
    ) -> Result<usize> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let maps = thread.lock().virtual_memory().maps();
        let offset = cmp::min(offset, maps.len());
        let maps = &maps[offset..];
        let len = cmp::min(maps.len(), len);
        vm.write_bytes(pointer.get(), &maps[..len])?;
        Ok(len)
    }

    fn write(&self, _offset: usize, _buf: &[u8]) -> Result<usize> {
        bail!(Acces)
    }

    fn write_from_user(
        &self,
        _offset: usize,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        _len: usize,
    ) -> Result<usize> {
        bail!(Acces)
    }

    fn append(&self, _buf: &[u8]) -> Result<usize> {
        bail!(Acces)
    }

    fn append_from_user(
        &self,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        _len: usize,
    ) -> Result<usize> {
        bail!(Acces)
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        bail!(Acces)
    }
}

struct ProcessStatFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    file_lock_record: Arc<FileLockRecord>,
}

impl ProcessStatFile {
    pub fn new(
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        file_lock_record: Arc<FileLockRecord>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            fs,
            process,
            file_lock_record,
        })
    }
}

impl INode for ProcessStatFile {
    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.fs.dev,
            ino: process.inos.maps_file,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::File, FileMode::from_bits_retain(0o444)),
            uid: Uid::SUPER_USER,
            gid: Gid::SUPER_USER,
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

    fn open(&self, path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        open_file(path, self.this.upgrade().unwrap(), flags)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        &self.file_lock_record
    }
}

impl File for ProcessStatFile {
    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, offset: usize, buf: &mut [u8], _no_atime: bool) -> Result<usize> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let stat = thread.lock().stat();
        let offset = cmp::min(offset, stat.len());
        let stat = &stat[offset..];
        let len = cmp::min(stat.len(), buf.len());
        buf[..len].copy_from_slice(&stat[..len]);
        Ok(len)
    }

    fn read_to_user(
        &self,
        offset: usize,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
        _no_atime: bool,
    ) -> Result<usize> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let stat = thread.lock().stat();
        let offset = cmp::min(offset, stat.len());
        let stat = &stat[offset..];
        let len = cmp::min(stat.len(), len);
        vm.write_bytes(pointer.get(), &stat[..len])?;
        Ok(len)
    }

    fn write(&self, _offset: usize, _buf: &[u8]) -> Result<usize> {
        bail!(Acces)
    }

    fn write_from_user(
        &self,
        _offset: usize,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        _len: usize,
    ) -> Result<usize> {
        bail!(Acces)
    }

    fn append(&self, _buf: &[u8]) -> Result<usize> {
        bail!(Acces)
    }

    fn append_from_user(
        &self,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        _len: usize,
    ) -> Result<usize> {
        bail!(Acces)
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        bail!(Acces)
    }
}

struct StatFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    ino: u64,
    file_lock_record: LazyFileLockRecord,
}

impl StatFile {
    pub fn new(fs: Arc<ProcFs>) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            fs,
            ino: new_ino(),
            file_lock_record: LazyFileLockRecord::new(),
        })
    }

    fn content(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        // TODO: Don't hard-code values.
        buffer
            .extend_from_slice(b"cpu 10132153 290696 3084719 46828483 16683 0 25195 0 175628 0\n");
        for cpu in 0..MAX_APS_COUNT {
            writeln!(
                buffer,
                "cpu{cpu} 10132153 290696 3084719 46828483 16683 0 25195 0 175628 0",
            )
            .unwrap();
        }

        buffer
    }
}

impl INode for StatFile {
    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: self.fs.dev,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::File, FileMode::from_bits_retain(0o444)),
            uid: Uid::SUPER_USER,
            gid: Gid::SUPER_USER,
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

    fn open(&self, path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        open_file(path, self.this.upgrade().unwrap(), flags)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        self.file_lock_record.get()
    }
}

impl File for StatFile {
    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, offset: usize, buf: &mut [u8], _no_atime: bool) -> Result<usize> {
        let content = self.content();
        let offset = cmp::min(offset, content.len());
        let content = &content[offset..];
        let len = cmp::min(content.len(), buf.len());
        buf[..len].copy_from_slice(&content[..len]);
        Ok(len)
    }

    fn read_to_user(
        &self,
        offset: usize,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
        _no_atime: bool,
    ) -> Result<usize> {
        let content = self.content();
        let offset = cmp::min(offset, content.len());
        let content = &content[offset..];
        let len = cmp::min(content.len(), len);
        vm.write_bytes(pointer.get(), &content[..len])?;
        Ok(len)
    }

    fn write(&self, _offset: usize, _buf: &[u8]) -> Result<usize> {
        bail!(Acces)
    }

    fn write_from_user(
        &self,
        _offset: usize,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        _len: usize,
    ) -> Result<usize> {
        bail!(Acces)
    }

    fn append(&self, _buf: &[u8]) -> Result<usize> {
        bail!(Acces)
    }

    fn append_from_user(
        &self,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        _len: usize,
    ) -> Result<usize> {
        bail!(Acces)
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        bail!(Acces)
    }
}

struct UptimeFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    ino: u64,
    file_lock_record: LazyFileLockRecord,
}

impl UptimeFile {
    pub fn new(fs: Arc<ProcFs>) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            fs,
            ino: new_ino(),
            file_lock_record: LazyFileLockRecord::new(),
        })
    }

    fn content(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        let uptime = now(ClockId::Monotonic);
        // TODO: We currently don't track the idle time, so we just multiple
        // the uptime by 3.
        let idle_time = uptime.saturating_add(uptime).saturating_add(uptime);

        write!(
            buffer,
            "{}.{:02}",
            uptime.tv_sec,
            uptime.tv_nsec / 10_000_000
        )
        .unwrap();
        write!(
            buffer,
            "{}.{:02}",
            idle_time.tv_sec,
            idle_time.tv_nsec / 10_000_000
        )
        .unwrap();

        buffer
    }
}

impl INode for UptimeFile {
    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: self.fs.dev,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::File, FileMode::from_bits_retain(0o444)),
            uid: Uid::SUPER_USER,
            gid: Gid::SUPER_USER,
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

    fn open(&self, path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        open_file(path, self.this.upgrade().unwrap(), flags)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        self.file_lock_record.get()
    }
}

impl File for UptimeFile {
    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, offset: usize, buf: &mut [u8], _no_atime: bool) -> Result<usize> {
        let content = self.content();
        let offset = cmp::min(offset, content.len());
        let content = &content[offset..];
        let len = cmp::min(content.len(), buf.len());
        buf[..len].copy_from_slice(&content[..len]);
        Ok(len)
    }

    fn read_to_user(
        &self,
        offset: usize,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
        _no_atime: bool,
    ) -> Result<usize> {
        let content = self.content();
        let offset = cmp::min(offset, content.len());
        let content = &content[offset..];
        let len = cmp::min(content.len(), len);
        vm.write_bytes(pointer.get(), &content[..len])?;
        Ok(len)
    }

    fn write(&self, _offset: usize, _buf: &[u8]) -> Result<usize> {
        bail!(Acces)
    }

    fn write_from_user(
        &self,
        _offset: usize,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        _len: usize,
    ) -> Result<usize> {
        bail!(Acces)
    }

    fn append(&self, _buf: &[u8]) -> Result<usize> {
        bail!(Acces)
    }

    fn append_from_user(
        &self,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        _len: usize,
    ) -> Result<usize> {
        bail!(Acces)
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        bail!(Acces)
    }
}
