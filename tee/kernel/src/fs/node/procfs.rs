use core::cmp;

use alloc::{
    string::ToString,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};

use crate::{
    error::{bail, err, Result},
    fs::{
        fd::{
            dir::open_dir,
            file::{open_file, File},
            FileDescriptor, FileLockRecord, LazyFileLockRecord,
        },
        node::DirEntryName,
        path::{FileName, Path},
    },
    memory::page::KernelPage,
    user::process::{
        memory::VirtualMemory,
        syscall::args::{
            FdNum, FileMode, FileType, FileTypeAndMode, OpenFlags, Pointer, Stat, Timespec,
        },
        Process,
    },
};

use super::{
    directory::{dir_impls, Directory, MountLocation, StaticLocation},
    lookup_node_with_parent, new_dev, new_ino, DirEntry, DynINode, FileAccessContext, INode,
};

pub fn new(location: MountLocation) -> Result<DynINode> {
    let dev = new_dev();
    Ok(Arc::new_cyclic(|this| ProcFsRoot {
        this: this.clone(),
        dev,
        ino: new_ino(),
        location,
        file_lock_record: LazyFileLockRecord::new(),
        self_link: Arc::new(SelfLink {
            parent: this.clone(),
            dev,
            ino: new_ino(),
            file_lock_record: LazyFileLockRecord::new(),
        }),
    }))
}

struct ProcFsRoot {
    this: Weak<Self>,
    dev: u64,
    ino: u64,
    location: MountLocation,
    file_lock_record: LazyFileLockRecord,
    self_link: Arc<SelfLink>,
}

impl INode for ProcFsRoot {
    dir_impls!();

    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: self.dev,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Dir, FileMode::from_bits_retain(0o777)),
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

    fn open(&self, path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        open_dir(path, self.this.upgrade().unwrap(), flags)
    }

    fn set_mode(&self, _mode: FileMode) {}

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
        if file_name == "self" {
            Ok(self.self_link.clone())
        } else {
            let bytes = file_name.as_bytes();
            let str = core::str::from_utf8(bytes).map_err(|_| err!(NoEnt))?;
            let pid = str.parse().map_err(|_| err!(NoEnt))?;
            let process = Process::find_by_pid(pid).ok_or(err!(NoEnt))?;
            Ok(ProcessDir::new(
                StaticLocation::new(self.this.upgrade().unwrap(), file_name.clone().into_owned()),
                self.dev,
                Arc::downgrade(&process),
            ))
        }
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

    fn delete(&self, _file_name: FileName<'static>) -> Result<()> {
        bail!(Perm)
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
    dev: u64,
    ino: u64,
    file_lock_record: LazyFileLockRecord,
}

impl INode for SelfLink {
    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: self.dev,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Link, FileMode::from_bits_retain(0o777)),
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

    fn open(&self, _path: Path, _flags: OpenFlags) -> Result<FileDescriptor> {
        bail!(Loop)
    }

    fn set_mode(&self, _mode: FileMode) {}

    fn read_link(&self, ctx: &FileAccessContext) -> Result<Path> {
        Path::new(ctx.process.pid().to_string().into_bytes())
    }

    fn try_resolve_link(
        &self,
        start_dir: DynINode,
        ctx: &mut FileAccessContext,
    ) -> Result<Option<(DynINode, DynINode)>> {
        ctx.follow_symlink()?;
        let file_name = FileName::new(ctx.process.pid().to_string().as_bytes())
            .unwrap()
            .into_owned();
        Ok(Some((
            start_dir,
            ProcessDir::new(
                StaticLocation::new(self.parent.upgrade().unwrap(), file_name),
                self.dev,
                Arc::downgrade(&ctx.process),
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
}

impl ProcessInos {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            root_dir: new_ino(),
            fd_dir: new_ino(),
            exe_link: new_ino(),
            maps_file: new_ino(),
        }
    }
}

struct ProcessDir {
    this: Weak<Self>,
    location: StaticLocation<ProcFsRoot>,
    dev: u64,
    process: Weak<Process>,
    file_lock_record: LazyFileLockRecord,
    fd_file_lock_record: LazyFileLockRecord,
    exe_link_lock_record: LazyFileLockRecord,
    maps_file_lock_record: LazyFileLockRecord,
}

impl ProcessDir {
    pub fn new(
        location: StaticLocation<ProcFsRoot>,
        dev: u64,
        process: Weak<Process>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            location,
            dev,
            process,
            file_lock_record: LazyFileLockRecord::new(),
            fd_file_lock_record: LazyFileLockRecord::new(),
            exe_link_lock_record: LazyFileLockRecord::new(),
            maps_file_lock_record: LazyFileLockRecord::new(),
        })
    }
}

impl INode for ProcessDir {
    dir_impls!();

    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.dev,
            ino: process.inos.root_dir,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Dir, FileMode::from_bits_retain(0o755)),
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

    fn open(&self, path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        open_dir(path, self.this.upgrade().unwrap(), flags)
    }

    fn set_mode(&self, _mode: FileMode) {}

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
        if file_name == "fd" {
            Ok(FdDir::new(
                StaticLocation::new(self.this.upgrade().unwrap(), file_name.clone().into_owned()),
                self.dev,
                self.process.clone(),
                self.fd_file_lock_record.get().clone(),
            ))
        } else if file_name == "exe" {
            Ok(ExeLink::new(
                self.dev,
                self.process.clone(),
                self.exe_link_lock_record.get().clone(),
            ))
        } else if file_name == "maps" {
            Ok(MapsFile::new(
                self.dev,
                self.process.clone(),
                self.maps_file_lock_record.get().clone(),
            ))
        } else {
            bail!(NoEnt)
        }
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
        Ok(entries)
    }

    fn delete(&self, _file_name: FileName<'static>) -> Result<()> {
        bail!(Perm)
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
    dev: u64,
    process: Weak<Process>,
    file_lock_record: Arc<FileLockRecord>,
}

impl FdDir {
    pub fn new(
        location: StaticLocation<ProcessDir>,
        dev: u64,
        process: Weak<Process>,
        file_lock_record: Arc<FileLockRecord>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            location,
            dev,
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
            dev: self.dev,
            ino: process.inos.fd_dir,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Dir, FileMode::from_bits_retain(0o755)),
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

    fn open(&self, path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        open_dir(path, self.this.upgrade().unwrap(), flags)
    }

    fn set_mode(&self, _mode: FileMode) {}

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
        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let fdtable = thread.fdtable.lock();
        fdtable.get_node(fd_num)
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

    fn is_empty(&self) -> bool {
        false
    }

    fn list_entries(&self, _ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let fdtable = thread.fdtable.lock();
        Ok(fdtable.list_entries())
    }

    fn delete(&self, _file_name: FileName<'static>) -> Result<()> {
        bail!(Perm)
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
    ino: u64,
    fd: FileDescriptor,
    file_lock_record: Arc<FileLockRecord>,
}

impl FdINode {
    pub fn new(ino: u64, fd: FileDescriptor, file_lock_record: Arc<FileLockRecord>) -> Self {
        Self {
            ino,
            fd,
            file_lock_record,
        }
    }
}

impl INode for FdINode {
    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
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
        })
    }

    fn open(&self, _path: Path, _flags: OpenFlags) -> Result<FileDescriptor> {
        Ok(self.fd.clone())
    }

    fn set_mode(&self, _mode: FileMode) {}

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn read_link(&self, _ctx: &FileAccessContext) -> Result<Path> {
        Ok(self.fd.path())
    }

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        &self.file_lock_record
    }
}

struct ExeLink {
    dev: u64,
    process: Weak<Process>,
    file_lock_record: Arc<FileLockRecord>,
}

impl ExeLink {
    pub fn new(
        dev: u64,
        process: Weak<Process>,
        file_lock_record: Arc<FileLockRecord>,
    ) -> Arc<Self> {
        Arc::new(Self {
            dev,
            process,
            file_lock_record,
        })
    }
}

impl INode for ExeLink {
    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.dev,
            ino: process.inos.exe_link,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Link, FileMode::from_bits_retain(0o777)),
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

    fn open(&self, _path: Path, _flags: OpenFlags) -> Result<FileDescriptor> {
        bail!(Loop)
    }

    fn set_mode(&self, _mode: FileMode) {}

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
    dev: u64,
    process: Weak<Process>,
    file_lock_record: Arc<FileLockRecord>,
}

impl MapsFile {
    pub fn new(
        dev: u64,
        process: Weak<Process>,
        file_lock_record: Arc<FileLockRecord>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            dev,
            process,
            file_lock_record,
        })
    }
}

impl INode for MapsFile {
    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.dev,
            ino: process.inos.maps_file,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::File, FileMode::from_bits_retain(0o444)),
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

    fn open(&self, path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        open_file(path, self.this.upgrade().unwrap(), flags)
    }

    fn set_mode(&self, _mode: FileMode) {}

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        &self.file_lock_record
    }
}

impl File for MapsFile {
    fn get_page(&self, _page_idx: usize) -> Result<KernelPage> {
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
