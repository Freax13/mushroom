use alloc::{
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::cmp;

use crate::{
    error::{Result, bail},
    fs::{
        FileSystem,
        fd::{
            BsdFileLockRecord, LazyBsdFileLockRecord, LazyUnixFileLockRecord, ReadBuf,
            StrongFileDescriptor, UnixFileLockRecord, WriteBuf,
            dir::open_dir,
            file::{File, open_file},
            inotify::Watchers,
            unix_socket::StreamUnixSocket,
        },
        node::{
            DirEntry, DirEntryName, DynINode, FileAccessContext, INode, Link, LinkLocation,
            directory::{Directory, dir_impls},
            new_ino,
            procfs::ProcFs,
        },
        path::{FileName, Path},
    },
    memory::page::KernelPage,
    user::{
        syscall::args::{
            FallocateMode, FileMode, FileType, FileTypeAndMode, OpenFlags, Stat, Timespec,
        },
        thread::{Gid, Uid},
    },
};

pub struct KernelDir {
    this: Weak<Self>,
    location: LinkLocation,
    fs: Arc<ProcFs>,
    ino: u64,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    watchers: Arc<Watchers>,
    hostname_file: Arc<HostnameFile>,
}

impl KernelDir {
    pub fn new(
        location: LinkLocation,
        fs: Arc<ProcFs>,
        ino: u64,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        watchers: Arc<Watchers>,
        hostname_file: Arc<HostnameFile>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            location,
            fs: fs.clone(),
            ino,
            bsd_file_lock_record,
            watchers,
            hostname_file,
        })
    }
}

impl INode for KernelDir {
    dir_impls!();

    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: self.fs.dev,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Dir, FileMode::from_bits_retain(0o555)),
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

    fn open(
        &self,
        _: LinkLocation,
        flags: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        open_dir(self.this.upgrade().unwrap(), flags)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn bsd_file_lock_record(&self) -> &Arc<BsdFileLockRecord> {
        &self.bsd_file_lock_record
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl Directory for KernelDir {
    fn location(&self) -> &LinkLocation {
        &self.location
    }

    fn create_file(
        &self,
        file_name: FileName<'static>,
        _: FileMode,
        ctx: &FileAccessContext,
    ) -> Result<Result<Link, Link>> {
        Directory::get_node(self, &file_name, ctx).map(Err)
    }

    fn create_tmp_file(&self, _: FileMode, _: &FileAccessContext) -> Result<Link> {
        bail!(NoEnt)
    }

    fn create_dir(
        &self,
        _: FileName<'static>,
        _: FileMode,
        _: &FileAccessContext,
    ) -> Result<DynINode> {
        bail!(NoEnt)
    }

    fn create_link(
        &self,
        _: FileName<'static>,
        _: Path,
        _: Uid,
        _: Gid,
        _create_new: bool,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn create_char_dev(
        &self,
        _: FileName<'static>,
        _major: u16,
        _minor: u8,
        _: FileMode,
        _: Uid,
        _: Gid,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn create_fifo(&self, _: FileName<'static>, _: FileMode, _: Uid, _: Gid) -> Result<()> {
        bail!(NoEnt)
    }

    fn bind_socket(
        &self,
        _: FileName<'static>,
        _: FileMode,
        _: Uid,
        _: Gid,
        _: &StreamUnixSocket,
        _: &Path,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn is_empty(&self) -> bool {
        false
    }

    fn list_entries(&self, _: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
        let mut entries = vec![DirEntry {
            ino: self.ino,
            ty: FileType::Dir,
            name: DirEntryName::Dot,
        }];
        if let Some(entry) = self.location.parent()
            && let Ok(stat) = entry.stat()
        {
            entries.push(DirEntry {
                ino: stat.ino,
                ty: FileType::Dir,
                name: DirEntryName::DotDot,
            });
        }
        entries.push(DirEntry {
            ino: self.hostname_file.ino,
            ty: FileType::File,
            name: DirEntryName::FileName(FileName::new(b"hostname").unwrap()),
        });
        Ok(entries)
    }

    fn get_node(&self, file_name: &FileName, _ctx: &FileAccessContext) -> Result<Link> {
        let location =
            LinkLocation::new(self.this.upgrade().unwrap(), file_name.clone().into_owned());
        let node: DynINode = match file_name.as_bytes() {
            b"hostname" => self.hostname_file.clone(),
            _ => bail!(NoEnt),
        };
        Ok(Link { location, node })
    }

    fn delete_non_dir(&self, _: FileName<'static>, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn delete_dir(&self, _: FileName<'static>, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn rename(
        &self,
        _oldname: FileName<'static>,
        _check_is_dir: bool,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _no_replace: bool,
        _: &FileAccessContext,
    ) -> Result<()> {
        bail!(Perm)
    }

    fn exchange(
        &self,
        _oldname: FileName<'static>,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _: &FileAccessContext,
    ) -> Result<()> {
        bail!(Perm)
    }

    fn hard_link(
        &self,
        _oldname: FileName<'static>,
        _follow_symlink: bool,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _: &FileAccessContext,
    ) -> Result<Option<Path>> {
        bail!(Perm)
    }
}

pub struct HostnameFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    ino: u64,
    bsd_file_lock_record: LazyBsdFileLockRecord,
    unix_file_lock_record: LazyUnixFileLockRecord,
    watchers: Watchers,
}

impl HostnameFile {
    pub fn new(fs: Arc<ProcFs>) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            fs,
            ino: new_ino(),
            bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            unix_file_lock_record: LazyUnixFileLockRecord::new(),
            watchers: Watchers::new(),
        })
    }

    fn content(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"myhostname\n");
        buffer
    }
}

impl INode for HostnameFile {
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

    fn open(
        &self,
        location: LinkLocation,
        flags: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        open_file(self.this.upgrade().unwrap(), location, flags)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn truncate(&self, _length: usize, _: &FileAccessContext) -> Result<()> {
        bail!(Acces)
    }

    fn bsd_file_lock_record(&self) -> &Arc<BsdFileLockRecord> {
        self.bsd_file_lock_record.get()
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl File for HostnameFile {
    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, offset: usize, buf: &mut dyn ReadBuf, _no_atime: bool) -> Result<usize> {
        let content = self.content();
        let offset = cmp::min(offset, content.len());
        let content = &content[offset..];
        let len = cmp::min(content.len(), buf.buffer_len());
        buf.write(0, &content[..len])?;
        Ok(len)
    }

    fn write(&self, _offset: usize, _buf: &dyn WriteBuf, _: &FileAccessContext) -> Result<usize> {
        bail!(Acces)
    }

    fn append(&self, _buf: &dyn WriteBuf, _: &FileAccessContext) -> Result<(usize, usize)> {
        bail!(Acces)
    }

    fn truncate(&self) -> Result<()> {
        bail!(Acces)
    }

    fn allocate(
        &self,
        _mode: FallocateMode,
        _offset: usize,
        _len: usize,
        _: &FileAccessContext,
    ) -> Result<()> {
        bail!(Acces)
    }

    fn deleted(&self) -> bool {
        false
    }

    fn unix_file_lock_record(&self) -> &Arc<UnixFileLockRecord> {
        self.unix_file_lock_record.get()
    }
}
