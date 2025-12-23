use alloc::{
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};

use crate::{
    error::{Result, bail},
    fs::{
        FileSystem,
        fd::{
            BsdFileLockRecord, StrongFileDescriptor, dir::open_dir, inotify::Watchers,
            unix_socket::StreamUnixSocket,
        },
        node::{
            DirEntry, DirEntryName, DynINode, FileAccessContext, INode, Link, LinkLocation,
            directory::{Directory, dir_impls},
            procfs::{
                ProcFs,
                sys::kernel::{HostnameFile, KernelDir},
            },
        },
        path::{FileName, Path},
    },
    user::{
        syscall::args::{FileMode, FileType, FileTypeAndMode, OpenFlags, Stat, Timespec},
        thread::{Gid, Uid},
    },
};

pub mod kernel;

pub struct SysDir {
    this: Weak<Self>,
    location: LinkLocation,
    fs: Arc<ProcFs>,
    ino: u64,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    watchers: Arc<Watchers>,
    kernel_dir_ino: u64,
    kernel_dir_bsd_file_lock_record: Arc<BsdFileLockRecord>,
    kernel_dir_watchers: Arc<Watchers>,
    kernel_hostname_file: Arc<HostnameFile>,
}

impl SysDir {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        location: LinkLocation,
        fs: Arc<ProcFs>,
        ino: u64,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        watchers: Arc<Watchers>,
        kernel_dir_ino: u64,
        kernel_dir_bsd_file_lock_record: Arc<BsdFileLockRecord>,
        kernel_dir_watchers: Arc<Watchers>,
        kernel_hostname_file: Arc<HostnameFile>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            location,
            fs: fs.clone(),
            ino,
            bsd_file_lock_record,
            watchers,
            kernel_dir_ino,
            kernel_dir_bsd_file_lock_record,
            kernel_dir_watchers,
            kernel_hostname_file,
        })
    }
}

impl INode for SysDir {
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

impl Directory for SysDir {
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
            ino: self.kernel_dir_ino,
            ty: FileType::Dir,
            name: DirEntryName::FileName(FileName::new(b"kernel").unwrap()),
        });
        Ok(entries)
    }

    fn get_node(&self, file_name: &FileName, _ctx: &FileAccessContext) -> Result<Link> {
        let location =
            LinkLocation::new(self.this.upgrade().unwrap(), file_name.clone().into_owned());
        let node: DynINode = match file_name.as_bytes() {
            b"kernel" => KernelDir::new(
                location.clone(),
                self.fs.clone(),
                self.kernel_dir_ino,
                self.kernel_dir_bsd_file_lock_record.clone(),
                self.kernel_dir_watchers.clone(),
                self.kernel_hostname_file.clone(),
            ),
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
