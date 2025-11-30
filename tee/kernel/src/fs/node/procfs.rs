use alloc::{
    boxed::Box,
    string::ToString,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::{cmp, mem::MaybeUninit};

use async_trait::async_trait;
use constants::{MAX_APS_COUNT, physical_address::DYNAMIC};
use usize_conversions::{FromUsize, usize_from};
use x86_64::VirtAddr;

use crate::{
    error::{ErrorKind, Result, bail, ensure, err},
    fs::{
        FileSystem, StatFs,
        fd::{
            BsdFileLockRecord, FileDescriptor, LazyBsdFileLockRecord, LazyUnixFileLockRecord,
            ReadBuf, StrongFileDescriptor, UnixFileLockRecord, WriteBuf,
            dir::open_dir,
            file::{File, open_file},
            inotify::Watchers,
            unix_socket::StreamUnixSocket,
        },
        node::{
            DirEntry, DirEntryName, DynINode, FileAccessContext, INode, Link, LinkLocation,
            directory::{Directory, dir_impls},
            new_dev, new_ino,
            procfs::sys::{SysDir, kernel::HostnameFile},
        },
        path::{FileName, Path},
    },
    memory::page::KernelPage,
    net::{IpVersion, tcp::NetTcpFile},
    time::now,
    user::{
        memory::WriteToVec,
        process::Process,
        syscall::args::{
            ClockId, FallocateMode, FdNum, FileMode, FileType, FileTypeAndMode, OpenFlags, Stat,
            Timespec, Whence,
        },
        thread::{Gid, Thread, Uid},
    },
};

mod sys;

pub struct ProcFs {
    dev: u64,
}

impl ProcFs {
    pub fn dev(&self) -> u64 {
        self.dev
    }
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

pub fn new(location: LinkLocation) -> Result<Arc<dyn Directory>> {
    let fs = Arc::new(ProcFs { dev: new_dev() });
    Ok(Arc::new_cyclic(|this| ProcFsRoot {
        this: this.clone(),
        fs: fs.clone(),
        ino: new_ino(),
        location,
        bsd_file_lock_record: LazyBsdFileLockRecord::new(),
        watchers: Watchers::new(),
        cpuinfo_file: CpuinfoFile::new(fs.clone()),
        meminfo_file: MeminfoFile::new(fs.clone()),
        net_dir_ino: new_ino(),
        net_dir_bsd_file_lock_record: Arc::new(BsdFileLockRecord::new()),
        net_dir_watchers: Arc::new(Watchers::new()),
        net_dev_file: NetDevFile::new(fs.clone()),
        net_tcp_file: NetTcpFile::new(fs.clone(), IpVersion::V4),
        net_tcp6_file: NetTcpFile::new(fs.clone(), IpVersion::V6),
        self_link: Arc::new(SelfLink {
            parent: this.clone(),
            fs: fs.clone(),
            ino: new_ino(),
            bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            watchers: Watchers::new(),
        }),
        stat_file: StatFile::new(fs.clone()),
        sys_dir_ino: new_ino(),
        sys_dir_bsd_file_lock_record: Arc::new(BsdFileLockRecord::new()),
        sys_dir_watchers: Arc::new(Watchers::new()),
        sys_kernel_dir_ino: new_ino(),
        sys_kernel_dir_bsd_file_lock_record: Arc::new(BsdFileLockRecord::new()),
        sys_kernel_dir_watchers: Arc::new(Watchers::new()),
        sys_kernel_hostname_file: HostnameFile::new(fs.clone()),
        uptime_file: UptimeFile::new(fs),
    }))
}

struct ProcFsRoot {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    ino: u64,
    location: LinkLocation,
    bsd_file_lock_record: LazyBsdFileLockRecord,
    watchers: Watchers,
    cpuinfo_file: Arc<CpuinfoFile>,
    meminfo_file: Arc<MeminfoFile>,
    net_dir_ino: u64,
    net_dir_bsd_file_lock_record: Arc<BsdFileLockRecord>,
    net_dir_watchers: Arc<Watchers>,
    net_dev_file: Arc<NetDevFile>,
    net_tcp_file: Arc<NetTcpFile>,
    net_tcp6_file: Arc<NetTcpFile>,
    self_link: Arc<SelfLink>,
    stat_file: Arc<StatFile>,
    sys_dir_ino: u64,
    sys_dir_bsd_file_lock_record: Arc<BsdFileLockRecord>,
    sys_dir_watchers: Arc<Watchers>,
    sys_kernel_dir_ino: u64,
    sys_kernel_dir_bsd_file_lock_record: Arc<BsdFileLockRecord>,
    sys_kernel_dir_watchers: Arc<Watchers>,
    sys_kernel_hostname_file: Arc<HostnameFile>,
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
        self.bsd_file_lock_record.get()
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl Directory for ProcFsRoot {
    fn location(&self) -> &LinkLocation {
        &self.location
    }

    fn get_node(&self, file_name: &FileName, _ctx: &FileAccessContext) -> Result<Link> {
        let location =
            LinkLocation::new(self.this.upgrade().unwrap(), file_name.clone().into_owned());
        let node: DynINode = match file_name.as_bytes() {
            b"cpuinfo" => self.cpuinfo_file.clone(),
            b"meminfo" => self.meminfo_file.clone(),
            b"net" => NetDir::new(
                location.clone(),
                self.fs.clone(),
                self.net_dir_ino,
                self.net_dir_bsd_file_lock_record.clone(),
                self.net_dir_watchers.clone(),
                self.net_dev_file.clone(),
                self.net_tcp_file.clone(),
                self.net_tcp6_file.clone(),
            ),
            b"self" => self.self_link.clone(),
            b"stat" => self.stat_file.clone(),
            b"sys" => SysDir::new(
                location.clone(),
                self.fs.clone(),
                self.sys_dir_ino,
                self.sys_dir_bsd_file_lock_record.clone(),
                self.sys_dir_watchers.clone(),
                self.sys_kernel_dir_ino,
                self.sys_kernel_dir_bsd_file_lock_record.clone(),
                self.sys_kernel_dir_watchers.clone(),
                self.sys_kernel_hostname_file.clone(),
            ),
            b"uptime" => self.uptime_file.clone(),
            _ => {
                let bytes = file_name.as_bytes();
                let str = core::str::from_utf8(bytes).map_err(|_| err!(NoEnt))?;
                let pid = str.parse().map_err(|_| err!(NoEnt))?;
                let process = Process::find_by_pid(pid).ok_or(err!(NoEnt))?;
                ProcessDir::new(location.clone(), self.fs.clone(), Arc::downgrade(&process))
            }
        };
        Ok(Link { location, node })
    }

    fn create_file(
        &self,
        _: FileName<'static>,
        _: FileMode,
        _: &FileAccessContext,
    ) -> Result<Result<Link, Link>> {
        bail!(NoEnt)
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
        _file_name: FileName<'static>,
        _target: Path,
        _uid: Uid,
        _gid: Gid,
        _create_new: bool,
    ) -> Result<()> {
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
    ) -> Result<()> {
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

    fn bind_socket(
        &self,
        _file_name: FileName<'static>,
        _mode: FileMode,
        _uid: Uid,
        _gid: Gid,
        _: &StreamUnixSocket,
        _socketname: &Path,
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
            ino: self.cpuinfo_file.ino,
            ty: FileType::File,
            name: DirEntryName::FileName(FileName::new(b"cpuinfo").unwrap()),
        });
        entries.push(DirEntry {
            ino: self.meminfo_file.ino,
            ty: FileType::File,
            name: DirEntryName::FileName(FileName::new(b"meminfo").unwrap()),
        });
        entries.push(DirEntry {
            ino: self.net_dir_ino,
            ty: FileType::Dir,
            name: DirEntryName::FileName(FileName::new(b"net").unwrap()),
        });
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
            ino: self.sys_dir_ino,
            ty: FileType::Dir,
            name: DirEntryName::FileName(FileName::new(b"sys").unwrap()),
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

    fn delete_non_dir(&self, _file_name: FileName<'static>, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn delete_dir(&self, _file_name: FileName<'static>, _: &FileAccessContext) -> Result<()> {
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
        bail!(NoEnt)
    }

    fn exchange(
        &self,
        _oldname: FileName<'static>,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _: &FileAccessContext,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn hard_link(
        &self,
        _oldname: FileName<'static>,
        _follow_symlink: bool,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _: &FileAccessContext,
    ) -> Result<Option<Path>> {
        bail!(NoEnt)
    }
}

struct CpuinfoFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    ino: u64,
    bsd_file_lock_record: LazyBsdFileLockRecord,
    unix_file_lock_record: LazyUnixFileLockRecord,
    watchers: Watchers,
}

impl CpuinfoFile {
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

        let features = [
            "fpu",
            "vme",
            "de",
            "pse",
            "tsc",
            "msr",
            "pae",
            "mce",
            "cx8",
            "apic",
            "sep",
            "mtrr",
            "pge",
            "mca",
            "cmov",
            "pat",
            "pse36",
            "clflush",
            "mmx",
            "fxsr",
            "sse",
            "sse2",
            "ht",
            "syscall",
            "nx",
            "pdpe1gb",
            "rdtscp",
            "lm",
            "constant_tsc",
            "rep_good",
            "nopl",
            "xtopology",
            "nonstop_tsc",
            "cpuid",
            "aperfmperf",
            "pni",
            "pclmulqdq",
            "monitor",
            "ssse3",
            "fma",
            "cx16",
            "pcid",
            "sse4_1",
            "sse4_2",
            "movbe",
            "popcnt",
            "aes",
            "xsave",
            "avx",
            "f16c",
            "rdrand",
            "lahf_lm",
            "abm",
            "3dnowprefetch",
            "cat_l3",
            "cdp_l3",
            "ssbd",
            "mba",
            "ibrs",
            "ibpb",
            "stibp",
            "fsgsbase",
            "bmi1",
            "avx2",
            "smep",
            "bmi2",
            "erms",
            "invpcid",
            "cqm",
            "rdt_a",
            "rdseed",
            "adx",
            "smap",
            "clflushopt",
            "clwb",
            "sha_ni",
            "xsaveopt",
            "xsavec",
            "xgetbv1",
            "xsaves",
            "cqm_llc",
            "cqm_occup_llc",
            "cqm_mbm_total",
            "cqm_mbm_local",
            "wbnoinvd",
            "umip",
            "pku",
            "ospke",
            "vaes",
            "vpclmulqdq",
            "rdpid",
        ];

        for i in 0..MAX_APS_COUNT {
            writeln!(buffer, "processor\t: {i}").unwrap();
            writeln!(buffer, "physical id\t: 0").unwrap();
            writeln!(buffer, "siblings\t: {MAX_APS_COUNT}").unwrap();
            writeln!(buffer, "core id\t\t: {i}").unwrap();
            writeln!(buffer, "cpu cores\t: {MAX_APS_COUNT}").unwrap();
            writeln!(buffer, "apicid\t\t: {i}").unwrap();
            writeln!(buffer, "initial apicid\t: {i}").unwrap();
            write!(buffer, "flags\t\t:").unwrap();
            for feature in features {
                write!(buffer, " {feature}").unwrap();
            }
            writeln!(buffer).unwrap();
            writeln!(buffer).unwrap();
        }
        buffer
    }
}

impl INode for CpuinfoFile {
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

impl File for CpuinfoFile {
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

struct MeminfoFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    ino: u64,
    bsd_file_lock_record: LazyBsdFileLockRecord,
    unix_file_lock_record: LazyUnixFileLockRecord,
    watchers: Watchers,
}

impl MeminfoFile {
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
        let total = (DYNAMIC.end.start_address() - DYNAMIC.start.start_address()) / 1024;
        let free = total / 2; // TODO
        let cached = total / 8;

        let mut buffer = Vec::new();
        writeln!(buffer, "MemTotal: {total:14} kB").unwrap();
        writeln!(buffer, "MemFree:  {free:14} kB").unwrap();
        writeln!(buffer, "Cached:   {cached:14} kB").unwrap();
        buffer
    }
}

impl INode for MeminfoFile {
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

impl File for MeminfoFile {
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

struct NetDir {
    this: Weak<Self>,
    location: LinkLocation,
    fs: Arc<ProcFs>,
    ino: u64,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    watchers: Arc<Watchers>,
    net_dev_file: Arc<NetDevFile>,
    net_tcp_file: Arc<NetTcpFile>,
    net_tcp6_file: Arc<NetTcpFile>,
}

impl NetDir {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        location: LinkLocation,
        fs: Arc<ProcFs>,
        ino: u64,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        watchers: Arc<Watchers>,
        net_dev_file: Arc<NetDevFile>,
        net_tcp_file: Arc<NetTcpFile>,
        net_tcp6_file: Arc<NetTcpFile>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            location,
            fs: fs.clone(),
            ino,
            bsd_file_lock_record,
            watchers,
            net_dev_file,
            net_tcp_file,
            net_tcp6_file,
        })
    }
}

impl INode for NetDir {
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

impl Directory for NetDir {
    fn location(&self) -> &LinkLocation {
        &self.location
    }

    fn create_file(
        &self,
        _: FileName<'static>,
        _: FileMode,
        _: &FileAccessContext,
    ) -> Result<Result<Link, Link>> {
        bail!(NoEnt)
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
            ino: self.net_dev_file.ino,
            ty: FileType::File,
            name: DirEntryName::FileName(FileName::new(b"dev").unwrap()),
        });
        entries.push(DirEntry {
            ino: self.net_tcp_file.ino,
            ty: FileType::Link,
            name: DirEntryName::FileName(FileName::new(b"tcp").unwrap()),
        });
        entries.push(DirEntry {
            ino: self.net_tcp6_file.ino,
            ty: FileType::Link,
            name: DirEntryName::FileName(FileName::new(b"tcp6").unwrap()),
        });
        Ok(entries)
    }

    fn get_node(&self, file_name: &FileName, _ctx: &FileAccessContext) -> Result<Link> {
        let location =
            LinkLocation::new(self.this.upgrade().unwrap(), file_name.clone().into_owned());
        let node: DynINode = match file_name.as_bytes() {
            b"dev" => self.net_dev_file.clone(),
            b"tcp" => self.net_tcp_file.clone(),
            b"tcp6" => self.net_tcp6_file.clone(),
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

struct NetDevFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    ino: u64,
    bsd_file_lock_record: LazyBsdFileLockRecord,
    unix_file_lock_record: LazyUnixFileLockRecord,
    watchers: Watchers,
}

impl NetDevFile {
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
        buffer.extend_from_slice(
            b"Inter-|   Receive                                                |  Transmit\n",
        );
        buffer.extend_from_slice(b" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");
        buffer.extend_from_slice(b"    lo: 2512365769 15037767    0    0    0     0          0         0 2512365769 15037767    0    0    0     0       0          0\n");
        buffer
    }
}

impl INode for NetDevFile {
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

impl File for NetDevFile {
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

struct SelfLink {
    parent: Weak<ProcFsRoot>,
    fs: Arc<ProcFs>,
    ino: u64,
    bsd_file_lock_record: LazyBsdFileLockRecord,
    watchers: Watchers,
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

    fn open(
        &self,
        _: LinkLocation,
        _: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
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
            ctx.process()
                .ok_or(err!(Srch))?
                .pid()
                .to_string()
                .into_bytes(),
        )
    }

    fn try_resolve_link(
        &self,
        _start_dir: Link,
        _: LinkLocation,
        ctx: &mut FileAccessContext,
    ) -> Result<Option<Link>> {
        ctx.follow_symlink()?;
        let process = ctx.process().ok_or(err!(Srch))?;
        let file_name = FileName::new(process.pid().to_string().as_bytes())
            .unwrap()
            .into_owned();
        let location = LinkLocation::new(self.parent.upgrade().unwrap(), file_name.clone());
        Ok(Some(Link {
            location: location.clone(),
            node: ProcessDir::new(location, self.fs.clone(), Arc::downgrade(process)),
        }))
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn truncate(&self, _length: usize, _: &FileAccessContext) -> Result<()> {
        bail!(Loop)
    }

    fn bsd_file_lock_record(&self) -> &Arc<BsdFileLockRecord> {
        self.bsd_file_lock_record.get()
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

pub struct ProcessInos {
    root_dir: u64,
    cmdline_file: u64,
    fd_dir: u64,
    fdinfo_dir: u64,
    exe_link: u64,
    maps_file: u64,
    mem_file: u64,
    mountinfo_file: u64,
    root_symlink: u64,
    stat_file: u64,
    status_file: u64,
    task_dir: u64,
}

impl ProcessInos {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            root_dir: new_ino(),
            cmdline_file: new_ino(),
            fd_dir: new_ino(),
            fdinfo_dir: new_ino(),
            exe_link: new_ino(),
            maps_file: new_ino(),
            mem_file: new_ino(),
            mountinfo_file: new_ino(),
            root_symlink: new_ino(),
            stat_file: new_ino(),
            status_file: new_ino(),
            task_dir: new_ino(),
        }
    }
}

struct ProcessDir {
    this: Weak<Self>,
    location: LinkLocation,
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    bsd_file_lock_record: LazyBsdFileLockRecord,
    watchers: Watchers,
    cmdline_bsd_file_lock_record: LazyBsdFileLockRecord,
    cmdline_unix_file_lock_record: LazyUnixFileLockRecord,
    cmdline_file_watchers: Arc<Watchers>,
    fd_dir_bsd_file_lock_record: LazyBsdFileLockRecord,
    fd_dir_file_watchers: Arc<Watchers>,
    fdinfo_dir_bsd_file_lock_record: LazyBsdFileLockRecord,
    fdinfo_dir_file_watchers: Arc<Watchers>,
    exe_link_lock_record: LazyBsdFileLockRecord,
    exe_link_watchers: Arc<Watchers>,
    maps_bsd_file_lock_record: LazyBsdFileLockRecord,
    maps_unix_file_lock_record: LazyUnixFileLockRecord,
    maps_file_watchers: Arc<Watchers>,
    mem_bsd_file_lock_record: LazyBsdFileLockRecord,
    mem_unix_file_lock_record: LazyUnixFileLockRecord,
    mem_file_watchers: Arc<Watchers>,
    mountinfo_bsd_file_lock_record: LazyBsdFileLockRecord,
    mountinfo_unix_file_lock_record: LazyUnixFileLockRecord,
    mountinfo_file_watchers: Arc<Watchers>,
    root_bsd_file_lock_record: LazyBsdFileLockRecord,
    root_file_watchers: Arc<Watchers>,
    stat_bsd_file_lock_record: LazyBsdFileLockRecord,
    stat_unix_file_lock_record: LazyUnixFileLockRecord,
    stat_file_watchers: Arc<Watchers>,
    status_bsd_file_lock_record: LazyBsdFileLockRecord,
    status_unix_file_lock_record: LazyUnixFileLockRecord,
    status_file_watchers: Arc<Watchers>,
    task_dir_bsd_lock_record: LazyBsdFileLockRecord,
    task_dir_watchers: Arc<Watchers>,
}

impl ProcessDir {
    pub fn new(location: LinkLocation, fs: Arc<ProcFs>, process: Weak<Process>) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            location,
            fs,
            process,
            bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            watchers: Watchers::new(),
            cmdline_bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            cmdline_unix_file_lock_record: LazyUnixFileLockRecord::new(),
            cmdline_file_watchers: Arc::new(Watchers::new()),
            fd_dir_bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            fd_dir_file_watchers: Arc::new(Watchers::new()),
            fdinfo_dir_bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            fdinfo_dir_file_watchers: Arc::new(Watchers::new()),
            exe_link_lock_record: LazyBsdFileLockRecord::new(),
            exe_link_watchers: Arc::new(Watchers::new()),
            maps_bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            maps_unix_file_lock_record: LazyUnixFileLockRecord::new(),
            maps_file_watchers: Arc::new(Watchers::new()),
            mem_bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            mem_unix_file_lock_record: LazyUnixFileLockRecord::new(),
            mem_file_watchers: Arc::new(Watchers::new()),
            mountinfo_bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            mountinfo_unix_file_lock_record: LazyUnixFileLockRecord::new(),
            mountinfo_file_watchers: Arc::new(Watchers::new()),
            root_bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            root_file_watchers: Arc::new(Watchers::new()),
            stat_bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            stat_unix_file_lock_record: LazyUnixFileLockRecord::new(),
            stat_file_watchers: Arc::new(Watchers::new()),
            status_bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            status_unix_file_lock_record: LazyUnixFileLockRecord::new(),
            status_file_watchers: Arc::new(Watchers::new()),
            task_dir_bsd_lock_record: LazyBsdFileLockRecord::new(),
            task_dir_watchers: Arc::new(Watchers::new()),
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
        self.bsd_file_lock_record.get()
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl Directory for ProcessDir {
    fn location(&self) -> &LinkLocation {
        &self.location
    }

    fn get_node(&self, file_name: &FileName, _ctx: &FileAccessContext) -> Result<Link> {
        let location =
            LinkLocation::new(self.this.upgrade().unwrap(), file_name.clone().into_owned());
        let node: DynINode = match file_name.as_bytes() {
            b"cmdline" => CmdlineFile::new(
                self.fs.clone(),
                self.process.clone(),
                self.cmdline_bsd_file_lock_record.get().clone(),
                self.cmdline_unix_file_lock_record.get().clone(),
                self.cmdline_file_watchers.clone(),
            ),
            b"fd" => FdDir::new(
                location.clone(),
                self.fs.clone(),
                self.process.clone(),
                self.fd_dir_bsd_file_lock_record.get().clone(),
                self.fd_dir_file_watchers.clone(),
            ),
            b"fdinfo" => FdInfoDir::new(
                location.clone(),
                self.fs.clone(),
                self.process.clone(),
                self.fdinfo_dir_bsd_file_lock_record.get().clone(),
                self.fdinfo_dir_file_watchers.clone(),
            ),
            b"exe" => ExeLink::new(
                self.fs.clone(),
                self.process.clone(),
                self.exe_link_lock_record.get().clone(),
                self.exe_link_watchers.clone(),
            ),
            b"maps" => MapsFile::new(
                self.fs.clone(),
                self.process.clone(),
                self.maps_bsd_file_lock_record.get().clone(),
                self.maps_unix_file_lock_record.get().clone(),
                self.maps_file_watchers.clone(),
            ),
            b"mem" => MemFile::new(
                self.fs.clone(),
                self.process.clone(),
                self.mem_bsd_file_lock_record.get().clone(),
                self.mem_unix_file_lock_record.get().clone(),
                self.mem_file_watchers.clone(),
            ),
            b"mountinfo" => MountInfoFile::new(
                self.fs.clone(),
                self.process.clone(),
                self.mountinfo_bsd_file_lock_record.get().clone(),
                self.mountinfo_unix_file_lock_record.get().clone(),
                self.mountinfo_file_watchers.clone(),
            ),
            b"root" => RootLink::new(
                self.fs.clone(),
                self.process.clone(),
                self.root_bsd_file_lock_record.get().clone(),
                self.root_file_watchers.clone(),
            ),
            b"stat" => ProcessStatFile::new(
                self.fs.clone(),
                self.process.clone(),
                self.stat_bsd_file_lock_record.get().clone(),
                self.stat_unix_file_lock_record.get().clone(),
                self.stat_file_watchers.clone(),
            ),
            b"status" => ProcessStatusFile::new(
                self.fs.clone(),
                self.process.clone(),
                self.status_bsd_file_lock_record.get().clone(),
                self.status_unix_file_lock_record.get().clone(),
                self.status_file_watchers.clone(),
            ),
            b"task" => ProcessTaskDir::new(
                location.clone(),
                self.fs.clone(),
                self.process.clone(),
                self.task_dir_bsd_lock_record.get().clone(),
                self.task_dir_watchers.clone(),
            ),
            _ => bail!(NoEnt),
        };
        Ok(Link { location, node })
    }

    fn create_file(
        &self,
        _: FileName<'static>,
        _: FileMode,
        _: &FileAccessContext,
    ) -> Result<Result<Link, Link>> {
        bail!(NoEnt)
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
        _file_name: FileName<'static>,
        _target: Path,
        _uid: Uid,
        _gid: Gid,
        _create_new: bool,
    ) -> Result<()> {
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
    ) -> Result<()> {
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

    fn bind_socket(
        &self,
        _file_name: FileName<'static>,
        _mode: FileMode,
        _uid: Uid,
        _gid: Gid,
        _: &StreamUnixSocket,
        _socketname: &Path,
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
            ino: process.inos.cmdline_file,
            ty: FileType::File,
            name: DirEntryName::FileName(FileName::new(b"cmdline").unwrap()),
        });
        entries.push(DirEntry {
            ino: process.inos.fd_dir,
            ty: FileType::Dir,
            name: DirEntryName::FileName(FileName::new(b"fd").unwrap()),
        });
        entries.push(DirEntry {
            ino: process.inos.fdinfo_dir,
            ty: FileType::Dir,
            name: DirEntryName::FileName(FileName::new(b"fdinfo").unwrap()),
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
            ino: process.inos.mem_file,
            ty: FileType::File,
            name: DirEntryName::FileName(FileName::new(b"mem").unwrap()),
        });
        entries.push(DirEntry {
            ino: process.inos.mountinfo_file,
            ty: FileType::File,
            name: DirEntryName::FileName(FileName::new(b"mountinfo").unwrap()),
        });
        entries.push(DirEntry {
            ino: process.inos.root_symlink,
            ty: FileType::Link,
            name: DirEntryName::FileName(FileName::new(b"root").unwrap()),
        });
        entries.push(DirEntry {
            ino: process.inos.stat_file,
            ty: FileType::File,
            name: DirEntryName::FileName(FileName::new(b"stat").unwrap()),
        });
        entries.push(DirEntry {
            ino: process.inos.status_file,
            ty: FileType::File,
            name: DirEntryName::FileName(FileName::new(b"status").unwrap()),
        });
        entries.push(DirEntry {
            ino: process.inos.task_dir,
            ty: FileType::Dir,
            name: DirEntryName::FileName(FileName::new(b"task").unwrap()),
        });
        Ok(entries)
    }

    fn delete_non_dir(&self, _file_name: FileName<'static>, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn delete_dir(&self, _file_name: FileName<'static>, _: &FileAccessContext) -> Result<()> {
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
        bail!(NoEnt)
    }

    fn exchange(
        &self,
        _oldname: FileName<'static>,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _: &FileAccessContext,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn hard_link(
        &self,
        _oldname: FileName<'static>,
        _follow_symlink: bool,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _: &FileAccessContext,
    ) -> Result<Option<Path>> {
        bail!(NoEnt)
    }
}

struct CmdlineFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    unix_file_lock_record: Arc<UnixFileLockRecord>,
    watchers: Arc<Watchers>,
}

impl CmdlineFile {
    pub fn new(
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        unix_file_lock_record: Arc<UnixFileLockRecord>,
        watchers: Arc<Watchers>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            fs,
            process,
            bsd_file_lock_record,
            unix_file_lock_record,
            watchers,
        })
    }
}

impl INode for CmdlineFile {
    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let size = process
            .mm_arg_end()
            .as_u64()
            .saturating_sub(process.mm_arg_start().as_u64()) as i64;
        Ok(Stat {
            dev: self.fs.dev,
            ino: process.inos.cmdline_file,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::File, FileMode::from_bits_retain(0o444)),
            uid: Uid::SUPER_USER,
            gid: Gid::SUPER_USER,
            rdev: 0,
            size,
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

    fn truncate(&self, _length: usize, _: &FileAccessContext) -> Result<()> {
        bail!(Acces)
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn bsd_file_lock_record(&self) -> &Arc<BsdFileLockRecord> {
        &self.bsd_file_lock_record
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl File for CmdlineFile {
    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, offset: usize, buf: &mut dyn ReadBuf, _no_atime: bool) -> Result<usize> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let virtual_memory = thread.lock().virtual_memory().clone();

        // Add the arg start to the offset.
        let Some(offset) = offset.checked_add(usize_from(process.mm_arg_start().as_u64())) else {
            return Ok(0);
        };
        // Clamp the len to the arg end.
        let len = usize_from(process.mm_arg_end().as_u64()).saturating_sub(offset);
        let len = cmp::min(buf.buffer_len(), len);

        let mut buffer = MaybeUninit::<[u8; 4096]>::uninit();
        let buffer = buffer.as_bytes_mut();
        for i in (0..len).step_by(buffer.len()) {
            let chunk_len = cmp::min(buffer.len(), len - i);
            let buffer = &mut buffer[..chunk_len];
            let addr = VirtAddr::try_new(u64::from_usize(offset + i))?;
            let buffer = virtual_memory.read_uninit_bytes(addr, buffer)?;
            buf.write(i, buffer)?;
        }
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
        &self.unix_file_lock_record
    }
}

struct FdDir {
    this: Weak<Self>,
    location: LinkLocation,
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    watchers: Arc<Watchers>,
}

impl FdDir {
    pub fn new(
        location: LinkLocation,
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        watchers: Arc<Watchers>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            location,
            fs,
            process,
            bsd_file_lock_record,
            watchers,
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

impl Directory for FdDir {
    fn location(&self) -> &LinkLocation {
        &self.location
    }

    fn get_node(&self, name: &FileName, _ctx: &FileAccessContext) -> Result<Link> {
        let file_name = name.as_bytes();
        let file_name = core::str::from_utf8(file_name).map_err(|_| err!(NoEnt))?;
        let fd_num = file_name.parse().map_err(|_| err!(NoEnt))?;
        let fd_num = FdNum::new(fd_num);

        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let guard = process.credentials.read();
        let uid = guard.real_user_id;
        let gid = guard.real_group_id;
        drop(guard);

        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let fdtable = thread.fdtable.lock();
        let node = fdtable.get_node(self.fs.clone(), fd_num, uid, gid)?;
        Ok(Link {
            location: LinkLocation::new(self.this.upgrade().unwrap(), name.clone().into_owned()),
            node,
        })
    }

    fn create_file(
        &self,
        _: FileName<'static>,
        _: FileMode,
        _: &FileAccessContext,
    ) -> Result<Result<Link, Link>> {
        bail!(NoEnt)
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
        _file_name: FileName<'static>,
        _target: Path,
        _uid: Uid,
        _gid: Gid,
        _create_new: bool,
    ) -> Result<()> {
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
    ) -> Result<()> {
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

    fn bind_socket(
        &self,
        _file_name: FileName<'static>,
        _mode: FileMode,
        _uid: Uid,
        _gid: Gid,
        _: &StreamUnixSocket,
        _socketname: &Path,
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

    fn delete_non_dir(&self, _file_name: FileName<'static>, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn delete_dir(&self, _file_name: FileName<'static>, _: &FileAccessContext) -> Result<()> {
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
        bail!(NoEnt)
    }

    fn exchange(
        &self,
        _oldname: FileName<'static>,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _: &FileAccessContext,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn hard_link(
        &self,
        oldname: FileName<'static>,
        follow_symlink: bool,
        new_dir: DynINode,
        newname: FileName<'static>,
        ctx: &FileAccessContext,
    ) -> Result<Option<Path>> {
        ensure!(follow_symlink, Loop);

        let file_name = oldname.as_bytes();
        let file_name = core::str::from_utf8(file_name).map_err(|_| err!(NoEnt))?;
        let fd_num = file_name.parse().map_err(|_| err!(NoEnt))?;
        let fd_num = FdNum::new(fd_num);

        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let guard = thread.fdtable.lock();
        let fd = guard.get(fd_num)?;
        drop(guard);

        fd.link_into(new_dir, newname, ctx)?;
        Ok(None)
    }
}

#[derive(Clone)]
pub struct FdINode {
    fs: Arc<ProcFs>,
    ino: u64,
    uid: Uid,
    gid: Gid,
    fd: FileDescriptor,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    watchers: Arc<Watchers>,
}

impl FdINode {
    pub fn new(
        fs: Arc<ProcFs>,
        ino: u64,
        uid: Uid,
        gid: Gid,
        fd: FileDescriptor,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        watchers: Arc<Watchers>,
    ) -> Self {
        Self {
            fs,
            ino,
            uid,
            gid,
            fd,
            bsd_file_lock_record,
            watchers,
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

    fn open(
        &self,
        _: LinkLocation,
        _: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
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

    fn truncate(&self, _length: usize, _: &FileAccessContext) -> Result<()> {
        bail!(Loop)
    }

    fn read_link(&self, _ctx: &FileAccessContext) -> Result<Path> {
        self.fd.path()
    }

    fn try_resolve_link(
        &self,
        _start_dir: Link,
        location: LinkLocation,
        ctx: &mut FileAccessContext,
    ) -> Result<Option<Link>> {
        ctx.follow_symlink()?;
        let location = if let Some(link) = self.fd.path_fd_link() {
            link.location.clone()
        } else {
            location
        };
        Ok(Some(Link {
            location,
            node: Arc::new(FollowedFdINode {
                fd: self.fd.clone(),
                bsd_file_lock_record: self.bsd_file_lock_record.clone(),
                watchers: self.watchers.clone(),
            }),
        }))
    }

    fn bsd_file_lock_record(&self) -> &Arc<BsdFileLockRecord> {
        &self.bsd_file_lock_record
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

/// This is the INode that's returned after following the link at an fd inode.
struct FollowedFdINode {
    fd: FileDescriptor,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    watchers: Arc<Watchers>,
}

#[async_trait]
impl INode for FollowedFdINode {
    fn stat(&self) -> Result<Stat> {
        if let Some(link) = self.fd.path_fd_link() {
            // Special case for path fds: Forward the stat call to the pointed
            // to link.
            link.node.stat()
        } else {
            self.fd.stat()
        }
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        if let Some(link) = self.fd.path_fd_link() {
            // Special case for path fds: Forward the open call to the pointed
            // to link.
            link.node.fs()
        } else {
            self.fd.fs()
        }
    }

    fn open(
        &self,
        _: LinkLocation,
        flags: OpenFlags,
        ctx: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        if let Some(link) = self.fd.path_fd_link() {
            // Special case for path fds: Forward the open call to the pointed
            // to link.
            link.node.open(link.location.clone(), flags, ctx)
        } else {
            FileDescriptor::upgrade(&self.fd).ok_or(err!(BadF))
        }
    }

    async fn async_open(
        self: Arc<Self>,
        _: LinkLocation,
        flags: OpenFlags,
        ctx: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        if let Some(link) = self.fd.path_fd_link() {
            // Special case for path fds: Forward the open call to the pointed
            // to link.
            link.node
                .clone()
                .async_open(link.location.clone(), flags, ctx)
                .await
        } else {
            FileDescriptor::upgrade(&self.fd).ok_or(err!(BadF))
        }
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        if let Some(link) = self.fd.path_fd_link() {
            // Special case for path fds: Forward the chmod call to the pointed
            // to link, but rewrite ELOOP to EOPNOTSUPP.
            link.node.chmod(mode, ctx).map_err(|err| {
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
        if let Some(link) = self.fd.path_fd_link() {
            // Special case for path fds: Forward the chown call to the pointed
            // to link.
            link.node.chown(uid, gid, ctx)
        } else {
            self.fd.chown(uid, gid, ctx)
        }
    }

    fn update_times(&self, ctime: Timespec, mtime: Option<Timespec>, atime: Option<Timespec>) {
        if let Some(link) = self.fd.path_fd_link() {
            // Special case for path fds: Forward the call to the pointed to
            // link.
            link.node.update_times(ctime, mtime, atime);
        } else {
            self.fd.update_times(ctime, mtime, atime);
        }
    }

    fn truncate(&self, length: usize, ctx: &FileAccessContext) -> Result<()> {
        if let Some(link) = self.fd.path_fd_link() {
            // Special case for path fds: Forward the call to the pointed to
            // link.
            link.node.truncate(length, ctx)
        } else {
            self.fd.truncate(length, ctx)
        }
    }

    fn bsd_file_lock_record(&self) -> &Arc<BsdFileLockRecord> {
        &self.bsd_file_lock_record
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

struct FdInfoDir {
    this: Weak<Self>,
    location: LinkLocation,
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    watchers: Arc<Watchers>,
}

impl FdInfoDir {
    pub fn new(
        location: LinkLocation,
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        watchers: Arc<Watchers>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            location,
            fs,
            process,
            bsd_file_lock_record,
            watchers,
        })
    }
}

impl INode for FdInfoDir {
    dir_impls!();

    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.fs.dev,
            ino: process.inos.fdinfo_dir,
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

impl Directory for FdInfoDir {
    fn location(&self) -> &LinkLocation {
        &self.location
    }

    fn get_node(&self, name: &FileName, _ctx: &FileAccessContext) -> Result<Link> {
        let file_name = name.as_bytes();
        let file_name = core::str::from_utf8(file_name).map_err(|_| err!(NoEnt))?;
        let fd_num = file_name.parse().map_err(|_| err!(NoEnt))?;
        let fd_num = FdNum::new(fd_num);

        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let guard = process.credentials.read();
        let uid = guard.real_user_id;
        let gid = guard.real_group_id;
        drop(guard);

        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let fdtable = thread.fdtable.lock();
        let node = fdtable.get_info_node(self.fs.clone(), fd_num, uid, gid)?;
        Ok(Link {
            location: LinkLocation::new(self.this.upgrade().unwrap(), name.clone().into_owned()),
            node,
        })
    }

    fn create_file(
        &self,
        _: FileName<'static>,
        _: FileMode,
        _: &FileAccessContext,
    ) -> Result<Result<Link, Link>> {
        bail!(NoEnt)
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
        _file_name: FileName<'static>,
        _target: Path,
        _uid: Uid,
        _gid: Gid,
        _create_new: bool,
    ) -> Result<()> {
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
    ) -> Result<()> {
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

    fn bind_socket(
        &self,
        _file_name: FileName<'static>,
        _mode: FileMode,
        _uid: Uid,
        _gid: Gid,
        _: &StreamUnixSocket,
        _socketname: &Path,
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
        Ok(fdtable.list_fdinfo_entries())
    }

    fn delete_non_dir(&self, _file_name: FileName<'static>, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn delete_dir(&self, _file_name: FileName<'static>, _: &FileAccessContext) -> Result<()> {
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
        bail!(NoEnt)
    }

    fn exchange(
        &self,
        _oldname: FileName<'static>,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _: &FileAccessContext,
    ) -> Result<()> {
        bail!(NoEnt)
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

#[derive(Clone)]
pub struct FdInfoFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    ino: u64,
    uid: Uid,
    gid: Gid,
    fd: FileDescriptor,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    unix_file_lock_record: Arc<UnixFileLockRecord>,
    watchers: Arc<Watchers>,
}

impl FdInfoFile {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        fs: Arc<ProcFs>,
        ino: u64,
        uid: Uid,
        gid: Gid,
        fd: FileDescriptor,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        unix_file_lock_record: Arc<UnixFileLockRecord>,
        watchers: Arc<Watchers>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            fs,
            ino,
            uid,
            gid,
            fd,
            bsd_file_lock_record,
            unix_file_lock_record,
            watchers,
        })
    }

    fn content(&self) -> Result<Vec<u8>> {
        let pos = self
            .fd
            .seek(0, Whence::Cur, &mut FileAccessContext::root())
            .unwrap_or(0);
        let flags = self.fd.flags();
        let mnt_id = 1; // TODO
        let ino = self.fd.stat()?.ino;

        let mut content = Vec::new();
        writeln!(content, "pos:\t{pos}").unwrap();
        writeln!(content, "flags:\t{flags:07o}").unwrap();
        writeln!(content, "mnt_id:\t{mnt_id}").unwrap();
        writeln!(content, "ino:\t{ino}").unwrap();
        Ok(content)
    }
}

impl INode for FdInfoFile {
    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: self.fs.dev,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::File, FileMode::from_bits_truncate(0o444)),
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

    fn truncate(&self, _length: usize, _: &FileAccessContext) -> Result<()> {
        bail!(Acces)
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn bsd_file_lock_record(&self) -> &Arc<BsdFileLockRecord> {
        &self.bsd_file_lock_record
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl File for FdInfoFile {
    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, offset: usize, buf: &mut dyn ReadBuf, _no_atime: bool) -> Result<usize> {
        let maps = self.content()?;
        let offset = cmp::min(offset, maps.len());
        let maps = &maps[offset..];
        let len = cmp::min(maps.len(), buf.buffer_len());
        buf.write(0, &maps[..len])?;
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
        &self.unix_file_lock_record
    }
}

struct ExeLink {
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    watchers: Arc<Watchers>,
}

impl ExeLink {
    pub fn new(
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        watchers: Arc<Watchers>,
    ) -> Arc<Self> {
        Arc::new(Self {
            fs,
            process,
            bsd_file_lock_record,
            watchers,
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

    fn open(
        &self,
        _: LinkLocation,
        _: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        bail!(Loop)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn truncate(&self, _length: usize, _: &FileAccessContext) -> Result<()> {
        bail!(Loop)
    }

    fn read_link(&self, _ctx: &FileAccessContext) -> Result<Path> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let exe = process.exe();
        exe.location.path()
    }

    fn try_resolve_link(
        &self,
        _start_dir: Link,
        _: LinkLocation,
        ctx: &mut FileAccessContext,
    ) -> Result<Option<Link>> {
        ctx.follow_symlink()?;
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Some(process.exe()))
    }

    fn bsd_file_lock_record(&self) -> &Arc<BsdFileLockRecord> {
        &self.bsd_file_lock_record
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

struct MapsFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    unix_file_lock_record: Arc<UnixFileLockRecord>,
    watchers: Arc<Watchers>,
}

impl MapsFile {
    pub fn new(
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        unix_file_lock_record: Arc<UnixFileLockRecord>,
        watchers: Arc<Watchers>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            fs,
            process,
            bsd_file_lock_record,
            unix_file_lock_record,
            watchers,
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

    fn truncate(&self, _length: usize, _: &FileAccessContext) -> Result<()> {
        bail!(Acces)
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn bsd_file_lock_record(&self) -> &Arc<BsdFileLockRecord> {
        &self.bsd_file_lock_record
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl File for MapsFile {
    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, offset: usize, buf: &mut dyn ReadBuf, _no_atime: bool) -> Result<usize> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let maps = thread.lock().virtual_memory().maps();
        let offset = cmp::min(offset, maps.len());
        let maps = &maps[offset..];
        let len = cmp::min(maps.len(), buf.buffer_len());
        buf.write(0, &maps[..len])?;
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
        &self.unix_file_lock_record
    }
}

struct MemFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    unix_file_lock_record: Arc<UnixFileLockRecord>,
    watchers: Arc<Watchers>,
}

impl MemFile {
    pub fn new(
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        unix_file_lock_record: Arc<UnixFileLockRecord>,
        watchers: Arc<Watchers>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            fs,
            process,
            bsd_file_lock_record,
            unix_file_lock_record,
            watchers,
        })
    }
}

impl INode for MemFile {
    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.fs.dev,
            ino: process.inos.mem_file,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::File, FileMode::from_bits_retain(0o666)),
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

    fn truncate(&self, _length: usize, _: &FileAccessContext) -> Result<()> {
        bail!(Acces)
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn bsd_file_lock_record(&self) -> &Arc<BsdFileLockRecord> {
        &self.bsd_file_lock_record
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl File for MemFile {
    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, offset: usize, buf: &mut dyn ReadBuf, _no_atime: bool) -> Result<usize> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let virtual_memory = thread.lock().virtual_memory().clone();

        let mut buffer = MaybeUninit::<[u8; 4096]>::uninit();
        let buffer = buffer.as_bytes_mut();
        let len = buf.buffer_len();
        for i in (0..len).step_by(buffer.len()) {
            let chunk_len = cmp::min(buffer.len(), len - i);
            let buffer = &mut buffer[..chunk_len];
            let addr = VirtAddr::try_new(u64::from_usize(offset + i))?;
            let buffer = virtual_memory.read_uninit_bytes(addr, buffer)?;
            buf.write(i, buffer)?;
        }
        Ok(len)
    }

    fn write(&self, offset: usize, buf: &dyn WriteBuf, _: &FileAccessContext) -> Result<usize> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let virtual_memory = thread.lock().virtual_memory().clone();

        let mut buffer = [0; 4096];
        let len = buf.buffer_len();
        for i in (0..len).step_by(buffer.len()) {
            let chunk_len = cmp::min(buffer.len(), len - i);
            let buffer = &mut buffer[..chunk_len];
            buf.read(i, buffer)?;
            let addr = VirtAddr::try_new(u64::from_usize(offset + i))?;
            virtual_memory.write_bytes(addr, buffer)?;
        }
        Ok(len)
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
        &self.unix_file_lock_record
    }
}

struct MountInfoFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    unix_file_lock_record: Arc<UnixFileLockRecord>,
    watchers: Arc<Watchers>,
}

impl MountInfoFile {
    pub fn new(
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        unix_file_lock_record: Arc<UnixFileLockRecord>,
        watchers: Arc<Watchers>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            fs,
            process,
            bsd_file_lock_record,
            unix_file_lock_record,
            watchers,
        })
    }

    fn content(&self) -> Vec<u8> {
        let mut content = Vec::new();
        writeln!(
            content,
            "3 2 0:1 / /dev rw,relatime shared:1 - devtmpfs devtmpfs rw,size=1609224k,nr_inodes=4019697,mode=755"
        ).unwrap();
        writeln!(
            content,
            "2 1 0:2 / / rw,relatime shared:1 - tmpfs tmpfs rw,size=1609224k,nr_inodes=4019697,mode=755"
        ).unwrap();
        content
    }
}

impl INode for MountInfoFile {
    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.fs.dev,
            ino: process.inos.mountinfo_file,
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

    fn truncate(&self, _length: usize, _: &FileAccessContext) -> Result<()> {
        bail!(Acces)
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn bsd_file_lock_record(&self) -> &Arc<BsdFileLockRecord> {
        &self.bsd_file_lock_record
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl File for MountInfoFile {
    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, offset: usize, buf: &mut dyn ReadBuf, _no_atime: bool) -> Result<usize> {
        let maps = self.content();
        let offset = cmp::min(offset, maps.len());
        let maps = &maps[offset..];
        let len = cmp::min(maps.len(), buf.buffer_len());
        buf.write(0, &maps[..len])?;
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
        &self.unix_file_lock_record
    }
}

struct RootLink {
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    watchers: Arc<Watchers>,
}

impl RootLink {
    pub fn new(
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        watchers: Arc<Watchers>,
    ) -> Arc<Self> {
        Arc::new(Self {
            fs,
            process,
            bsd_file_lock_record,
            watchers,
        })
    }
}

impl INode for RootLink {
    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.fs.dev,
            ino: process.inos.root_symlink,
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

    fn open(
        &self,
        _: LinkLocation,
        _: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        bail!(Loop)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn read_link(&self, _: &FileAccessContext) -> Result<Path> {
        Ok(Path::root())
    }

    fn try_resolve_link(
        &self,
        _start_dir: Link,
        _: LinkLocation,
        ctx: &mut FileAccessContext,
    ) -> Result<Option<Link>> {
        ctx.follow_symlink()?;
        Ok(Some(Link::root()))
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn truncate(&self, _length: usize, _: &FileAccessContext) -> Result<()> {
        bail!(Loop)
    }

    fn bsd_file_lock_record(&self) -> &Arc<BsdFileLockRecord> {
        &self.bsd_file_lock_record
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

struct ProcessStatFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    unix_file_lock_record: Arc<UnixFileLockRecord>,
    watchers: Arc<Watchers>,
}

impl ProcessStatFile {
    pub fn new(
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        unix_file_lock_record: Arc<UnixFileLockRecord>,
        watchers: Arc<Watchers>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            fs,
            process,
            bsd_file_lock_record,
            unix_file_lock_record,
            watchers,
        })
    }
}

impl INode for ProcessStatFile {
    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.fs.dev,
            ino: process.inos.stat_file,
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
        &self.bsd_file_lock_record
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl File for ProcessStatFile {
    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, offset: usize, buf: &mut dyn ReadBuf, _no_atime: bool) -> Result<usize> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let stat = thread.lock().stat();
        let offset = cmp::min(offset, stat.len());
        let stat = &stat[offset..];
        let len = cmp::min(stat.len(), buf.buffer_len());
        buf.write(0, &stat[..len])?;
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
        &self.unix_file_lock_record
    }
}

struct ProcessStatusFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    unix_file_lock_record: Arc<UnixFileLockRecord>,
    watchers: Arc<Watchers>,
}

impl ProcessStatusFile {
    pub fn new(
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        unix_file_lock_record: Arc<UnixFileLockRecord>,
        watchers: Arc<Watchers>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            fs,
            process,
            bsd_file_lock_record,
            unix_file_lock_record,
            watchers,
        })
    }
}

impl INode for ProcessStatusFile {
    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.fs.dev,
            ino: process.inos.status_file,
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
        &self.bsd_file_lock_record
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl File for ProcessStatusFile {
    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, offset: usize, buf: &mut dyn ReadBuf, _no_atime: bool) -> Result<usize> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let thread = process.thread_group_leader().upgrade().ok_or(err!(Srch))?;
        let stat = thread.lock().status();
        let offset = cmp::min(offset, stat.len());
        let stat = &stat[offset..];
        let len = cmp::min(stat.len(), buf.buffer_len());
        buf.write(0, &stat[..len])?;
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
        &self.unix_file_lock_record
    }
}

pub struct ThreadInos {
    root_dir: u64,
    comm_file: u64,
}

impl ThreadInos {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            root_dir: new_ino(),
            comm_file: new_ino(),
        }
    }
}

struct ProcessTaskDir {
    this: Weak<Self>,
    location: LinkLocation,
    fs: Arc<ProcFs>,
    process: Weak<Process>,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    watchers: Arc<Watchers>,
}

impl ProcessTaskDir {
    pub fn new(
        location: LinkLocation,
        fs: Arc<ProcFs>,
        process: Weak<Process>,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        watchers: Arc<Watchers>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            location,
            fs,
            process,
            bsd_file_lock_record,
            watchers,
        })
    }
}

impl INode for ProcessTaskDir {
    dir_impls!();

    fn stat(&self) -> Result<Stat> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.fs.dev,
            ino: process.inos.task_dir,
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

impl Directory for ProcessTaskDir {
    fn location(&self) -> &LinkLocation {
        &self.location
    }

    fn create_file(
        &self,
        _: FileName<'static>,
        _: FileMode,
        _: &FileAccessContext,
    ) -> Result<Result<Link, Link>> {
        bail!(NoEnt)
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
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let mut entries = vec![DirEntry {
            ino: process.inos.task_dir,
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
        for thread in process.threads() {
            entries.push(DirEntry {
                ino: thread.inos.root_dir,
                ty: FileType::Dir,
                name: DirEntryName::FileName(
                    FileName::new(thread.tid().to_string().as_bytes())
                        .unwrap()
                        .into_owned(),
                ),
            });
        }
        Ok(entries)
    }

    fn get_node(&self, file_name: &FileName, _: &FileAccessContext) -> Result<Link> {
        let process = self.process.upgrade().ok_or(err!(Srch))?;
        let tid = core::str::from_utf8(file_name.as_bytes()).map_err(|_| err!(NoEnt))?;
        let tid = tid.parse::<u32>().map_err(|_| err!(NoEnt))?;
        let thread = process
            .threads()
            .into_iter()
            .find(|t| t.tid() == tid)
            .ok_or(err!(NoEnt))?;
        let location =
            LinkLocation::new(self.this.upgrade().unwrap(), file_name.clone().into_owned());
        let node = TaskDir::new(location.clone(), self.fs.clone(), Arc::downgrade(&thread));
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

struct TaskDir {
    this: Weak<Self>,
    location: LinkLocation,
    fs: Arc<ProcFs>,
    thread: Weak<Thread>,
    bsd_file_lock_record: LazyBsdFileLockRecord,
    watchers: Watchers,
    comm_bsd_file_lock_record: LazyBsdFileLockRecord,
    comm_unix_file_lock_record: LazyUnixFileLockRecord,
    comm_file_watchers: Arc<Watchers>,
}

impl TaskDir {
    pub fn new(location: LinkLocation, fs: Arc<ProcFs>, thread: Weak<Thread>) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            location,
            fs,
            thread,
            bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            watchers: Watchers::new(),
            comm_bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            comm_unix_file_lock_record: LazyUnixFileLockRecord::new(),
            comm_file_watchers: Arc::new(Watchers::new()),
        })
    }
}

impl INode for TaskDir {
    dir_impls!();

    fn stat(&self) -> Result<Stat> {
        let threads = self.thread.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.fs.dev,
            ino: threads.inos.root_dir,
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
        self.bsd_file_lock_record.get()
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl Directory for TaskDir {
    fn location(&self) -> &LinkLocation {
        &self.location
    }

    fn get_node(&self, file_name: &FileName, _ctx: &FileAccessContext) -> Result<Link> {
        let location =
            LinkLocation::new(self.this.upgrade().unwrap(), file_name.clone().into_owned());
        let node: DynINode = match file_name.as_bytes() {
            b"comm" => TaskCommFile::new(
                self.fs.clone(),
                self.thread.clone(),
                self.comm_bsd_file_lock_record.get().clone(),
                self.comm_unix_file_lock_record.get().clone(),
                self.comm_file_watchers.clone(),
            ),
            _ => bail!(NoEnt),
        };
        Ok(Link { location, node })
    }

    fn create_file(
        &self,
        _: FileName<'static>,
        _: FileMode,
        _: &FileAccessContext,
    ) -> Result<Result<Link, Link>> {
        bail!(NoEnt)
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
        _file_name: FileName<'static>,
        _target: Path,
        _uid: Uid,
        _gid: Gid,
        _create_new: bool,
    ) -> Result<()> {
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
    ) -> Result<()> {
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

    fn bind_socket(
        &self,
        _file_name: FileName<'static>,
        _mode: FileMode,
        _uid: Uid,
        _gid: Gid,
        _: &StreamUnixSocket,
        _socketname: &Path,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn is_empty(&self) -> bool {
        false
    }

    fn list_entries(&self, _ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
        let process = self.thread.upgrade().ok_or(err!(Srch))?;
        let mut entries = vec![DirEntry {
            ino: process.inos.root_dir,
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
            ino: process.inos.comm_file,
            ty: FileType::File,
            name: DirEntryName::FileName(FileName::new(b"comm").unwrap()),
        });
        Ok(entries)
    }

    fn delete_non_dir(&self, _file_name: FileName<'static>, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn delete_dir(&self, _file_name: FileName<'static>, _: &FileAccessContext) -> Result<()> {
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
        bail!(NoEnt)
    }

    fn exchange(
        &self,
        _oldname: FileName<'static>,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _: &FileAccessContext,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn hard_link(
        &self,
        _oldname: FileName<'static>,
        _follow_symlink: bool,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _: &FileAccessContext,
    ) -> Result<Option<Path>> {
        bail!(NoEnt)
    }
}

struct TaskCommFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    thread: Weak<Thread>,
    bsd_file_lock_record: Arc<BsdFileLockRecord>,
    unix_file_lock_record: Arc<UnixFileLockRecord>,
    watchers: Arc<Watchers>,
}

impl TaskCommFile {
    pub fn new(
        fs: Arc<ProcFs>,
        thread: Weak<Thread>,
        bsd_file_lock_record: Arc<BsdFileLockRecord>,
        unix_file_lock_record: Arc<UnixFileLockRecord>,
        watchers: Arc<Watchers>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            fs,
            thread,
            bsd_file_lock_record,
            unix_file_lock_record,
            watchers,
        })
    }

    fn content(&self) -> Result<Vec<u8>> {
        let thread = self.thread.upgrade().ok_or(err!(Srch))?;
        Ok(thread.lock().task_comm().to_vec())
    }
}

impl INode for TaskCommFile {
    fn stat(&self) -> Result<Stat> {
        let thread = self.thread.upgrade().ok_or(err!(Srch))?;
        Ok(Stat {
            dev: self.fs.dev,
            ino: thread.inos.comm_file,
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
        &self.bsd_file_lock_record
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl File for TaskCommFile {
    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, offset: usize, buf: &mut dyn ReadBuf, _no_atime: bool) -> Result<usize> {
        let content = self.content()?;
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
        &self.unix_file_lock_record
    }
}

struct StatFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    ino: u64,
    bsd_file_lock_record: LazyBsdFileLockRecord,
    unix_file_lock_record: LazyUnixFileLockRecord,
    watchers: Watchers,
}

impl StatFile {
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
        buffer.extend_from_slice(b"intr 4 2 1 1\n");
        buffer.extend_from_slice(b"ctxt 1477882447\n");
        buffer.extend_from_slice(b"btime 1147679732\n");
        buffer.extend_from_slice(b"softirq 4 2 1 1\n");

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

impl File for StatFile {
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

struct UptimeFile {
    this: Weak<Self>,
    fs: Arc<ProcFs>,
    ino: u64,
    bsd_file_lock_record: LazyBsdFileLockRecord,
    unix_file_lock_record: LazyUnixFileLockRecord,
    watchers: Watchers,
}

impl UptimeFile {
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

impl File for UptimeFile {
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
