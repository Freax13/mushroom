use core::{cmp, iter::from_fn};

use crate::{
    error::{bail, ensure},
    fs::fd::{
        dir::MountLocation,
        file::{open_file, File},
        FileDescriptor,
    },
    memory::page::KernelPage,
    spin::{lazy::Lazy, mutex::Mutex},
    user::process::syscall::args::OpenFlags,
};
use alloc::sync::{Arc, Weak};
use usize_conversions::FromUsize;
use x86_64::instructions::random::RdRand;

use crate::{
    error::Result,
    fs::{path::FileName, INPUT},
    supervisor,
    user::process::{
        memory::VirtualMemory,
        syscall::args::{FileMode, FileType, FileTypeAndMode, Pointer, Stat, Timespec},
    },
};

use super::{
    fdfs, new_ino,
    tmpfs::{TmpFsDir, TmpFsFile},
    DynINode, INode,
};

pub fn new(location: MountLocation) -> Result<DynINode> {
    let tmp_fs_dir = TmpFsDir::new(location, FileMode::from_bits_truncate(0o755));

    let input_name = FileName::new(b"input").unwrap();
    let input_file = TmpFsFile::new(FileMode::from_bits_truncate(0o444));
    input_file.write(0, *INPUT)?;
    tmp_fs_dir.mount(input_name, input_file)?;

    let output_name = FileName::new(b"output").unwrap();
    let output_file = OutputFile::new();
    tmp_fs_dir.mount(output_name, output_file)?;

    let null_name = FileName::new(b"null").unwrap();
    let null_file = NullFile::new();
    tmp_fs_dir.mount(null_name, null_file)?;

    let random_file = RandomFile::new();
    let random_name = FileName::new(b"random").unwrap();
    tmp_fs_dir.mount(random_name, random_file.clone())?;
    let urandom_name = FileName::new(b"urandom").unwrap();
    tmp_fs_dir.mount(urandom_name, random_file)?;

    let fd_name = FileName::new(b"fd").unwrap();
    let fd = fdfs::new(
        MountLocation::new(Arc::downgrade(&tmp_fs_dir) as _, fd_name.clone()),
        FileMode::from_bits_truncate(0o777),
    );
    tmp_fs_dir.mount(fd_name, fd)?;

    Ok(tmp_fs_dir)
}

struct NullFile {
    ino: u64,
    this: Weak<Self>,
    mode: Mutex<FileMode>,
}

impl NullFile {
    fn new() -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            ino: new_ino(),
            this: this.clone(),
            mode: Mutex::new(FileMode::from_bits_truncate(0o666)),
        })
    }
}

impl INode for NullFile {
    fn stat(&self) -> Stat {
        Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Char, *self.mode.lock()),
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
        open_file(self.this.upgrade().unwrap(), flags)
    }

    fn set_mode(&self, mode: FileMode) {
        *self.mode.lock() = mode;
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}
}

impl File for NullFile {
    fn get_page(&self, _: usize) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, _offset: usize, _buf: &mut [u8], _no_atime: bool) -> Result<usize> {
        Ok(0)
    }

    fn read_to_user(
        &self,
        _offset: usize,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        _len: usize,
        _no_atime: bool,
    ) -> Result<usize> {
        Ok(0)
    }

    fn write(&self, _offset: usize, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn write_from_user(
        &self,
        _offset: usize,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        Ok(len)
    }

    fn append(&self, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn append_from_user(&self, _vm: &VirtualMemory, _: Pointer<[u8]>, len: usize) -> Result<usize> {
        Ok(len)
    }

    fn truncate(&self, _len: usize) -> Result<()> {
        Ok(())
    }
}

struct OutputFile {
    ino: u64,
    this: Weak<Self>,
    internal: Mutex<OutputFileInternal>,
}

struct OutputFileInternal {
    mode: FileMode,
    offset: usize,
}

impl OutputFile {
    fn new() -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            ino: new_ino(),
            this: this.clone(),
            internal: Mutex::new(OutputFileInternal {
                mode: FileMode::OWNER_ALL,
                offset: 0,
            }),
        })
    }
}

impl INode for OutputFile {
    fn stat(&self) -> Stat {
        let guard = self.internal.lock();
        let mode = FileTypeAndMode::new(FileType::Char, guard.mode);
        Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: guard.offset as i64,
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

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}
}

impl File for OutputFile {
    fn get_page(&self, _: usize) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, _offset: usize, _buf: &mut [u8], _no_atime: bool) -> Result<usize> {
        bail!(Inval)
    }

    fn write(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        let mut guard = self.internal.lock();

        // Make sure that writes always append.
        ensure!(guard.offset == offset, Inval);

        supervisor::output(buf);
        guard.offset += buf.len();

        Ok(buf.len())
    }

    fn write_from_user(
        &self,
        offset: usize,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let mut guard = self.internal.lock();

        // Make sure that writes always append.
        ensure!(guard.offset == offset, Inval);

        let mut addr = pointer.get();
        let mut remaining_len = len;
        while remaining_len > 0 {
            let buffer_len = cmp::min(remaining_len, 0x1000);
            let mut buf = [0; 0x1000];
            let buf = &mut buf[..buffer_len];

            vm.read_bytes(addr, buf)?;

            supervisor::output(buf);
            guard.offset += buf.len();

            addr += u64::from_usize(buf.len());
            remaining_len -= buf.len();
        }

        Ok(len)
    }

    fn append(&self, buf: &[u8]) -> Result<usize> {
        let mut guard = self.internal.lock();

        supervisor::output(buf);
        guard.offset += buf.len();

        Ok(buf.len())
    }

    fn truncate(&self, len: usize) -> Result<()> {
        let guard = self.internal.lock();
        ensure!(guard.offset == len, Io);
        Ok(())
    }
}

pub struct RandomFile {
    ino: u64,
    this: Weak<Self>,
    internal: Mutex<RandomFileInternal>,
}

struct RandomFileInternal {
    mode: FileMode,
}

impl RandomFile {
    fn new() -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            ino: new_ino(),
            this: this.clone(),
            internal: Mutex::new(RandomFileInternal {
                mode: FileMode::from_bits_truncate(0o666),
            }),
        })
    }

    pub fn random_bytes() -> impl Iterator<Item = u8> {
        static RD_RAND: Lazy<RdRand> = Lazy::new(|| RdRand::new().unwrap());
        from_fn(|| RD_RAND.get_u64()).flat_map(u64::to_ne_bytes)
    }
}

impl INode for RandomFile {
    fn stat(&self) -> Stat {
        let guard = self.internal.lock();
        let mode = FileTypeAndMode::new(FileType::Char, guard.mode);
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
        open_file(self.this.upgrade().unwrap(), flags)
    }

    fn set_mode(&self, mode: FileMode) {
        self.internal.lock().mode = mode;
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}
}

impl File for RandomFile {
    fn get_page(&self, _: usize) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn read(&self, _offset: usize, buf: &mut [u8], _no_atime: bool) -> Result<usize> {
        let mut len = 0;
        for (buf, random) in buf.iter_mut().zip(Self::random_bytes()) {
            *buf = random;
            len += 1;
        }

        Ok(len)
    }

    fn write(&self, _offset: usize, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn write_from_user(
        &self,
        _offset: usize,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        Ok(len)
    }

    fn append(&self, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn append_from_user(
        &self,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        Ok(len)
    }

    fn truncate(&self, _len: usize) -> Result<()> {
        Ok(())
    }
}
