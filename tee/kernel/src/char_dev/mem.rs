use core::iter::from_fn;

use alloc::sync::Arc;
use kernel_macros::register;
use usize_conversions::FromUsize;
use x86_64::instructions::random::RdRand;

use crate::{
    error::{bail, Result},
    fs::{
        fd::{Events, FileLock, LazyFileLockRecord, OpenFileDescription},
        node::FileAccessContext,
        path::Path,
        FileSystem,
    },
    memory::page::KernelPage,
    spin::lazy::Lazy,
    user::process::{
        memory::VirtualMemory,
        syscall::args::{FileMode, OpenFlags, Pointer, Stat},
        thread::{Gid, Uid},
    },
};

use super::CharDev;

const MAJOR: u16 = 1;

pub struct Null {
    path: Path,
    flags: OpenFlags,
    stat: Stat,
    fs: Arc<dyn FileSystem>,
    file_lock: FileLock,
}

#[register]
impl CharDev for Null {
    const MAJOR: u16 = MAJOR;
    const MINOR: u8 = 3;

    fn new(path: Path, flags: OpenFlags, stat: Stat, fs: Arc<dyn FileSystem>) -> Result<Self> {
        static RECORD: LazyFileLockRecord = LazyFileLockRecord::new();
        Ok(Self {
            path,
            flags,
            stat,
            fs,
            file_lock: FileLock::new(RECORD.get().clone()),
        })
    }
}

impl OpenFileDescription for Null {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Result<Path> {
        Ok(self.path.clone())
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn stat(&self) -> Result<Stat> {
        Ok(self.stat)
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(self.fs.clone())
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & (Events::READ | Events::WRITE)
    }

    fn read(&self, _buf: &mut [u8]) -> Result<usize> {
        Ok(0)
    }

    fn read_to_user(
        &self,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        _len: usize,
    ) -> Result<usize> {
        Ok(0)
    }

    fn pread(&self, _pos: usize, _buf: &mut [u8]) -> Result<usize> {
        Ok(0)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn write_from_user(
        &self,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        len: usize,
    ) -> crate::error::Result<usize> {
        Ok(len)
    }

    fn pwrite(&self, _pos: usize, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        Ok(())
    }

    fn get_page(&self, _page_idx: usize) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

pub struct Zero {
    path: Path,
    flags: OpenFlags,
    stat: Stat,
    fs: Arc<dyn FileSystem>,
    file_lock: FileLock,
}

#[register]
impl CharDev for Zero {
    const MAJOR: u16 = MAJOR;
    const MINOR: u8 = 5;

    fn new(path: Path, flags: OpenFlags, stat: Stat, fs: Arc<dyn FileSystem>) -> Result<Self> {
        static RECORD: LazyFileLockRecord = LazyFileLockRecord::new();
        Ok(Self {
            path,
            flags,
            stat,
            fs,
            file_lock: FileLock::new(RECORD.get().clone()),
        })
    }
}

impl OpenFileDescription for Zero {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Result<Path> {
        Ok(self.path.clone())
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn stat(&self) -> Result<Stat> {
        Ok(self.stat)
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(self.fs.clone())
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & (Events::READ | Events::WRITE)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        buf.fill(0);
        Ok(buf.len())
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        for i in 0..len {
            vm.write(pointer.cast::<u8>().bytes_offset(i), 0u8)?;
        }
        Ok(len)
    }

    fn pread(&self, _pos: usize, buf: &mut [u8]) -> Result<usize> {
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn write_from_user(
        &self,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        len: usize,
    ) -> crate::error::Result<usize> {
        Ok(len)
    }

    fn pwrite(&self, _pos: usize, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        Ok(())
    }

    fn get_page(&self, _page_idx: usize) -> Result<KernelPage> {
        Ok(KernelPage::zeroed())
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

pub fn random_bytes() -> impl Iterator<Item = u8> {
    static RD_RAND: Lazy<RdRand> = Lazy::new(|| RdRand::new().unwrap());
    from_fn(|| RD_RAND.get_u64()).flat_map(u64::to_ne_bytes)
}

pub struct Random {
    path: Path,
    flags: OpenFlags,
    stat: Stat,
    fs: Arc<dyn FileSystem>,
    file_lock: FileLock,
}

#[register]
impl CharDev for Random {
    const MAJOR: u16 = MAJOR;
    const MINOR: u8 = 8;

    fn new(path: Path, flags: OpenFlags, stat: Stat, fs: Arc<dyn FileSystem>) -> Result<Self> {
        static RECORD: LazyFileLockRecord = LazyFileLockRecord::new();
        Ok(Self {
            path,
            flags,
            stat,
            fs,
            file_lock: FileLock::new(RECORD.get().clone()),
        })
    }
}

impl OpenFileDescription for Random {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Result<Path> {
        Ok(self.path.clone())
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn stat(&self) -> Result<Stat> {
        Ok(self.stat)
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(self.fs.clone())
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & (Events::READ | Events::WRITE)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut len = 0;
        for (buf, random) in buf.iter_mut().zip(random_bytes()) {
            *buf = random;
            len += 1;
        }
        Ok(len)
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        for (offset, b) in (0..len).zip(random_bytes()) {
            vm.write_bytes(pointer.get() + u64::from_usize(offset), &[b])?;
        }
        Ok(len)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn write_from_user(
        &self,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        len: usize,
    ) -> crate::error::Result<usize> {
        Ok(len)
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        Ok(())
    }

    fn get_page(&self, _page_idx: usize) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

pub struct URandom {
    path: Path,
    flags: OpenFlags,
    stat: Stat,
    fs: Arc<dyn FileSystem>,
    file_lock: FileLock,
}

#[register]
impl CharDev for URandom {
    const MAJOR: u16 = MAJOR;
    const MINOR: u8 = 9;

    fn new(path: Path, flags: OpenFlags, stat: Stat, fs: Arc<dyn FileSystem>) -> Result<Self> {
        static RECORD: LazyFileLockRecord = LazyFileLockRecord::new();
        Ok(Self {
            path,
            flags,
            stat,
            fs,
            file_lock: FileLock::new(RECORD.get().clone()),
        })
    }
}

impl OpenFileDescription for URandom {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Result<Path> {
        Ok(self.path.clone())
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn stat(&self) -> Result<Stat> {
        Ok(self.stat)
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(self.fs.clone())
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & (Events::READ | Events::WRITE)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut len = 0;
        for (buf, random) in buf.iter_mut().zip(random_bytes()) {
            *buf = random;
            len += 1;
        }
        Ok(len)
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        for (offset, b) in (0..len).zip(random_bytes()) {
            vm.write_bytes(pointer.get() + u64::from_usize(offset), &[b])?;
        }
        Ok(len)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn write_from_user(
        &self,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        len: usize,
    ) -> crate::error::Result<usize> {
        Ok(len)
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        Ok(())
    }

    fn get_page(&self, _page_idx: usize) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}
