use core::iter::{from_fn, repeat_n};

use alloc::sync::Arc;
use kernel_macros::register;
use x86_64::instructions::random::RdRand;

use crate::{
    error::{Result, bail},
    fs::{
        FileSystem,
        fd::{
            Events, FileLock, LazyFileLockRecord, OpenFileDescription, PipeBlocked, ReadBuf,
            WriteBuf, stream_buffer,
        },
        node::FileAccessContext,
        path::Path,
    },
    memory::page::KernelPage,
    spin::lazy::Lazy,
    user::process::{
        syscall::args::{FileMode, OpenFlags, Stat},
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

    fn read(&self, _buf: &mut dyn ReadBuf) -> Result<usize> {
        Ok(0)
    }

    fn pread(&self, _pos: usize, _buf: &mut dyn ReadBuf) -> Result<usize> {
        Ok(0)
    }

    fn write(&self, buf: &dyn WriteBuf) -> Result<usize> {
        Ok(buf.buffer_len())
    }

    fn pwrite(&self, _pos: usize, buf: &dyn WriteBuf) -> Result<usize> {
        Ok(buf.buffer_len())
    }

    fn splice_from(
        &self,
        read_half: &stream_buffer::ReadHalf,
        _offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        read_half.splice_to(len, |buffer, len| {
            buffer.drain(..len);
        })
    }

    fn splice_to(
        &self,
        _write_half: &stream_buffer::WriteHalf,
        _offset: Option<usize>,
        _len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        Ok(Ok(0))
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        Ok(())
    }

    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
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

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        buf.fill(0)?;
        Ok(buf.buffer_len())
    }

    fn pread(&self, _pos: usize, buf: &mut dyn ReadBuf) -> Result<usize> {
        buf.fill(0)?;
        Ok(buf.buffer_len())
    }

    fn write(&self, buf: &dyn WriteBuf) -> Result<usize> {
        Ok(buf.buffer_len())
    }

    fn pwrite(&self, _pos: usize, buf: &dyn WriteBuf) -> Result<usize> {
        Ok(buf.buffer_len())
    }

    fn splice_from(
        &self,
        read_half: &stream_buffer::ReadHalf,
        _offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        read_half.splice_to(len, |buffer, len| {
            buffer.drain(..len);
        })
    }

    fn splice_to(
        &self,
        write_half: &stream_buffer::WriteHalf,
        _offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        write_half.splice_from(len, |buffer, len| {
            buffer.extend(repeat_n(0, len));
        })
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        Ok(())
    }

    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
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

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        let len = buf.buffer_len();
        for (offset, random) in (0..len).zip(random_bytes()) {
            buf.write(offset, &[random])?;
        }
        Ok(len)
    }

    fn write(&self, buf: &dyn WriteBuf) -> Result<usize> {
        Ok(buf.buffer_len())
    }

    fn splice_from(
        &self,
        read_half: &stream_buffer::ReadHalf,
        _offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        read_half.splice_to(len, |buffer, len| {
            buffer.drain(..len);
        })
    }

    fn splice_to(
        &self,
        write_half: &stream_buffer::WriteHalf,
        _offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        write_half.splice_from(len, |buffer, len| {
            buffer.extend(random_bytes().take(len));
        })
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        Ok(())
    }

    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
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

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        let len = buf.buffer_len();
        for (offset, random) in (0..len).zip(random_bytes()) {
            buf.write(offset, &[random])?;
        }
        Ok(len)
    }

    fn write(&self, buf: &dyn WriteBuf) -> Result<usize> {
        Ok(buf.buffer_len())
    }

    fn splice_from(
        &self,
        read_half: &stream_buffer::ReadHalf,
        _offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        read_half.splice_to(len, |buffer, len| {
            buffer.drain(..len);
        })
    }

    fn splice_to(
        &self,
        write_half: &stream_buffer::WriteHalf,
        _offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        write_half.splice_from(len, |buffer, len| {
            buffer.extend(random_bytes().take(len));
        })
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        Ok(())
    }

    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}
