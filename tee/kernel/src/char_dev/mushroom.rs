use core::cmp;

use alloc::sync::Arc;
use kernel_macros::register;
use usize_conversions::FromUsize;

use crate::{
    error::{bail, Result},
    fs::{
        fd::{
            stream_buffer, Events, FileLock, LazyFileLockRecord, OpenFileDescription, PipeBlocked,
        },
        node::FileAccessContext,
        path::Path,
        FileSystem,
    },
    supervisor,
    user::process::{
        memory::VirtualMemory,
        syscall::args::{FileMode, OpenFlags, Pointer, Stat},
        thread::{Gid, Uid},
    },
};

use super::CharDev;

const MAJOR: u16 = 0xf00;

pub struct Output {
    path: Path,
    flags: OpenFlags,
    stat: Stat,
    fs: Arc<dyn FileSystem>,
    file_lock: FileLock,
}

#[register]
impl CharDev for Output {
    const MAJOR: u16 = MAJOR;
    const MINOR: u8 = 0;

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

impl OpenFileDescription for Output {
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

    fn poll_ready(&self, events: Events) -> Events {
        events & Events::WRITE
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        supervisor::update_output(buf);
        Ok(buf.len())
    }

    fn write_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let mut addr = pointer.get();
        let mut remaining_len = len;
        while remaining_len > 0 {
            let buffer_len = cmp::min(remaining_len, supervisor::OUTPUT_BUFFER_CAPACITY);
            let mut buf = [0; supervisor::OUTPUT_BUFFER_CAPACITY];
            let buf = &mut buf[..buffer_len];

            vm.read_bytes(addr, buf)?;

            supervisor::update_output(buf);

            addr += u64::from_usize(buf.len());
            remaining_len -= buf.len();
        }

        Ok(len)
    }

    fn splice_from(
        &self,
        read_half: &stream_buffer::ReadHalf,
        _offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        read_half.splice_to(len, |buffer, len| {
            let (slice1, slice2) = buffer.as_slices();
            let len1 = cmp::min(len, slice1.len());
            let len2 = len - len1;
            let slice1 = &slice1[..len1];
            let slice2 = &slice2[..len2];
            supervisor::update_output(slice1);
            supervisor::update_output(slice2);

            buffer.drain(..len);
        })
    }

    fn splice_to(
        &self,
        _write_half: &stream_buffer::WriteHalf,
        _offset: Option<usize>,
        _len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        bail!(BadF)
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(self.fs.clone())
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}
