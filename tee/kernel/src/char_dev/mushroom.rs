use core::cmp;

use kernel_macros::register;
use usize_conversions::FromUsize;

use crate::{
    error::Result,
    fs::{
        fd::{Events, FileLock, LazyFileLockRecord, OpenFileDescription},
        node::FileAccessContext,
        path::Path,
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
    file_lock: FileLock,
}

#[register]
impl CharDev for Output {
    const MAJOR: u16 = MAJOR;
    const MINOR: u8 = 0;

    fn new(path: Path, flags: OpenFlags, stat: Stat) -> Result<Self> {
        static RECORD: LazyFileLockRecord = LazyFileLockRecord::new();
        Ok(Self {
            path,
            flags,
            stat,
            file_lock: FileLock::new(RECORD.get().clone()),
        })
    }
}

impl OpenFileDescription for Output {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Path {
        self.path.clone()
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
        supervisor::output(buf);
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
            let buffer_len = cmp::min(remaining_len, 0x1000);
            let mut buf = [0; 0x1000];
            let buf = &mut buf[..buffer_len];

            vm.read_bytes(addr, buf)?;

            supervisor::output(buf);

            addr += u64::from_usize(buf.len());
            remaining_len -= buf.len();
        }

        Ok(len)
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}
