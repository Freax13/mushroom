use alloc::sync::Arc;
use spin::Mutex;
use x86_64::VirtAddr;

use crate::{
    error::{Error, Result},
    fs::node::File,
    user::process::{
        memory::{ActiveVirtualMemory, MemoryPermissions},
        syscall::args::{FileMode, Stat, Whence},
    },
};

use super::OpenFileDescription;

/// A file description for files opened as read-only.
pub struct ReadonlyFileFileDescription {
    file: Arc<dyn File>,
    cursor_idx: Mutex<usize>,
}

impl ReadonlyFileFileDescription {
    pub fn new(file: Arc<dyn File>) -> Self {
        Self {
            file,
            cursor_idx: Mutex::new(0),
        }
    }
}

impl OpenFileDescription for ReadonlyFileFileDescription {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut guard = self.cursor_idx.lock();
        let len = self.file.read(*guard, buf)?;
        *guard += len;
        Ok(len)
    }

    fn pread(&self, pos: usize, buf: &mut [u8]) -> Result<usize> {
        self.file.read(pos, buf)
    }

    fn seek(&self, offset: usize, whence: Whence) -> Result<usize> {
        let mut guard = self.cursor_idx.lock();
        match whence {
            Whence::Set => *guard = offset,
            Whence::Cur => {
                *guard = guard
                    .checked_add_signed(offset as isize)
                    .ok_or_else(|| Error::inval(()))?
            }
            Whence::End => todo!(),
            Whence::Data => todo!(),
            Whence::Hole => todo!(),
        }
        Ok(*guard)
    }

    fn set_mode(&self, mode: FileMode) -> Result<()> {
        self.file.set_mode(mode);
        Ok(())
    }

    fn stat(&self) -> Result<Stat> {
        Ok(self.file.stat())
    }

    fn mmap(
        &self,
        vm: &mut ActiveVirtualMemory,
        addr: Option<VirtAddr>,
        offset: u64,
        len: u64,
        permissions: MemoryPermissions,
    ) -> Result<VirtAddr> {
        let snapshot = self.file.read_snapshot()?;
        vm.mmap_into(addr, len, offset, snapshot, permissions)
    }
}

/// A file description for files opened as write-only.
pub struct WriteonlyFileFileDescription {
    file: Arc<dyn File>,
    cursor_idx: Mutex<usize>,
}

impl WriteonlyFileFileDescription {
    pub fn new(file: Arc<dyn File>) -> Self {
        Self {
            file,
            cursor_idx: Mutex::new(0),
        }
    }
}

impl OpenFileDescription for WriteonlyFileFileDescription {
    fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut guard = self.cursor_idx.lock();
        let len = self.file.write(*guard, buf)?;
        *guard += len;
        Ok(len)
    }

    fn pwrite(&self, pos: usize, buf: &[u8]) -> Result<usize> {
        self.file.write(pos, buf)
    }

    fn set_mode(&self, mode: FileMode) -> Result<()> {
        self.file.set_mode(mode);
        Ok(())
    }

    fn stat(&self) -> Result<Stat> {
        Ok(self.file.stat())
    }
}

/// A file description for files opened as read and write.
pub struct ReadWriteFileFileDescription {
    file: Arc<dyn File>,
    cursor_idx: Mutex<usize>,
}

impl ReadWriteFileFileDescription {
    pub fn new(file: Arc<dyn File>) -> Self {
        Self {
            file,
            cursor_idx: Mutex::new(0),
        }
    }
}

impl OpenFileDescription for ReadWriteFileFileDescription {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut guard = self.cursor_idx.lock();
        let len = self.file.read(*guard, buf)?;
        *guard += len;
        Ok(len)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut guard = self.cursor_idx.lock();
        let len = self.file.write(*guard, buf)?;
        *guard += len;
        Ok(len)
    }

    fn pread(&self, pos: usize, buf: &mut [u8]) -> Result<usize> {
        self.file.read(pos, buf)
    }

    fn pwrite(&self, pos: usize, buf: &[u8]) -> Result<usize> {
        self.file.write(pos, buf)
    }

    fn set_mode(&self, mode: FileMode) -> Result<()> {
        self.file.set_mode(mode);
        Ok(())
    }

    fn stat(&self) -> Result<Stat> {
        Ok(self.file.stat())
    }
}
