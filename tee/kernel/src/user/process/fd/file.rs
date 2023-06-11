use alloc::sync::Arc;
use spin::Mutex;

use crate::{
    error::{Error, Result},
    fs::node::File,
    user::process::syscall::args::{FileMode, Stat, Whence},
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

    fn set_mode(&self, mode: FileMode) -> Result<()> {
        self.file.set_mode(mode);
        Ok(())
    }

    fn stat(&self) -> Result<Stat> {
        Ok(self.file.stat())
    }
}
