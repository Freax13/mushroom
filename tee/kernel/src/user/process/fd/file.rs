use alloc::sync::Arc;
use spin::Mutex;

use crate::{
    error::{Error, Result},
    fs::node::File,
    user::process::syscall::args::Whence,
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
            Whence::Cur => *guard = guard.checked_add(offset).ok_or_else(|| Error::inval(()))?,
            Whence::End => todo!(),
            Whence::Data => todo!(),
            Whence::Hole => todo!(),
        }
        Ok(*guard)
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
}
