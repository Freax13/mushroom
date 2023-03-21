use alloc::sync::Arc;
use spin::Mutex;

use crate::{error::Result, fs::node::File};

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
}
