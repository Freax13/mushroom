use super::{File, FileSnapshot};
use crate::error::Result;

pub struct NullFile;

impl File for NullFile {
    fn is_executable(&self) -> bool {
        false
    }

    fn read(&self, _offset: usize, _buf: &mut [u8]) -> Result<usize> {
        Ok(0)
    }

    fn write(&self, _offset: usize, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn read_snapshot(&self) -> Result<FileSnapshot> {
        Ok(FileSnapshot::empty())
    }
}
