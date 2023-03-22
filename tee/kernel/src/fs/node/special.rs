use spin::Mutex;

use super::{File, FileSnapshot};
use crate::{
    error::{Error, Result},
    supervisor,
};

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

pub struct OutputFile {
    offset: Mutex<usize>,
}

impl OutputFile {
    pub fn new() -> Self {
        Self {
            offset: Mutex::new(0),
        }
    }
}

impl File for OutputFile {
    fn is_executable(&self) -> bool {
        false
    }

    fn read(&self, _offset: usize, _buf: &mut [u8]) -> Result<usize> {
        Err(Error::Inval)
    }

    fn write(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        let mut guard = self.offset.lock();

        // Make sure that writes always append.
        if *guard != offset {
            return Err(Error::Inval);
        }

        supervisor::output(buf);
        *guard += buf.len();

        Ok(buf.len())
    }

    fn read_snapshot(&self) -> Result<FileSnapshot> {
        Err(Error::Inval)
    }
}
