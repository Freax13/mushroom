use spin::Mutex;

use super::{File, FileSnapshot};
use crate::{
    error::{Error, Result},
    supervisor,
    user::process::syscall::args::FileMode,
};

pub struct NullFile {
    mode: FileMode,
}

impl NullFile {
    pub fn new() -> Self {
        Self {
            mode: FileMode::from_bits_truncate(0o666),
        }
    }
}

impl File for NullFile {
    fn mode(&self) -> FileMode {
        self.mode
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
    mode: FileMode,
    offset: Mutex<usize>,
}

impl OutputFile {
    pub fn new() -> Self {
        Self {
            mode: FileMode::OWNER_ALL,
            offset: Mutex::new(0),
        }
    }
}

impl File for OutputFile {
    fn mode(&self) -> FileMode {
        self.mode
    }

    fn read(&self, _offset: usize, _buf: &mut [u8]) -> Result<usize> {
        Err(Error::inval(()))
    }

    fn write(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        let mut guard = self.offset.lock();

        // Make sure that writes always append.
        if *guard != offset {
            return Err(Error::inval(()));
        }

        supervisor::output(buf);
        *guard += buf.len();

        Ok(buf.len())
    }

    fn read_snapshot(&self) -> Result<FileSnapshot> {
        Err(Error::inval(()))
    }
}
