use spin::Mutex;

use super::{File, FileSnapshot};
use crate::{
    error::{Error, Result},
    supervisor,
    user::process::syscall::args::FileMode,
};

pub struct NullFile {
    mode: Mutex<FileMode>,
}

impl NullFile {
    pub fn new() -> Self {
        Self {
            mode: Mutex::new(FileMode::from_bits_truncate(0o666)),
        }
    }
}

impl File for NullFile {
    fn mode(&self) -> FileMode {
        *self.mode.lock()
    }

    fn set_mode(&self, mode: FileMode) {
        *self.mode.lock() = mode;
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
    internal: Mutex<OutputFileInternal>,
}

struct OutputFileInternal {
    mode: FileMode,
    offset: usize,
}

impl OutputFile {
    pub fn new() -> Self {
        Self {
            internal: Mutex::new(OutputFileInternal {
                mode: FileMode::OWNER_ALL,
                offset: 0,
            }),
        }
    }
}

impl File for OutputFile {
    fn mode(&self) -> FileMode {
        self.internal.lock().mode
    }

    fn set_mode(&self, mode: FileMode) {
        self.internal.lock().mode = mode;
    }

    fn read(&self, _offset: usize, _buf: &mut [u8]) -> Result<usize> {
        Err(Error::inval(()))
    }

    fn write(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        let mut guard = self.internal.lock();

        // Make sure that writes always append.
        if guard.offset != offset {
            return Err(Error::inval(()));
        }

        supervisor::output(buf);
        guard.offset += buf.len();

        Ok(buf.len())
    }

    fn read_snapshot(&self) -> Result<FileSnapshot> {
        Err(Error::inval(()))
    }
}
