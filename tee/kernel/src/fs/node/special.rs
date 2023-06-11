use spin::Mutex;

use super::{new_ino, File, FileSnapshot};
use crate::{
    error::{Error, Result},
    supervisor,
    user::process::syscall::args::{FileMode, FileType, FileTypeAndMode, Stat},
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
    fn stat(&self) -> Stat {
        todo!()
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
    ino: u64,
    internal: Mutex<OutputFileInternal>,
}

struct OutputFileInternal {
    mode: FileMode,
    offset: usize,
}

impl OutputFile {
    pub fn new() -> Self {
        Self {
            ino: new_ino(),
            internal: Mutex::new(OutputFileInternal {
                mode: FileMode::OWNER_ALL,
                offset: 0,
            }),
        }
    }
}

impl File for OutputFile {
    fn stat(&self) -> Stat {
        let guard = self.internal.lock();
        let mode = FileTypeAndMode::new(FileType::File, guard.mode);
        Stat {
            dev: 0,
            ino: self.ino,
            nlink: 0,
            mode,
            uid: 0,
            gid: 0,
            _pad0: 0,
            rdev: 0,
            size: guard.offset as i64,
            blksize: 0,
            blocks: 0,
            atime: 0,
            atime_nsec: 0,
            mtime: 0,
            mtime_nsec: 0,
            ctime: 0,
            ctime_nsec: 0,
            _unused: [0; 3],
        }
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
