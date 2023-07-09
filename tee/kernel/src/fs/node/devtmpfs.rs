use core::iter::from_fn;

use alloc::sync::Arc;
use spin::{Lazy, Mutex};
use x86_64::instructions::random::RdRand;

use crate::{
    error::{Error, Result},
    fs::{path::FileName, INPUT},
    supervisor,
    user::process::syscall::args::{FileMode, FileType, FileTypeAndMode, Stat},
};

use super::{
    new_ino,
    tmpfs::{TmpFsDir, TmpFsFile},
    Directory, File, FileSnapshot, Node,
};

pub fn new() -> Result<impl Directory> {
    let tmp_fs_dir = TmpFsDir::new(FileMode::from_bits_truncate(0o755));

    let input_name = FileName::new(b"input").unwrap();
    let input_file = TmpFsFile::new(FileMode::from_bits_truncate(0o444), *INPUT);
    tmp_fs_dir.mount(input_name, Node::File(Arc::new(input_file)))?;

    let output_name = FileName::new(b"output").unwrap();
    let output_file = OutputFile::new();
    tmp_fs_dir.mount(output_name, Node::File(Arc::new(output_file)))?;

    let null_name = FileName::new(b"null").unwrap();
    let null_file = NullFile::new();
    tmp_fs_dir.mount(null_name, Node::File(Arc::new(null_file)))?;

    let random_file = RandomFile::new();
    let random_file = Arc::new(random_file);
    let random_name = FileName::new(b"random").unwrap();
    tmp_fs_dir.mount(random_name, Node::File(random_file.clone()))?;
    let urandom_name = FileName::new(b"urandom").unwrap();
    tmp_fs_dir.mount(urandom_name, Node::File(random_file))?;

    Ok(tmp_fs_dir)
}

struct NullFile {
    mode: Mutex<FileMode>,
}

impl NullFile {
    fn new() -> Self {
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

struct OutputFile {
    ino: u64,
    internal: Mutex<OutputFileInternal>,
}

struct OutputFileInternal {
    mode: FileMode,
    offset: usize,
}

impl OutputFile {
    fn new() -> Self {
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

struct RandomFile {
    ino: u64,
    internal: Mutex<RandomFileInternal>,
}

struct RandomFileInternal {
    mode: FileMode,
}

impl RandomFile {
    fn new() -> Self {
        Self {
            ino: new_ino(),
            internal: Mutex::new(RandomFileInternal {
                mode: FileMode::from_bits_truncate(0o666),
            }),
        }
    }
}

impl File for RandomFile {
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
            size: 0,
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

    fn read(&self, _offset: usize, buf: &mut [u8]) -> Result<usize> {
        static RD_RAND: Lazy<RdRand> = Lazy::new(|| RdRand::new().unwrap());

        let random_bytes = from_fn(|| RD_RAND.get_u64()).flat_map(u64::to_ne_bytes);

        let mut len = 0;
        for (buf, random) in buf.iter_mut().zip(random_bytes) {
            *buf = random;
            len += 1;
        }

        Ok(len)
    }

    fn write(&self, _offset: usize, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn read_snapshot(&self) -> Result<FileSnapshot> {
        Err(Error::inval(()))
    }
}
