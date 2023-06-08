use core::{
    ops::Deref,
    sync::atomic::{AtomicI32, Ordering},
};

use alloc::{collections::BTreeMap, sync::Arc};
use spin::Mutex;

use crate::error::{Error, Result};

use super::syscall::args::{FdNum, FileMode, Stat, Whence};

pub mod file;
pub mod pipe;
mod std;

#[derive(Clone)]
pub struct FileDescriptor(Arc<dyn OpenFileDescription>);

impl<T> From<T> for FileDescriptor
where
    T: OpenFileDescription,
{
    fn from(value: T) -> Self {
        FileDescriptor(Arc::new(value))
    }
}

impl Deref for FileDescriptor {
    type Target = dyn OpenFileDescription;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

pub struct FileDescriptorTable {
    fd_counter: AtomicI32,
    table: Mutex<BTreeMap<i32, FileDescriptor>>,
}

impl FileDescriptorTable {
    pub fn new() -> Self {
        let this = Self {
            fd_counter: AtomicI32::new(0),
            table: Mutex::new(BTreeMap::new()),
        };

        let stdin = this.insert(std::Stdin);
        assert_eq!(stdin.get(), 0);
        let stdout = this.insert(std::Stdout);
        assert_eq!(stdout.get(), 1);
        let stderr = this.insert(std::Stderr);
        assert_eq!(stderr.get(), 2);

        this
    }

    pub fn insert(&self, fd: impl Into<FileDescriptor>) -> FdNum {
        let fd_num = self.fd_counter.fetch_add(1, Ordering::SeqCst);
        assert!(fd_num >= 0);

        self.table.lock().insert(fd_num, fd.into());

        FdNum::new(fd_num)
    }

    pub fn replace(&self, fd_num: FdNum, fd: impl Into<FileDescriptor>) {
        let mut guard = self.table.lock();
        guard.insert(fd_num.get(), fd.into());
    }

    pub fn get(&self, fd_num: FdNum) -> Result<FileDescriptor> {
        self.table
            .lock()
            .get(&fd_num.get())
            .cloned()
            .ok_or(Error::bad_f(()))
    }

    pub fn close(&self, fd_num: FdNum) -> Result<()> {
        let fd = self
            .table
            .lock()
            .remove(&fd_num.get())
            .ok_or(Error::bad_f(()))?;
        fd.close()
    }
}

impl Clone for FileDescriptorTable {
    fn clone(&self) -> Self {
        // Copy the table.
        let table = self.table.lock().clone();

        // Read the counter. We intentionally do this after copying the table.
        let fd_counter = self.fd_counter.load(Ordering::SeqCst);

        Self {
            fd_counter: AtomicI32::new(fd_counter),
            table: Mutex::new(table),
        }
    }
}

pub trait OpenFileDescription: Send + Sync + 'static {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let _ = buf;
        Err(Error::inval(()))
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let _ = buf;
        Err(Error::inval(()))
    }

    fn seek(&self, offset: usize, whence: Whence) -> Result<usize> {
        let _ = offset;
        let _ = whence;
        Err(Error::inval(()))
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }

    fn write_all(&self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            let len = self.write(buf)?;
            buf = &buf[len..];
        }
        Ok(())
    }

    fn set_mode(&self, mode: FileMode) -> Result<()> {
        let _ = mode;
        Err(Error::io(()))
    }

    fn stat(&self) -> Result<Stat> {
        Err(Error::io(()))
    }
}
