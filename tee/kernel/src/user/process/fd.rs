use core::{cmp, ops::Deref};

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use spin::Mutex;
use x86_64::VirtAddr;

use crate::{
    error::{Error, Result},
    fs::node::{DirEntry, Directory},
};

use super::{
    memory::{ActiveVirtualMemory, MemoryPermissions},
    syscall::args::{FdNum, FileMode, Stat, Whence},
};

pub mod dir;
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
    table: Mutex<BTreeMap<i32, FileDescriptor>>,
}

impl FileDescriptorTable {
    pub const fn empty() -> Self {
        Self {
            table: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn with_standard_io() -> Self {
        let this = Self::empty();

        let stdin = this.insert(std::Stdin).unwrap();
        assert_eq!(stdin.get(), 0);
        let stdout = this.insert(std::Stdout).unwrap();
        assert_eq!(stdout.get(), 1);
        let stderr = this.insert(std::Stderr).unwrap();
        assert_eq!(stderr.get(), 2);

        this
    }

    pub fn insert(&self, fd: impl Into<FileDescriptor>) -> Result<FdNum> {
        self.insert_after(0, fd)
    }

    fn find_free_fd_num(table: &BTreeMap<i32, FileDescriptor>, min: i32) -> Result<i32> {
        const MAX_FD: i32 = i32::MAX;

        let min = cmp::max(0, min);

        let fd_iter = table.keys().copied().skip_while(|i| *i < min);
        let mut counter_iter = min..MAX_FD;

        fd_iter
            .zip(counter_iter.by_ref())
            .find(|(fd, counter)| counter < fd)
            .map(|(_, counter)| counter)
            .or_else(|| counter_iter.next())
            .ok_or_else(|| Error::mfile(()))
    }

    pub fn insert_after(&self, min: i32, fd: impl Into<FileDescriptor>) -> Result<FdNum> {
        let mut guard = self.table.lock();
        let fd_num = Self::find_free_fd_num(&guard, min)?;
        guard.insert(fd_num, fd.into());
        Ok(FdNum::new(fd_num))
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

        Self {
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

    fn pread(&self, pos: usize, buf: &mut [u8]) -> Result<usize> {
        let _ = pos;
        let _ = buf;
        Err(Error::inval(()))
    }

    fn pwrite(&self, pos: usize, buf: &[u8]) -> Result<usize> {
        let _ = pos;
        let _ = buf;
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

    fn as_dir(&self) -> Result<Arc<dyn Directory>> {
        Err(Error::not_dir(()))
    }

    fn getdents64(&self, capacity: usize) -> Result<Vec<DirEntry>> {
        let _ = capacity;
        Err(Error::not_dir(()))
    }

    fn mmap(
        &self,
        vm: &mut ActiveVirtualMemory,
        addr: Option<VirtAddr>,
        offset: u64,
        len: u64,
        permissions: MemoryPermissions,
    ) -> Result<VirtAddr> {
        let _ = vm;
        let _ = addr;
        let _ = offset;
        let _ = len;
        let _ = permissions;
        Err(Error::io(()))
    }
}
