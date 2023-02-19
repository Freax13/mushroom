use core::sync::atomic::{AtomicI32, Ordering};

use alloc::{collections::BTreeMap, sync::Arc};
use spin::Mutex;

use crate::error::{Error, Result};

use super::syscall::Fd;

pub mod file;
mod std;

pub struct FileDescriptorTable {
    fd_counter: AtomicI32,
    table: Mutex<BTreeMap<i32, Arc<dyn FileDescriptor>>>,
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

    pub fn insert(&self, fd: impl FileDescriptor) -> Fd {
        let fd_num = self.fd_counter.fetch_add(1, Ordering::SeqCst);
        assert!(fd_num >= 0);

        let arc = Arc::new(fd);
        self.table.lock().insert(fd_num, arc);

        Fd::new(fd_num)
    }

    pub fn get(&self, fd_num: Fd) -> Result<Arc<dyn FileDescriptor>> {
        self.table
            .lock()
            .get(&fd_num.get())
            .cloned()
            .ok_or(Error::BadF)
    }

    pub fn close(&self, fd_num: Fd) -> Result<()> {
        let fd = self.table.lock().remove(&fd_num.get()).ok_or(Error::BadF)?;
        fd.close()
    }
}

pub trait FileDescriptor: Send + Sync + 'static {
    fn write(&self, buf: &[u8]) -> Result<u64> {
        let _ = buf;
        Err(Error::Inval)
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}
