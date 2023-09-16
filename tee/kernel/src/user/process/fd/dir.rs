use crate::spin::mutex::Mutex;
use alloc::{sync::Arc, vec::Vec};

use crate::{
    error::{Error, Result},
    fs::node::{DirEntry, Directory},
    user::process::syscall::args::Stat,
};

use super::OpenFileDescription;

pub struct DirectoryFileDescription {
    dir: Arc<dyn Directory>,
    entries: Mutex<Option<Vec<DirEntry>>>,
}

impl DirectoryFileDescription {
    pub fn new(dir: Arc<dyn Directory>) -> Self {
        Self {
            dir,
            entries: Mutex::new(None),
        }
    }
}

impl OpenFileDescription for DirectoryFileDescription {
    fn stat(&self) -> Result<Stat> {
        Ok(self.dir.stat())
    }

    fn as_dir(&self) -> Result<Arc<dyn Directory>> {
        Ok(self.dir.clone())
    }

    fn getdents64(&self, mut capacity: usize) -> Result<Vec<DirEntry>> {
        let mut guard = self.entries.lock();
        let entries = guard.get_or_insert_with(|| self.dir.list_entries());

        let mut ret = Vec::new();
        while let Some(last) = entries.last() {
            if let Some(new_capacity) = capacity.checked_sub(last.len()) {
                ret.push(entries.pop().unwrap());
                capacity = new_capacity;
            } else {
                if ret.is_empty() {
                    return Err(Error::inval(()));
                }
                break;
            }
        }

        Ok(ret)
    }
}
