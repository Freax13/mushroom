use alloc::sync::Arc;

use crate::{error::Result, fs::node::Directory, user::process::syscall::args::Stat};

use super::OpenFileDescription;

pub struct DirectoryFileDescription {
    dir: Arc<dyn Directory>,
}

impl DirectoryFileDescription {
    pub fn new(dir: Arc<dyn Directory>) -> Self {
        Self { dir }
    }
}

impl OpenFileDescription for DirectoryFileDescription {
    fn stat(&self) -> Result<Stat> {
        Ok(self.dir.stat())
    }

    fn as_dir(&self) -> Result<Arc<dyn Directory>> {
        Ok(self.dir.clone())
    }
}
