use alloc::{borrow::Cow, sync::Arc};

use super::{File, FileSnapshot};
use crate::error::Result;

pub struct NullFile;

impl File for NullFile {
    fn is_executable(&self) -> bool {
        false
    }

    fn read_snapshot(&self) -> Result<FileSnapshot> {
        Ok(FileSnapshot(Arc::new(Cow::Borrowed(&[]))))
    }
}
