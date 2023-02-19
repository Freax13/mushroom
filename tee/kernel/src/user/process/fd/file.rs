use crate::fs::node::FileSnapshot;

use super::FileDescriptor;

pub struct ReadonlyFile {
    snapshot: FileSnapshot,
    cursor_idx: u64,
}

impl ReadonlyFile {
    pub fn new(snapshot: FileSnapshot) -> Self {
        Self {
            snapshot,
            cursor_idx: 0,
        }
    }
}

impl FileDescriptor for ReadonlyFile {}
