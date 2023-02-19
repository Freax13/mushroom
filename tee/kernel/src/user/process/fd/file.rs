use core::{
    cmp,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{error::Result, fs::node::FileSnapshot};

use super::FileDescriptor;

pub struct ReadonlyFile {
    snapshot: FileSnapshot,
    cursor_idx: AtomicUsize,
}

impl ReadonlyFile {
    pub fn new(snapshot: FileSnapshot) -> Self {
        Self {
            snapshot,
            cursor_idx: AtomicUsize::new(0),
        }
    }
}

impl FileDescriptor for ReadonlyFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let idx = self
            .cursor_idx
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |idx| {
                let bytes = &self.snapshot[idx..];
                let len = cmp::min(buf.len(), bytes.len());
                Some(idx + len)
            })
            .unwrap();

        let bytes = &self.snapshot[idx..];
        let len = cmp::min(buf.len(), bytes.len());
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(len)
    }
}
