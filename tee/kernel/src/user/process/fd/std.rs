use log::debug;

use super::FileDescriptor;
use crate::error::Result;

pub struct Stdin;

impl FileDescriptor for Stdin {}

pub struct Stdout;

impl FileDescriptor for Stdout {
    fn write(&self, buf: &[u8]) -> Result<usize> {
        let chunk = core::str::from_utf8(buf);
        debug!("{chunk:02x?}");
        Ok(buf.len())
    }
}

pub struct Stderr;

impl FileDescriptor for Stderr {
    fn write(&self, buf: &[u8]) -> Result<usize> {
        let chunk = core::str::from_utf8(buf);
        debug!("{chunk:02x?}");
        Ok(buf.len())
    }
}
