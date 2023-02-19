use log::debug;

use super::FileDescriptor;
use crate::error::Result;

pub struct Stdin;

impl FileDescriptor for Stdin {}

pub struct Stdout;

impl FileDescriptor for Stdout {
    fn write(&self, buf: &[u8]) -> Result<u64> {
        let chunk = core::str::from_utf8(buf);
        debug!("{chunk:02x?}");
        Ok(u64::try_from(buf.len()).unwrap())
    }
}

pub struct Stderr;

impl FileDescriptor for Stderr {
    fn write(&self, buf: &[u8]) -> Result<u64> {
        let chunk = core::str::from_utf8(buf);
        debug!("{chunk:02x?}");
        Ok(u64::try_from(buf.len()).unwrap())
    }
}
