use log::debug;

use super::OpenFileDescription;
use crate::error::Result;

pub struct Stdin;

impl OpenFileDescription for Stdin {}

pub struct Stdout;

impl OpenFileDescription for Stdout {
    fn write(&self, buf: &[u8]) -> Result<usize> {
        let chunk = core::str::from_utf8(buf);
        debug!("{chunk:02x?}");
        Ok(buf.len())
    }
}

pub struct Stderr;

impl OpenFileDescription for Stderr {
    fn write(&self, buf: &[u8]) -> Result<usize> {
        let chunk = core::str::from_utf8(buf);
        debug!("{chunk:02x?}");
        Ok(buf.len())
    }
}
