use alloc::boxed::Box;
use async_trait::async_trait;
use log::debug;

use super::{Events, OpenFileDescription};
use crate::error::Result;

pub struct UnixSocket {}

impl UnixSocket {
    pub fn new_pair() -> (Self, Self) {
        (Self {}, Self {})
    }
}

#[async_trait]
impl OpenFileDescription for UnixSocket {
    fn read(&self, _buf: &mut [u8]) -> Result<usize> {
        todo!()
    }

    fn write(&self, _buf: &[u8]) -> Result<usize> {
        todo!()
    }

    fn poll_ready(&self, events: Events) -> Result<Events> {
        debug!("{events:?}");
        Ok(Events::empty())
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        debug!("{events:?}");
        core::future::pending().await
    }
}
