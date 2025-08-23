use alloc::{boxed::Box, sync::Arc};
use core::{cmp, future::pending};

use async_trait::async_trait;
use kernel_macros::register;

use super::CharDev;
use crate::{
    error::{Result, bail},
    fs::{
        FileSystem,
        fd::{
            BsdFileLock, Events, LazyBsdFileLockRecord, NonEmptyEvents, OpenFileDescription,
            PipeBlocked, StrongFileDescriptor, WriteBuf, stream_buffer,
        },
        node::{FileAccessContext, LinkLocation},
        path::Path,
    },
    supervisor,
    user::process::{
        syscall::args::{FileMode, OpenFlags, Stat},
        thread::{Gid, Uid},
    },
};

const MAJOR: u16 = 0xf00;

pub struct Output {
    location: LinkLocation,
    flags: OpenFlags,
    stat: Stat,
    fs: Arc<dyn FileSystem>,
    bsd_file_lock: BsdFileLock,
}

#[register]
impl CharDev for Output {
    const MAJOR: u16 = MAJOR;
    const MINOR: u8 = 0;

    fn new(
        location: LinkLocation,
        flags: OpenFlags,
        stat: Stat,
        fs: Arc<dyn FileSystem>,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        static RECORD: LazyBsdFileLockRecord = LazyBsdFileLockRecord::new();
        Ok(StrongFileDescriptor::from(Self {
            location,
            flags,
            stat,
            fs,
            bsd_file_lock: BsdFileLock::new(RECORD.get().clone()),
        }))
    }
}

#[async_trait]
impl OpenFileDescription for Output {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Result<Path> {
        self.location.path()
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn stat(&self) -> Result<Stat> {
        Ok(self.stat)
    }

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        NonEmptyEvents::new(events & Events::WRITE)
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        if let Some(events) = self.poll_ready(events) {
            events
        } else {
            pending().await
        }
    }

    fn write(&self, buf: &dyn WriteBuf) -> Result<usize> {
        let len = buf.buffer_len();
        for chunk_offset in (0..buf.buffer_len()).step_by(supervisor::OUTPUT_BUFFER_CAPACITY) {
            let remaining_len = len - chunk_offset;
            let buffer_len = cmp::min(remaining_len, supervisor::OUTPUT_BUFFER_CAPACITY);
            let mut chunk = [0; supervisor::OUTPUT_BUFFER_CAPACITY];
            let chunk = &mut chunk[..buffer_len];
            buf.read(chunk_offset, chunk)?;

            supervisor::update_output(chunk);
        }
        Ok(len)
    }

    fn splice_from(
        &self,
        read_half: &stream_buffer::ReadHalf,
        _offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        read_half.splice_to(len, |buffer, len| {
            let (slice1, slice2) = buffer.as_slices();
            let len1 = cmp::min(len, slice1.len());
            let len2 = len - len1;
            let slice1 = &slice1[..len1];
            let slice2 = &slice2[..len2];
            supervisor::update_output(slice1);
            supervisor::update_output(slice2);

            buffer.drain(..len);
        })
    }

    fn splice_to(
        &self,
        _write_half: &stream_buffer::WriteHalf,
        _offset: Option<usize>,
        _len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        bail!(BadF)
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(self.fs.clone())
    }

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
        Ok(&self.bsd_file_lock)
    }
}
