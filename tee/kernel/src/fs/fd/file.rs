use core::{future::pending, num::NonZeroU32};

use crate::{
    error::{bail, ensure, err},
    fs::{
        FileSystem,
        node::{FileAccessContext, INode, LinkLocation},
        path::Path,
    },
    memory::page::KernelPage,
    spin::mutex::Mutex,
    user::process::{
        futex::Futexes,
        syscall::args::{FallocateMode, InotifyMask, OpenFlags, Timespec},
        thread::{Gid, Uid},
    },
};
use alloc::{boxed::Box, sync::Arc};
use async_trait::async_trait;

use crate::{
    error::Result,
    user::process::syscall::args::{FileMode, Stat, Whence},
};

use super::{
    Events, FileLock, NonEmptyEvents, OpenFileDescription, PipeBlocked, ReadBuf,
    StrongFileDescriptor, WriteBuf, stream_buffer,
};

pub trait File: INode {
    fn get_page(&self, page_idx: usize, shared: bool) -> Result<KernelPage>;
    fn futexes(&self) -> Option<Arc<Futexes>> {
        None
    }
    fn read(&self, offset: usize, buf: &mut dyn ReadBuf, no_atime: bool) -> Result<usize>;
    fn write(&self, offset: usize, buf: &dyn WriteBuf) -> Result<usize>;
    /// Returns a tuple of `(bytes_written, file_length)`.
    fn append(&self, buf: &dyn WriteBuf) -> Result<(usize, usize)>;
    fn splice_from(
        &self,
        read_half: &stream_buffer::ReadHalf,
        offset: usize,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        let _ = read_half;
        let _ = offset;
        let _ = len;
        bail!(Inval)
    }
    fn splice_to(
        &self,
        write_half: &stream_buffer::WriteHalf,
        offset: usize,
        len: usize,
        no_atime: bool,
    ) -> Result<Result<usize, PipeBlocked>> {
        let _ = write_half;
        let _ = offset;
        let _ = len;
        let _ = no_atime;
        bail!(Inval)
    }
    fn copy_file_range(
        &self,
        offset_in: usize,
        out: &dyn File,
        offset_out: usize,
        len: usize,
    ) -> Result<usize> {
        let _ = offset_in;
        let _ = out;
        let _ = offset_out;
        let _ = len;
        bail!(OpNotSupp)
    }
    fn allocate(&self, mode: FallocateMode, offset: usize, len: usize) -> Result<()>;
    fn deleted(&self) -> bool;
}

pub fn open_file(
    file: Arc<dyn File>,
    location: LinkLocation,
    flags: OpenFlags,
) -> Result<StrongFileDescriptor> {
    ensure!(!flags.contains(OpenFlags::DIRECTORY), NotDir);
    if flags.contains(OpenFlags::TRUNC) {
        file.truncate(0)?;
    }
    Ok(FileFileDescription::new(file, location, flags).into())
}

struct InternalFileFileDescription {
    flags: OpenFlags,
    cursor_idx: usize,
}

pub struct FileFileDescription {
    file: Arc<dyn File>,
    location: LinkLocation,
    file_lock: FileLock,
    internal: Mutex<InternalFileFileDescription>,
}

impl FileFileDescription {
    pub fn new(file: Arc<dyn File>, location: LinkLocation, flags: OpenFlags) -> Self {
        let file_lock = FileLock::new(file.file_lock_record().clone());
        Self {
            file,
            location,
            file_lock,
            internal: Mutex::new(InternalFileFileDescription {
                flags,
                cursor_idx: 0,
            }),
        }
    }

    fn send_event(&self, mask: InotifyMask, cookie: Option<NonZeroU32>) {
        self.file.watchers().send_event(mask, cookie, None);
        let parent = self.location.parent().unwrap();
        let file_name = self.location.file_name().unwrap();
        parent.watchers().send_event(mask, cookie, Some(file_name));
    }
}

#[async_trait]
impl OpenFileDescription for FileFileDescription {
    fn flags(&self) -> OpenFlags {
        self.internal.lock().flags
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.internal.lock().flags = flags;
    }

    fn path(&self) -> Result<Path> {
        self.location.path()
    }

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        let mut guard = self.internal.lock();
        ensure!(!guard.flags.contains(OpenFlags::WRONLY), BadF);
        let no_atime = guard.flags.contains(OpenFlags::NOATIME);
        let len = self.file.read(guard.cursor_idx, buf, no_atime)?;
        guard.cursor_idx += len;
        drop(guard);

        if len > 0 {
            self.send_event(InotifyMask::ACCESS, None);
        }

        Ok(len)
    }

    fn pread(&self, pos: usize, buf: &mut dyn ReadBuf) -> Result<usize> {
        let guard = self.internal.lock();
        ensure!(!guard.flags.contains(OpenFlags::WRONLY), BadF);
        let no_atime = guard.flags.contains(OpenFlags::NOATIME);
        drop(guard);
        let len = self.file.read(pos, buf, no_atime)?;

        if len > 0 {
            self.send_event(InotifyMask::ACCESS, None);
        }

        Ok(len)
    }

    fn write(&self, buf: &dyn WriteBuf) -> Result<usize> {
        let mut guard = self.internal.lock();
        ensure!(
            guard.flags.contains(OpenFlags::RDWR) || guard.flags.contains(OpenFlags::WRONLY),
            BadF
        );
        let len = if !guard.flags.contains(OpenFlags::APPEND) {
            let len = self.file.write(guard.cursor_idx, buf)?;
            guard.cursor_idx += len;
            len
        } else {
            let (len, cursor_idx) = self.file.append(buf)?;
            guard.cursor_idx = cursor_idx;
            len
        };
        drop(guard);

        if len > 0 {
            self.send_event(InotifyMask::MODIFY, None);
        }

        Ok(len)
    }

    fn pwrite(&self, pos: usize, buf: &dyn WriteBuf) -> Result<usize> {
        let guard = self.internal.lock();
        ensure!(
            guard.flags.contains(OpenFlags::RDWR) || guard.flags.contains(OpenFlags::WRONLY),
            BadF
        );
        let len = self.file.write(pos, buf)?;
        drop(guard);

        if len > 0 {
            self.send_event(InotifyMask::MODIFY, None);
        }

        Ok(len)
    }

    fn splice_from(
        &self,
        read_half: &stream_buffer::ReadHalf,
        offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        let mut guard = self.internal.lock();
        ensure!(
            guard.flags.contains(OpenFlags::RDWR) || guard.flags.contains(OpenFlags::WRONLY),
            BadF
        );
        ensure!(!guard.flags.contains(OpenFlags::APPEND), Inval);

        if let Some(offset) = offset {
            self.file.splice_from(read_half, offset, len)
        } else {
            self.file
                .splice_from(read_half, guard.cursor_idx, len)
                .inspect(|res| {
                    if let Ok(len) = res {
                        guard.cursor_idx += len;
                    }
                })
        }
    }

    fn splice_to(
        &self,
        write_half: &stream_buffer::WriteHalf,
        offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        let mut guard = self.internal.lock();
        ensure!(!guard.flags.contains(OpenFlags::WRONLY), BadF);

        let no_atime = guard.flags.contains(OpenFlags::NOATIME);
        if let Some(offset) = offset {
            self.file.splice_to(write_half, offset, len, no_atime)
        } else {
            self.file
                .splice_to(write_half, guard.cursor_idx, len, no_atime)
                .inspect(|res| {
                    if let Ok(len) = res {
                        guard.cursor_idx += len
                    }
                })
        }
    }

    fn copy_file_range(
        &self,
        offset_in: Option<usize>,
        fd_out: &dyn OpenFileDescription,
        offset_out: Option<usize>,
        len: usize,
    ) -> Result<usize> {
        let mut guard = self.internal.lock();
        ensure!(!guard.flags.contains(OpenFlags::WRONLY), BadF);

        if let Some(offset_in) = offset_in {
            fd_out.copy_range_from_file(offset_out, &*self.file, offset_in, len)
        } else {
            let len =
                fd_out.copy_range_from_file(offset_out, &*self.file, guard.cursor_idx, len)?;
            guard.cursor_idx += len;
            Ok(len)
        }
    }

    fn copy_range_from_file(
        &self,
        offset_out: Option<usize>,
        file_in: &dyn File,
        offset_in: usize,
        len: usize,
    ) -> Result<usize> {
        let mut guard = self.internal.lock();
        ensure!(
            guard.flags.contains(OpenFlags::RDWR) || guard.flags.contains(OpenFlags::WRONLY),
            BadF
        );
        ensure!(!guard.flags.contains(OpenFlags::APPEND), BadF);

        if let Some(offset_out) = offset_out {
            file_in.copy_file_range(offset_in, &*self.file, offset_out, len)
        } else {
            let len = file_in.copy_file_range(offset_in, &*self.file, guard.cursor_idx, len)?;
            guard.cursor_idx += len;
            Ok(len)
        }
    }

    fn truncate(&self, length: usize) -> Result<()> {
        let guard = self.internal.lock();
        ensure!(
            guard.flags.contains(OpenFlags::RDWR) || guard.flags.contains(OpenFlags::WRONLY),
            BadF
        );
        self.file.truncate(length)
    }

    fn allocate(&self, mode: FallocateMode, offset: usize, len: usize) -> Result<()> {
        let guard = self.internal.lock();
        ensure!(
            guard.flags.contains(OpenFlags::RDWR) || guard.flags.contains(OpenFlags::WRONLY),
            BadF
        );
        self.file.allocate(mode, offset, len)
    }

    fn seek(&self, offset: usize, whence: Whence) -> Result<usize> {
        let mut guard = self.internal.lock();

        match whence {
            Whence::Set => guard.cursor_idx = offset,
            Whence::Cur => {
                guard.cursor_idx = guard
                    .cursor_idx
                    .checked_add_signed(offset as isize)
                    .ok_or(err!(Inval))?
            }
            Whence::End => {
                let size = usize::try_from(self.file.stat()?.size)?;
                guard.cursor_idx = size
                    .checked_add_signed(offset as isize)
                    .ok_or(err!(Inval))?
            }
            Whence::Data => {
                // Ensure that `offset` doesn't point past the file.
                ensure!(offset < self.file.stat()?.size as usize, NxIo);

                // We don't support holes so we always jump to `offset`.
                guard.cursor_idx = offset;
            }
            Whence::Hole => {
                let size = usize::try_from(self.file.stat()?.size)?;

                // Ensure that `offset` doesn't point past the file.
                ensure!(offset < size, NxIo);

                // We don't support holes so we always jump to the end of the file.
                guard.cursor_idx = size;
            }
        }
        Ok(guard.cursor_idx)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.file.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.file.chown(uid, gid, ctx)
    }

    fn update_times(&self, ctime: Timespec, atime: Option<Timespec>, mtime: Option<Timespec>) {
        self.file.update_times(ctime, atime, mtime);
    }

    fn stat(&self) -> Result<Stat> {
        self.file.stat()
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        self.file.fs()
    }

    fn deleted(&self) -> bool {
        self.file.deleted()
    }

    fn get_page(&self, page_idx: usize, shared: bool) -> Result<KernelPage> {
        self.file.get_page(page_idx, shared)
    }

    fn futexes(&self) -> Option<Arc<Futexes>> {
        self.file.futexes()
    }

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        NonEmptyEvents::new(events & (Events::READ | Events::WRITE))
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        if let Some(event) = self.poll_ready(events) {
            event
        } else {
            pending().await
        }
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

impl Drop for FileFileDescription {
    fn drop(&mut self) {
        let mask = if self
            .internal
            .get_mut()
            .flags
            .intersects(OpenFlags::RDWR | OpenFlags::WRONLY)
        {
            InotifyMask::CLOSE_WRITE
        } else {
            InotifyMask::CLOSE_NOWRITE
        };

        self.send_event(mask, None);
    }
}
