use core::any::type_name;

use crate::{
    error::{bail, ensure, err},
    fs::{
        FileSystem,
        node::{FileAccessContext, INode},
        path::Path,
    },
    memory::page::KernelPage,
    spin::mutex::Mutex,
    user::process::{
        syscall::args::{OpenFlags, Timespec},
        thread::{Gid, Uid},
    },
};
use alloc::sync::Arc;
use log::debug;

use crate::{
    error::Result,
    user::process::{
        memory::VirtualMemory,
        syscall::args::{FileMode, Pointer, Stat, Whence},
    },
};

use super::{Events, FileDescriptor, FileLock, OpenFileDescription, PipeBlocked, stream_buffer};

pub trait File: INode {
    fn get_page(&self, page_idx: usize, shared: bool) -> Result<KernelPage>;
    fn read(&self, offset: usize, buf: &mut [u8], no_atime: bool) -> Result<usize>;
    fn read_to_user(
        &self,
        offset: usize,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        mut len: usize,
        no_atime: bool,
    ) -> Result<usize> {
        const MAX_BUFFER_LEN: usize = 8192;
        if len > MAX_BUFFER_LEN {
            len = MAX_BUFFER_LEN;
            debug!("unoptimized read from {} truncated", type_name::<Self>());
        }

        let mut buf = [0; MAX_BUFFER_LEN];
        let buf = &mut buf[..len];

        let count = self.read(offset, buf, no_atime)?;

        let buf = &buf[..count];
        vm.write_bytes(pointer.get(), buf)?;

        Ok(count)
    }
    fn write(&self, offset: usize, buf: &[u8]) -> Result<usize>;
    fn write_from_user(
        &self,
        offset: usize,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        mut len: usize,
    ) -> Result<usize> {
        const MAX_BUFFER_LEN: usize = 8192;
        if len > MAX_BUFFER_LEN {
            len = MAX_BUFFER_LEN;
            debug!("unoptimized write to {} truncated", type_name::<Self>());
        }

        let mut buf = [0; MAX_BUFFER_LEN];
        let buf = &mut buf[..len];

        vm.read_bytes(pointer.get(), buf)?;

        self.write(offset, buf)
    }
    /// Returns a tuple of `(bytes_written, file_length)`.
    fn append(&self, buf: &[u8]) -> Result<(usize, usize)>;
    fn append_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        mut len: usize,
    ) -> Result<(usize, usize)> {
        const MAX_BUFFER_LEN: usize = 8192;
        if len > MAX_BUFFER_LEN {
            len = MAX_BUFFER_LEN;
            debug!("unoptimized write to {} truncated", type_name::<Self>());
        }

        let mut buf = [0; MAX_BUFFER_LEN];
        let buf = &mut buf[..len];

        vm.read_bytes(pointer.get(), buf)?;

        self.append(buf)
    }
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
    fn truncate(&self, length: usize) -> Result<()>;
}

pub fn open_file(path: Path, file: Arc<dyn File>, flags: OpenFlags) -> Result<FileDescriptor> {
    ensure!(!flags.contains(OpenFlags::DIRECTORY), IsDir);
    if flags.contains(OpenFlags::TRUNC) {
        file.truncate(0)?;
    }
    Ok(FileFileDescription::new(path, file, flags).into())
}

struct InternalFileFileDescription {
    flags: OpenFlags,
    cursor_idx: usize,
}

pub struct FileFileDescription {
    path: Path,
    file: Arc<dyn File>,
    file_lock: FileLock,
    internal: Mutex<InternalFileFileDescription>,
}

impl FileFileDescription {
    pub fn new(path: Path, file: Arc<dyn File>, flags: OpenFlags) -> Self {
        let file_lock = FileLock::new(file.file_lock_record().clone());
        Self {
            path,
            file,
            file_lock,
            internal: Mutex::new(InternalFileFileDescription {
                flags,
                cursor_idx: 0,
            }),
        }
    }
}

impl OpenFileDescription for FileFileDescription {
    fn flags(&self) -> OpenFlags {
        self.internal.lock().flags
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.internal.lock().flags = flags;
    }

    fn path(&self) -> Result<Path> {
        Ok(self.path.clone())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut guard = self.internal.lock();
        ensure!(!guard.flags.contains(OpenFlags::WRONLY), BadF);
        let no_atime = guard.flags.contains(OpenFlags::NOATIME);
        let len = self.file.read(guard.cursor_idx, buf, no_atime)?;
        guard.cursor_idx += len;
        Ok(len)
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let mut guard = self.internal.lock();
        ensure!(!guard.flags.contains(OpenFlags::WRONLY), BadF);
        let no_atime = guard.flags.contains(OpenFlags::NOATIME);
        let len = self
            .file
            .read_to_user(guard.cursor_idx, vm, pointer, len, no_atime)?;
        guard.cursor_idx += len;
        Ok(len)
    }

    fn pread(&self, pos: usize, buf: &mut [u8]) -> Result<usize> {
        let guard = self.internal.lock();
        ensure!(!guard.flags.contains(OpenFlags::WRONLY), BadF);
        let no_atime = guard.flags.contains(OpenFlags::NOATIME);
        drop(guard);
        self.file.read(pos, buf, no_atime)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut guard = self.internal.lock();
        ensure!(
            guard.flags.contains(OpenFlags::RDWR) || guard.flags.contains(OpenFlags::WRONLY),
            BadF
        );
        if !guard.flags.contains(OpenFlags::APPEND) {
            let len = self.file.write(guard.cursor_idx, buf)?;
            guard.cursor_idx += len;
            Ok(len)
        } else {
            let (len, cursor_idx) = self.file.append(buf)?;
            guard.cursor_idx = cursor_idx;
            Ok(len)
        }
    }

    fn write_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let mut guard = self.internal.lock();
        ensure!(
            guard.flags.contains(OpenFlags::RDWR) || guard.flags.contains(OpenFlags::WRONLY),
            BadF
        );
        if !guard.flags.contains(OpenFlags::APPEND) {
            let len = self
                .file
                .write_from_user(guard.cursor_idx, vm, pointer, len)?;
            guard.cursor_idx += len;
            Ok(len)
        } else {
            let (len, cursor_idx) = self.file.append_from_user(vm, pointer, len)?;
            guard.cursor_idx = cursor_idx;
            Ok(len)
        }
    }

    fn pwrite(&self, pos: usize, buf: &[u8]) -> Result<usize> {
        let guard = self.internal.lock();
        ensure!(
            guard.flags.contains(OpenFlags::RDWR) || guard.flags.contains(OpenFlags::WRONLY),
            BadF
        );
        self.file.write(pos, buf)
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
                ensure!(offset < self.file.stat()?.size as usize, XIo);

                // We don't support holes so we always jump to `offset`.
                guard.cursor_idx = offset;
            }
            Whence::Hole => {
                let size = usize::try_from(self.file.stat()?.size)?;

                // Ensure that `offset` doesn't point past the file.
                ensure!(offset < size, XIo);

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

    fn get_page(&self, page_idx: usize, shared: bool) -> Result<KernelPage> {
        self.file.get_page(page_idx, shared)
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & Events::READ
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}
