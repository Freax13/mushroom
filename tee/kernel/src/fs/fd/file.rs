use core::any::type_name;

use crate::{
    error::{ensure, err},
    fs::{
        node::{FileAccessContext, INode},
        path::Path,
        FileSystem,
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

use super::{Events, FileDescriptor, FileLock, OpenFileDescription};

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
    fn append(&self, buf: &[u8]) -> Result<usize>;
    fn append_from_user(
        &self,
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

        self.append(buf)
    }
    fn truncate(&self, length: usize) -> Result<()>;
}

pub fn open_file(path: Path, file: Arc<dyn File>, flags: OpenFlags) -> Result<FileDescriptor> {
    ensure!(!flags.contains(OpenFlags::DIRECTORY), IsDir);

    if flags.contains(OpenFlags::TRUNC) {
        file.truncate(0)?;
    }

    let fd = if flags.contains(OpenFlags::WRONLY) {
        if flags.contains(OpenFlags::APPEND) {
            FileDescriptor::from(AppendFileFileDescription::new(path, file, flags))
        } else {
            FileDescriptor::from(WriteonlyFileFileDescription::new(path, file, flags))
        }
    } else if flags.contains(OpenFlags::RDWR) {
        FileDescriptor::from(ReadWriteFileFileDescription::new(path, file, flags))
    } else {
        FileDescriptor::from(ReadonlyFileFileDescription::new(path, file, flags))
    };
    Ok(fd)
}

/// A file description for files opened as read-only.
pub struct ReadonlyFileFileDescription {
    path: Path,
    file: Arc<dyn File>,
    flags: OpenFlags,
    cursor_idx: Mutex<usize>,
    file_lock: FileLock,
}

impl ReadonlyFileFileDescription {
    pub fn new(path: Path, file: Arc<dyn File>, flags: OpenFlags) -> Self {
        let file_lock = FileLock::new(file.file_lock_record().clone());
        Self {
            path,
            file,
            flags,
            cursor_idx: Mutex::new(0),
            file_lock,
        }
    }
}

impl OpenFileDescription for ReadonlyFileFileDescription {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Result<Path> {
        Ok(self.path.clone())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let no_atime = self.flags.contains(OpenFlags::NOATIME);
        let mut guard = self.cursor_idx.lock();
        let len = self.file.read(*guard, buf, no_atime)?;
        *guard += len;
        Ok(len)
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let no_atime = self.flags.contains(OpenFlags::NOATIME);
        let mut guard = self.cursor_idx.lock();
        let len = self.file.read_to_user(*guard, vm, pointer, len, no_atime)?;
        *guard += len;
        Ok(len)
    }

    fn pread(&self, pos: usize, buf: &mut [u8]) -> Result<usize> {
        let no_atime = self.flags.contains(OpenFlags::NOATIME);
        self.file.read(pos, buf, no_atime)
    }

    fn seek(&self, offset: usize, whence: Whence) -> Result<usize> {
        let mut guard = self.cursor_idx.lock();
        match whence {
            Whence::Set => *guard = offset,
            Whence::Cur => {
                *guard = guard
                    .checked_add_signed(offset as isize)
                    .ok_or(err!(Inval))?
            }
            Whence::End => {
                let size = usize::try_from(self.file.stat()?.size)?;
                *guard = size
                    .checked_add_signed(offset as isize)
                    .ok_or(err!(Inval))?
            }
            Whence::Data => {
                // Ensure that `offset` doesn't point past the file.
                ensure!(offset < self.file.stat()?.size as usize, XIo);

                // We don't support holes so we always jump to `offset`.
                *guard = offset;
            }
            Whence::Hole => {
                let size = usize::try_from(self.file.stat()?.size)?;

                // Ensure that `offset` doesn't point past the file.
                ensure!(offset < size, XIo);

                // We don't support holes so we always jump to the end of the file.
                *guard = size;
            }
        }
        Ok(*guard)
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

/// A file description for files opened as write-only.
pub struct WriteonlyFileFileDescription {
    path: Path,
    file: Arc<dyn File>,
    flags: OpenFlags,
    cursor_idx: Mutex<usize>,
    file_lock: FileLock,
}

impl WriteonlyFileFileDescription {
    pub fn new(path: Path, file: Arc<dyn File>, flags: OpenFlags) -> Self {
        let file_lock = FileLock::new(file.file_lock_record().clone());
        Self {
            path,
            file,
            flags,
            cursor_idx: Mutex::new(0),
            file_lock,
        }
    }
}

impl OpenFileDescription for WriteonlyFileFileDescription {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Result<Path> {
        Ok(self.path.clone())
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut guard = self.cursor_idx.lock();
        let len = self.file.write(*guard, buf)?;
        *guard += len;
        Ok(len)
    }

    fn write_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let mut guard = self.cursor_idx.lock();
        let len = self.file.write_from_user(*guard, vm, pointer, len)?;
        *guard += len;
        Ok(len)
    }

    fn pwrite(&self, pos: usize, buf: &[u8]) -> Result<usize> {
        self.file.write(pos, buf)
    }

    fn truncate(&self, length: usize) -> Result<()> {
        self.file.truncate(length)
    }

    fn seek(&self, offset: usize, whence: Whence) -> Result<usize> {
        let mut guard = self.cursor_idx.lock();
        match whence {
            Whence::Set => *guard = offset,
            Whence::Cur => {
                *guard = guard
                    .checked_add_signed(offset as isize)
                    .ok_or(err!(Inval))?
            }
            Whence::End => {
                let size = usize::try_from(self.file.stat()?.size)?;
                *guard = size
                    .checked_add_signed(offset as isize)
                    .ok_or(err!(Inval))?
            }
            Whence::Data => todo!(),
            Whence::Hole => todo!(),
        }
        Ok(*guard)
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
        events & Events::WRITE
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

/// A file description for files opened as write-only.
pub struct AppendFileFileDescription {
    path: Path,
    file: Arc<dyn File>,
    flags: OpenFlags,
    file_lock: FileLock,
}

impl AppendFileFileDescription {
    pub fn new(path: Path, file: Arc<dyn File>, flags: OpenFlags) -> Self {
        let file_lock = FileLock::new(file.file_lock_record().clone());
        Self {
            path,
            file,
            flags,
            file_lock,
        }
    }
}

impl OpenFileDescription for AppendFileFileDescription {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Result<Path> {
        Ok(self.path.clone())
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.file.append(buf)
    }

    fn write_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        self.file.append_from_user(vm, pointer, len)
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
        events & Events::WRITE
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

/// A file description for files opened as read and write.
pub struct ReadWriteFileFileDescription {
    path: Path,
    file: Arc<dyn File>,
    flags: OpenFlags,
    cursor_idx: Mutex<usize>,
    file_lock: FileLock,
}

impl ReadWriteFileFileDescription {
    pub fn new(path: Path, file: Arc<dyn File>, flags: OpenFlags) -> Self {
        let file_lock = FileLock::new(file.file_lock_record().clone());
        Self {
            path,
            file,
            flags,
            cursor_idx: Mutex::new(0),
            file_lock,
        }
    }
}

impl OpenFileDescription for ReadWriteFileFileDescription {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Result<Path> {
        Ok(self.path.clone())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let no_atime = self.flags.contains(OpenFlags::NOATIME);
        let mut guard = self.cursor_idx.lock();
        let len = self.file.read(*guard, buf, no_atime)?;
        *guard += len;
        Ok(len)
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let no_atime = self.flags.contains(OpenFlags::NOATIME);
        let mut guard = self.cursor_idx.lock();
        let len = self.file.read_to_user(*guard, vm, pointer, len, no_atime)?;
        *guard += len;
        Ok(len)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut guard = self.cursor_idx.lock();
        let len = self.file.write(*guard, buf)?;
        *guard += len;
        Ok(len)
    }

    fn write_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        let mut guard = self.cursor_idx.lock();
        let len = self.file.write_from_user(*guard, vm, pointer, len)?;
        *guard += len;
        Ok(len)
    }

    fn pread(&self, pos: usize, buf: &mut [u8]) -> Result<usize> {
        let no_atime = self.flags.contains(OpenFlags::NOATIME);
        self.file.read(pos, buf, no_atime)
    }

    fn pwrite(&self, pos: usize, buf: &[u8]) -> Result<usize> {
        self.file.write(pos, buf)
    }

    fn truncate(&self, length: usize) -> Result<()> {
        self.file.truncate(length)
    }

    fn seek(&self, offset: usize, whence: Whence) -> Result<usize> {
        let mut guard = self.cursor_idx.lock();
        match whence {
            Whence::Set => *guard = offset,
            Whence::Cur => {
                *guard = guard
                    .checked_add_signed(offset as isize)
                    .ok_or(err!(Inval))?
            }
            Whence::End => {
                let size = usize::try_from(self.file.stat()?.size)?;
                *guard = size
                    .checked_add_signed(offset as isize)
                    .ok_or(err!(Inval))?
            }
            Whence::Data => todo!(),
            Whence::Hole => todo!(),
        }
        Ok(*guard)
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
        events & (Events::READ | Events::WRITE)
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}
