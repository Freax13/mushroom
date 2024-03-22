use core::{any::type_name, cmp, ops::Deref};

use crate::{
    fs::{
        node::{new_ino, DirEntryName, DynINode, FileAccessContext},
        path::FileName,
    },
    memory::page::KernelPage,
    spin::mutex::Mutex,
    user::process::{
        memory::VirtualMemory,
        syscall::args::{
            EpollEvent, FdNum, FileMode, FileType, OpenFlags, Pointer, Stat, Timespec, Whence,
        },
    },
};
use alloc::{boxed::Box, collections::BTreeMap, format, sync::Arc, vec::Vec};
use async_trait::async_trait;
use bitflags::bitflags;
use log::debug;

use crate::{
    error::{Error, ErrorKind, Result},
    fs::node::DirEntry,
};

use super::node::fdfs::FdINode;

pub mod dir;
pub mod epoll;
pub mod eventfd;
pub mod file;
pub mod path;
pub mod pipe;
mod std;
pub mod unix_socket;

#[derive(Clone)]
pub struct FileDescriptor(Arc<dyn OpenFileDescription>);

impl<T> From<T> for FileDescriptor
where
    T: OpenFileDescription,
{
    fn from(value: T) -> Self {
        FileDescriptor(Arc::new(value))
    }
}

impl Deref for FileDescriptor {
    type Target = dyn OpenFileDescription;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

pub struct FileDescriptorTable {
    table: Mutex<BTreeMap<i32, FileDescriptorTableEntry>>,
}

impl FileDescriptorTable {
    pub const MAX_FD: i32 = 0x10000;

    pub const fn empty() -> Self {
        Self {
            table: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn with_standard_io() -> Self {
        let this = Self::empty();

        let stdin = this.insert(std::Stdin::new(), FdFlags::empty()).unwrap();
        assert_eq!(stdin.get(), 0);
        let stdout = this.insert(std::Stdout::new(), FdFlags::empty()).unwrap();
        assert_eq!(stdout.get(), 1);
        let stderr = this.insert(std::Stderr::new(), FdFlags::empty()).unwrap();
        assert_eq!(stderr.get(), 2);

        this
    }

    pub fn insert(
        &self,
        fd: impl Into<FileDescriptor>,
        flags: impl Into<FdFlags>,
    ) -> Result<FdNum> {
        self.insert_after(0, fd, flags)
    }

    fn find_free_fd_num(table: &BTreeMap<i32, FileDescriptorTableEntry>, min: i32) -> Result<i32> {
        let min = cmp::max(0, min);

        let fd_iter = table.keys().copied().skip_while(|i| *i < min);
        let mut counter_iter = min..Self::MAX_FD;

        fd_iter
            .zip(counter_iter.by_ref())
            .find(|(fd, counter)| counter < fd)
            .map(|(_, counter)| counter)
            .or_else(|| counter_iter.next())
            .ok_or_else(|| Error::mfile(()))
    }

    pub fn insert_after(
        &self,
        min: i32,
        fd: impl Into<FileDescriptor>,
        flags: impl Into<FdFlags>,
    ) -> Result<FdNum> {
        let mut guard = self.table.lock();
        let fd_num = Self::find_free_fd_num(&guard, min)?;
        guard.insert(
            fd_num,
            FileDescriptorTableEntry::new(fd.into(), flags.into()),
        );
        Ok(FdNum::new(fd_num))
    }

    pub fn replace(
        &self,
        fd_num: FdNum,
        fd: impl Into<FileDescriptor>,
        flags: impl Into<FdFlags>,
    ) -> Result<()> {
        if fd_num.get() >= Self::MAX_FD {
            return Err(Error::bad_f(()));
        }

        let mut guard = self.table.lock();
        guard.insert(
            fd_num.get(),
            FileDescriptorTableEntry::new(fd.into(), flags.into()),
        );

        Ok(())
    }

    pub fn get(&self, fd_num: FdNum) -> Result<FileDescriptor> {
        self.get_with_flags(fd_num).map(|(fd, _flags)| fd)
    }

    pub fn get_with_flags(&self, fd_num: FdNum) -> Result<(FileDescriptor, FdFlags)> {
        self.table
            .lock()
            .get(&fd_num.get())
            .map(|fd| (fd.fd.clone(), fd.flags))
            .ok_or(Error::bad_f(()))
    }

    pub fn set_flags(&self, fd_num: FdNum, flags: FdFlags) -> Result<()> {
        let mut guard = self.table.lock();
        let entry = guard.get_mut(&fd_num.get()).ok_or(Error::bad_f(()))?;
        entry.flags = flags;
        Ok(())
    }

    pub fn close(&self, fd_num: FdNum) -> Result<()> {
        let fd = self
            .table
            .lock()
            .remove(&fd_num.get())
            .ok_or(Error::bad_f(()))?;
        fd.fd.close()
    }

    pub fn close_after_exec(&self) {
        let mut guard = self.table.lock();
        guard.retain(|_, entry| !entry.flags.contains(FdFlags::CLOEXEC));
    }

    pub fn list_entries(&self) -> Vec<DirEntry> {
        let guard = self.table.lock();
        guard
            .iter()
            .map(|(num, entry)| DirEntry {
                ino: entry.ino,
                ty: entry.fd.ty(),
                name: DirEntryName::FileName(
                    FileName::new(format!("{num}").as_bytes())
                        .unwrap()
                        .into_owned(),
                ),
            })
            .collect()
    }

    pub fn get_node(&self, fd_num: FdNum) -> Result<DynINode> {
        let guard = self.table.lock();
        let entry = guard.get(&fd_num.get()).ok_or_else(|| Error::no_ent(()))?;
        Ok(Arc::new(FdINode::new(entry.ino, entry.fd.clone())))
    }
}

struct FileDescriptorTableEntry {
    ino: u64,
    fd: FileDescriptor,
    flags: FdFlags,
}

impl FileDescriptorTableEntry {
    fn new(fd: FileDescriptor, flags: FdFlags) -> Self {
        Self {
            ino: new_ino(),
            fd,
            flags,
        }
    }
}

impl Clone for FileDescriptorTable {
    fn clone(&self) -> Self {
        // Copy the table.
        let table = self
            .table
            .lock()
            .iter()
            .map(|(num, fd)| (*num, FileDescriptorTableEntry::new(fd.fd.clone(), fd.flags)))
            .collect();
        Self {
            table: Mutex::new(table),
        }
    }
}

bitflags! {
    #[derive(Clone, Copy)]
    pub struct FdFlags: u64 {
        const CLOEXEC = 1;
    }
}

#[async_trait]
pub trait OpenFileDescription: Send + Sync + 'static {
    fn flags(&self) -> OpenFlags;

    fn set_flags(&self, flags: OpenFlags) {
        let _ = flags;
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let _ = buf;
        Err(Error::inval(()))
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        mut len: usize,
    ) -> Result<usize> {
        const MAX_BUFFER_LEN: usize = 8192;
        if len > MAX_BUFFER_LEN {
            len = MAX_BUFFER_LEN;
            debug!("unoptimized read from {} truncated", type_name::<Self>());
        }

        let mut buf = [0; MAX_BUFFER_LEN];
        let buf = &mut buf[..len];

        let count = self.read(buf)?;

        let buf = &buf[..count];
        vm.write_bytes(pointer.get(), buf)?;

        Ok(count)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let _ = buf;
        Err(Error::inval(()))
    }

    fn write_from_user(
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

        self.write(buf)
    }

    fn seek(&self, offset: usize, whence: Whence) -> Result<usize> {
        let _ = offset;
        let _ = whence;
        Err(Error::s_pipe(()))
    }

    fn pread(&self, pos: usize, buf: &mut [u8]) -> Result<usize> {
        let _ = pos;
        let _ = buf;
        Err(Error::inval(()))
    }

    fn pwrite(&self, pos: usize, buf: &[u8]) -> Result<usize> {
        let _ = pos;
        let _ = buf;
        Err(Error::inval(()))
    }

    fn truncate(&self, length: usize) -> Result<()> {
        let _ = length;
        Err(Error::inval(()))
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }

    async fn write_all(&self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            let len = do_io(self, Events::WRITE, || self.write(buf)).await?;
            buf = &buf[len..];
        }
        Ok(())
    }

    fn set_mode(&self, mode: FileMode) -> Result<()> {
        let _ = mode;
        Err(Error::io(()))
    }

    fn update_times(&self, ctime: Timespec, atime: Option<Timespec>, mtime: Option<Timespec>) {
        let _ = ctime;
        let _ = atime;
        let _ = mtime;
    }

    fn stat(&self) -> Stat;

    fn ty(&self) -> FileType {
        self.stat().mode.ty()
    }

    fn as_dir(&self, ctx: &mut FileAccessContext) -> Result<DynINode> {
        let _ = ctx;
        Err(Error::not_dir(()))
    }

    fn getdents64(&self, capacity: usize, _ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
        let _ = capacity;
        Err(Error::not_dir(()))
    }

    fn get_page(&self, page_idx: usize) -> Result<KernelPage> {
        let _ = page_idx;
        Err(Error::acces(()))
    }

    async fn epoll_wait(&self, max_events: usize) -> Result<Vec<EpollEvent>> {
        let _ = max_events;
        Err(Error::inval(()))
    }

    fn epoll_add(&self, fd: FileDescriptor, event: EpollEvent) -> Result<()> {
        let _ = fd;
        let _ = event;
        Err(Error::inval(()))
    }

    fn poll_ready(&self, events: Events) -> Events;

    fn epoll_ready(&self, events: Events) -> Result<Events> {
        let _ = events;
        Err(Error::perm(()))
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        let _ = events;
        Err(Error::perm(()))
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct Events: u8 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
    }
}

pub async fn do_io<R>(
    fd: &(impl OpenFileDescription + ?Sized),
    events: Events,
    mut callback: impl FnMut() -> Result<R>,
) -> Result<R> {
    loop {
        // Try to execute the closure.
        let res = callback();
        match res {
            Ok(value) => return Ok(value),
            Err(err) if err.kind() == ErrorKind::Again => {
                // Wait for the fd to be ready, then try again.
                fd.ready(events).await?;
            }
            Err(err) => return Err(err),
        }
    }
}

pub async fn do_io_with_vm<R, F>(
    fd: &(impl OpenFileDescription + ?Sized),
    events: Events,
    vm: Arc<VirtualMemory>,
    mut callback: F,
) -> Result<R>
where
    R: Send + 'static,
    F: FnMut(&VirtualMemory) -> Result<R>,
{
    let flags = fd.flags();
    let non_blocking = flags.contains(OpenFlags::NONBLOCK);

    loop {
        // Try to execute the closure.
        let res = callback(&vm);

        match res {
            Ok(value) => return Ok(value),
            Err(err) if err.kind() == ErrorKind::Again && !non_blocking => {
                // Wait for the fd to be ready, then try again.
                fd.ready(events).await?;
            }
            Err(err) => return Err(err),
        }
    }
}
