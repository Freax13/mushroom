#[cfg(not(feature = "harden"))]
use core::fmt;
use core::{
    any::type_name,
    cmp,
    ffi::c_void,
    ops::Deref,
    sync::atomic::{AtomicI64, Ordering},
};

use crate::{
    error::{bail, ensure, err},
    fs::{
        node::{new_ino, DirEntryName, DynINode, FileAccessContext},
        path::FileName,
    },
    memory::page::KernelPage,
    rt::notify::Notify,
    spin::{
        lazy::Lazy,
        mutex::{Mutex, MutexGuard},
    },
    user::process::{
        limits::CurrentNoFileLimit,
        memory::VirtualMemory,
        syscall::{
            args::{
                Accept4Flags, EpollEvent, FdNum, FileMode, FileType, OpenFlags, Pointer,
                RecvFromFlags, SentToFlags, ShutdownHow, SocketAddr, Stat, Timespec, Whence,
            },
            traits::Abi,
        },
        thread::{Gid, Uid},
    },
};
use alloc::{boxed::Box, collections::BTreeMap, format, sync::Arc, vec::Vec};
use async_trait::async_trait;
use bitflags::bitflags;
use file::File;
use log::debug;

use crate::{
    error::{ErrorKind, Result},
    fs::node::DirEntry,
};

use super::{
    node::procfs::{FdINode, ProcFs},
    path::Path,
    FileSystem,
};

pub mod dir;
pub mod epoll;
pub mod eventfd;
pub mod file;
pub mod path;
pub mod pipe;
mod std;
pub mod stream_buffer;
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

impl<T> From<Arc<T>> for FileDescriptor
where
    T: OpenFileDescription,
{
    fn from(value: Arc<T>) -> Self {
        FileDescriptor(value)
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
    pub const fn empty() -> Self {
        Self {
            table: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn with_standard_io() -> Self {
        let this = Self::empty();
        let no_file_limit = CurrentNoFileLimit::new(3);

        let stdin = this
            .insert(
                std::Stdin::new(Uid::SUPER_USER, Gid::SUPER_USER),
                FdFlags::empty(),
                no_file_limit,
            )
            .unwrap();
        assert_eq!(stdin.get(), 0);
        let stdout = this
            .insert(
                std::Stdout::new(Uid::SUPER_USER, Gid::SUPER_USER),
                FdFlags::empty(),
                no_file_limit,
            )
            .unwrap();
        assert_eq!(stdout.get(), 1);
        let stderr = this
            .insert(
                std::Stderr::new(Uid::SUPER_USER, Gid::SUPER_USER),
                FdFlags::empty(),
                no_file_limit,
            )
            .unwrap();
        assert_eq!(stderr.get(), 2);

        this
    }

    pub fn insert(
        &self,
        fd: impl Into<FileDescriptor>,
        flags: impl Into<FdFlags>,
        no_file_limit: CurrentNoFileLimit,
    ) -> Result<FdNum> {
        self.insert_after(0, fd, flags, no_file_limit)
    }

    fn find_free_fd_num(
        table: &BTreeMap<i32, FileDescriptorTableEntry>,
        min: i32,
        no_file_limit: CurrentNoFileLimit,
    ) -> Result<i32> {
        ensure!(min < no_file_limit.get() as i32, Inval);
        let min = cmp::max(0, min);

        let fd_iter = table.keys().copied().skip_while(|i| *i < min);
        let mut counter_iter = min..no_file_limit.get() as i32;

        fd_iter
            .zip(counter_iter.by_ref())
            .find(|(fd, counter)| counter < fd)
            .map(|(_, counter)| counter)
            .or_else(|| counter_iter.next())
            .ok_or(err!(Mfile))
    }

    pub fn insert_after(
        &self,
        min: i32,
        fd: impl Into<FileDescriptor>,
        flags: impl Into<FdFlags>,
        no_file_limit: CurrentNoFileLimit,
    ) -> Result<FdNum> {
        let mut guard = self.table.lock();
        let fd_num = Self::find_free_fd_num(&guard, min, no_file_limit)?;
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
        no_file_limit: CurrentNoFileLimit,
    ) -> Result<()> {
        ensure!(fd_num.get() < no_file_limit.get() as i32, BadF);

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
            .ok_or(err!(BadF))
    }

    pub fn set_flags(&self, fd_num: FdNum, flags: FdFlags) -> Result<()> {
        let mut guard = self.table.lock();
        let entry = guard.get_mut(&fd_num.get()).ok_or(err!(BadF))?;
        entry.flags = flags;
        Ok(())
    }

    pub fn close(&self, fd_num: FdNum) -> Result<()> {
        self.table
            .lock()
            .remove(&fd_num.get())
            .map(drop)
            .ok_or(err!(BadF))
    }

    pub fn prepare_for_execve(&self) -> Self {
        let guard = self.table.lock();
        // Unshare the entries and skip any entries with CLOEXEC set.
        Self {
            table: Mutex::new(
                guard
                    .iter()
                    .filter(|(_, entry)| !entry.flags.contains(FdFlags::CLOEXEC))
                    .map(|(fd, entry)| {
                        (
                            *fd,
                            FileDescriptorTableEntry::new(entry.fd.clone(), entry.flags),
                        )
                    })
                    .collect(),
            ),
        }
    }

    pub fn list_entries(&self) -> Vec<DirEntry> {
        let guard = self.table.lock();
        guard
            .iter()
            .map(|(num, entry)| DirEntry {
                ino: entry.ino,
                ty: FileType::Link,
                name: DirEntryName::FileName(
                    FileName::new(format!("{num}").as_bytes())
                        .unwrap()
                        .into_owned(),
                ),
            })
            .collect()
    }

    pub fn get_node(&self, fs: Arc<ProcFs>, fd_num: FdNum, uid: Uid, gid: Gid) -> Result<DynINode> {
        let guard = self.table.lock();
        let entry = guard.get(&fd_num.get()).ok_or(err!(NoEnt))?;
        Ok(Arc::new(FdINode::new(
            fs,
            entry.ino,
            uid,
            gid,
            entry.fd.clone(),
            entry.file_lock_record.get().clone(),
        )))
    }

    #[cfg(not(feature = "harden"))]
    pub fn dump(&self, indent: usize, mut write: impl fmt::Write) -> fmt::Result {
        writeln!(write, "{:indent$}fd table:", "")?;
        let indent = indent + 2;
        for (num, fd) in self.table.lock().iter() {
            writeln!(
                write,
                "{:indent$}{num} {} {:?}",
                "",
                fd.fd.type_name(),
                fd.flags
            )?;
        }
        Ok(())
    }
}

struct FileDescriptorTableEntry {
    ino: u64,
    fd: FileDescriptor,
    flags: FdFlags,
    file_lock_record: LazyFileLockRecord,
}

impl FileDescriptorTableEntry {
    fn new(fd: FileDescriptor, flags: FdFlags) -> Self {
        Self {
            ino: new_ino(),
            fd,
            flags,
            file_lock_record: LazyFileLockRecord::new(),
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
    #[derive(Debug, Clone, Copy)]
    pub struct FdFlags: u64 {
        const CLOEXEC = 1;
    }
}

pub struct PipeBlocked;

#[async_trait]
pub trait OpenFileDescription: Send + Sync + 'static {
    fn flags(&self) -> OpenFlags;

    fn set_flags(&self, flags: OpenFlags) {
        let _ = flags;
    }

    fn set_non_blocking(&self, non_blocking: bool) {
        let _ = non_blocking;
    }

    fn path(&self) -> Result<Path>;

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let _ = buf;
        bail!(Inval)
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
        bail!(Inval)
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
        bail!(SPipe)
    }

    fn pread(&self, pos: usize, buf: &mut [u8]) -> Result<usize> {
        let _ = pos;
        let _ = buf;
        bail!(Inval)
    }

    fn pwrite(&self, pos: usize, buf: &[u8]) -> Result<usize> {
        let _ = pos;
        let _ = buf;
        bail!(Inval)
    }

    fn splice_from(
        &self,
        read_half: &stream_buffer::ReadHalf,
        offset: Option<usize>,
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
        offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        let _ = write_half;
        let _ = offset;
        let _ = len;
        bail!(Inval)
    }

    /// Copy `len` bytes from `self` at offset `offset_in` to `fd_out` at
    /// offset `offset_out`.
    ///
    /// If this file descriptor represents a file, it should get a reference to
    /// the file and call copy_range_from_file on `fd_out`.
    fn copy_file_range(
        &self,
        offset_in: Option<usize>,
        fd_out: &dyn OpenFileDescription,
        offset_out: Option<usize>,
        len: usize,
    ) -> Result<usize> {
        let _ = offset_in;
        let _ = fd_out;
        let _ = offset_out;
        let _ = len;
        bail!(Inval)
    }

    /// Copy `len` bytes from `file_in` at offset `offset_in` to `self` at
    /// offset `offset_out`.
    ///
    /// If this file descriptor represents a file, it should get a reference to
    /// the file and call [`File::copy_file_range`].
    fn copy_range_from_file(
        &self,
        offset_out: Option<usize>,
        file_in: &dyn File,
        offset_in: usize,
        len: usize,
    ) -> Result<usize> {
        let _ = offset_out;
        let _ = file_in;
        let _ = offset_in;
        let _ = len;
        bail!(Inval)
    }

    fn truncate(&self, length: usize) -> Result<()> {
        let _ = length;
        bail!(Inval)
    }

    async fn write_all(&self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            let len = do_io(self, Events::WRITE, || self.write(buf)).await?;
            buf = &buf[len..];
        }
        Ok(())
    }

    fn bind(
        &self,
        virtual_memory: &VirtualMemory,
        addr: Pointer<SocketAddr>,
        addrlen: usize,
    ) -> Result<()> {
        let _ = virtual_memory;
        let _ = addr;
        let _ = addrlen;
        bail!(NotSock)
    }

    fn listen(&self, backlog: usize) -> Result<()> {
        let _ = backlog;
        bail!(NotSock)
    }

    fn accept(&self, flags: Accept4Flags) -> Result<(FileDescriptor, Vec<u8>)> {
        let _ = flags;
        bail!(NotSock)
    }

    async fn connect(
        &self,
        virtual_memory: &VirtualMemory,
        addr: Pointer<SocketAddr>,
        addrlen: usize,
    ) -> Result<()> {
        let _ = virtual_memory;
        let _ = addr;
        let _ = addrlen;
        bail!(NotSock)
    }

    fn get_socket_option(&self, abi: Abi, level: i32, optname: i32) -> Result<Vec<u8>> {
        let _ = abi;
        let _ = level;
        let _ = optname;
        bail!(NotSock)
    }

    fn set_socket_option(
        &self,
        virtual_memory: Arc<VirtualMemory>,
        abi: Abi,
        level: i32,
        optname: i32,
        optval: Pointer<[u8]>,
        optlen: i32,
    ) -> Result<()> {
        let _ = virtual_memory;
        let _ = abi;
        let _ = level;
        let _ = optname;
        let _ = optval;
        let _ = optlen;
        bail!(NotSock)
    }

    fn get_socket_name(&self) -> Result<Vec<u8>> {
        bail!(NotSock)
    }

    fn get_peer_name(&self) -> Result<Vec<u8>> {
        bail!(NotSock)
    }

    fn send_to(
        &self,
        vm: &VirtualMemory,
        buf: Pointer<[u8]>,
        len: usize,
        flags: SentToFlags,
        addr: Pointer<SocketAddr>,
        addrlen: usize,
    ) -> Result<usize> {
        let _ = vm;
        let _ = buf;
        let _ = len;
        let _ = flags;
        let _ = addr;
        let _ = addrlen;
        bail!(Inval)
    }

    fn recv_from(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
        flags: RecvFromFlags,
    ) -> Result<usize> {
        let _ = vm;
        let _ = pointer;
        let _ = len;
        let _ = flags;
        bail!(Inval)
    }

    fn shutdown(&self, how: ShutdownHow) -> Result<()> {
        let _ = how;
        bail!(NotSock)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()>;

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()>;

    fn update_times(&self, ctime: Timespec, atime: Option<Timespec>, mtime: Option<Timespec>) {
        let _ = ctime;
        let _ = atime;
        let _ = mtime;
    }

    fn stat(&self) -> Result<Stat>;

    fn fs(&self) -> Result<Arc<dyn FileSystem>>;

    fn as_dir(&self, ctx: &mut FileAccessContext) -> Result<DynINode> {
        let _ = ctx;
        bail!(NotDir)
    }

    fn getdents64(&self, capacity: usize, _ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
        let _ = capacity;
        bail!(NotDir)
    }

    fn as_pipe_read_half(&self) -> Option<&stream_buffer::ReadHalf> {
        None
    }

    fn as_pipe_write_half(&self) -> Option<&stream_buffer::WriteHalf> {
        None
    }

    fn get_page(&self, page_idx: usize, shared: bool) -> Result<KernelPage> {
        let _ = page_idx;
        let _ = shared;
        bail!(Acces)
    }

    async fn epoll_wait(&self, max_events: usize) -> Result<Vec<EpollEvent>> {
        let _ = max_events;
        bail!(Inval)
    }

    fn epoll_add(&self, fd: FileDescriptor, event: EpollEvent) -> Result<()> {
        let _ = fd;
        let _ = event;
        bail!(Inval)
    }

    fn poll_ready(&self, events: Events) -> Events;

    fn epoll_ready(&self, events: Events) -> Result<Events> {
        let _ = events;
        bail!(Perm)
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        let _ = events;
        bail!(Perm)
    }

    /// Returns a future that is ready when the file descriptor can process
    /// write of `size` bytes. Note that this doesn't necessairly mean that all
    /// `size` bytes will be written.
    async fn ready_for_write(&self, count: usize) -> Result<()> {
        let _ = count;
        self.ready(Events::WRITE).await.map(drop)
    }

    fn file_lock(&self) -> Result<&FileLock>;

    /// For path file descriptors, this method should return the pointed to
    /// path and INode.
    fn path_fd_node(&self) -> Option<(Path, DynINode)> {
        None
    }

    fn ioctl(&self, virtual_memory: &VirtualMemory, cmd: u32, arg: Pointer<c_void>) -> Result<u64> {
        common_ioctl(self, virtual_memory, cmd, arg)
    }

    #[cfg(not(feature = "harden"))]
    fn type_name(&self) -> &'static str {
        core::any::type_name::<Self>()
    }
}

pub fn common_ioctl<O>(
    fd: &O,
    virtual_memory: &VirtualMemory,
    cmd: u32,
    arg: Pointer<c_void>,
) -> Result<u64>
where
    O: OpenFileDescription + ?Sized,
{
    match cmd {
        0x5421 => {
            // FIONBIO
            let addr = arg.cast::<u32>();
            let val = virtual_memory.read(addr)? != 0;
            fd.set_non_blocking(val);
            Ok(0)
        }
        _ => bail!(NoTty),
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct Events: u8 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const ERR = 1 << 2;
        const RDHUP = 1 << 3;
        const HUP = 1 << 4;
        const PRI = 1 << 5;
    }
}

pub async fn do_io<R>(
    fd: &(impl OpenFileDescription + ?Sized),
    events: Events,
    mut callback: impl FnMut() -> Result<R>,
) -> Result<R> {
    let flags = fd.flags();
    let non_blocking = flags.contains(OpenFlags::NONBLOCK);

    loop {
        // Try to execute the closure.
        let res = callback();
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

pub async fn do_write_io<R>(
    fd: &(impl OpenFileDescription + ?Sized),
    count: usize,
    mut callback: impl FnMut() -> Result<R>,
) -> Result<R> {
    let flags = fd.flags();
    let non_blocking = flags.contains(OpenFlags::NONBLOCK);

    loop {
        // Try to execute the closure.
        let res = callback();
        match res {
            Ok(value) => return Ok(value),
            Err(err) if err.kind() == ErrorKind::Again && !non_blocking => {
                // Wait for the fd to be ready, then try again.
                fd.ready_for_write(count).await?;
            }
            Err(err) => return Err(err),
        }
    }
}

pub struct LazyFileLockRecord {
    file_lock_record: Lazy<Arc<FileLockRecord>>,
}

impl LazyFileLockRecord {
    pub const fn new() -> Self {
        Self {
            file_lock_record: Lazy::new(Default::default),
        }
    }

    pub fn get(&self) -> &Arc<FileLockRecord> {
        &self.file_lock_record
    }
}

pub struct FileLockRecord {
    /// -1  => exclusive
    /// 0   => unlocked
    /// 1.. => shared
    counter: AtomicI64,
    notify: Notify,
}

impl FileLockRecord {
    pub fn new() -> Self {
        Self {
            counter: AtomicI64::new(0),
            notify: Notify::new(),
        }
    }
}

impl Default for FileLockRecord {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FileLock {
    record: Arc<FileLockRecord>,
    state: Mutex<FileLockState>,
}

impl FileLock {
    pub fn new(record: Arc<FileLockRecord>) -> Self {
        Self {
            record,
            state: Mutex::new(FileLockState::Unlocked),
        }
    }

    pub fn anonymous() -> Self {
        Self::new(Arc::new(FileLockRecord::new()))
    }

    pub async fn lock_shared(&self, non_blocking: bool) -> Result<()> {
        loop {
            let wait = non_blocking.then(|| self.record.notify.wait());

            let mut guard = self.state.lock();
            self.unlock_internal(&mut guard);
            let res =
                self.record
                    .counter
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                        (value >= 0).then_some(value + 1)
                    });
            if res.is_ok() {
                *guard = FileLockState::Shared;
                return Ok(());
            }
            drop(guard);

            wait.ok_or(err!(Again))?.await;
        }
    }

    pub async fn lock_exclusive(&self, non_blocking: bool) -> Result<()> {
        loop {
            let wait = non_blocking.then(|| self.record.notify.wait());

            let mut guard = self.state.lock();
            self.unlock_internal(&mut guard);
            let res =
                self.record
                    .counter
                    .compare_exchange(0, -1, Ordering::Relaxed, Ordering::Relaxed);
            if res.is_ok() {
                *guard = FileLockState::Exclusive;
                return Ok(());
            }
            drop(guard);

            wait.ok_or(err!(Again))?.await;
        }
    }

    pub fn unlock(&self) {
        let mut guard = self.state.lock();
        self.unlock_internal(&mut guard)
    }

    fn unlock_internal(&self, guard: &mut MutexGuard<FileLockState>) {
        let prev_state = core::mem::replace(&mut **guard, FileLockState::Unlocked);
        match prev_state {
            FileLockState::Unlocked => {}
            FileLockState::Shared => {
                let value = self.record.counter.fetch_sub(1, Ordering::Relaxed);
                // If this was the last lock, notify any tasks waiting to
                // acquire an exclusive lock.
                if value == 1 {
                    self.record.notify.notify();
                }
            }
            FileLockState::Exclusive => {
                self.record.counter.store(0, Ordering::Relaxed);
                // Notify any tasks waiting to acquire an exclusive lock.
                self.record.notify.notify();
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        self.unlock();
    }
}

enum FileLockState {
    Unlocked,
    Shared,
    Exclusive,
}
