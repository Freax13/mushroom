#[cfg(not(feature = "harden"))]
use core::fmt;
use core::{
    cmp,
    ffi::c_void,
    mem::offset_of,
    num::NonZeroU8,
    ops::{BitOr, BitOrAssign, Deref, Not},
    pin::pin,
    sync::atomic::{AtomicI64, AtomicUsize, Ordering},
};

use crate::{
    char_dev::char::PtyData,
    error::{bail, ensure, err},
    fs::{
        node::{DirEntryName, DynINode, FileAccessContext, new_ino},
        path::FileName,
    },
    memory::page::KernelPage,
    rt::notify::Notify,
    spin::{
        lazy::Lazy,
        mutex::{Mutex, MutexGuard},
    },
    user::process::{
        futex::Futexes,
        limits::CurrentNoFileLimit,
        memory::VirtualMemory,
        syscall::{
            args::{
                Accept4Flags, EpollEvent, FallocateMode, FdNum, FileMode, FileType, ITimerspec,
                InotifyMask, MsgHdr, OpenFlags, Pointer, RecvFromFlags, SentToFlags, SetTimeFlags,
                ShutdownHow, SocketAddr, Stat, Timespec, Whence,
            },
            traits::Abi,
        },
        thread::{Gid, ThreadGuard, Uid},
    },
};
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    sync::{Arc, Weak},
    vec::Vec,
};
use async_trait::async_trait;
use bitflags::bitflags;
use file::File;
use futures::{
    FutureExt,
    future::{Either, select},
};
use inotify::Watchers;

use crate::{
    error::{ErrorKind, Result},
    fs::node::DirEntry,
};

use super::{
    FileSystem,
    node::{
        Link,
        procfs::{FdINode, ProcFs},
    },
    path::Path,
};

mod buf;
pub mod dir;
pub mod epoll;
pub mod eventfd;
pub mod file;
pub mod inotify;
pub mod path;
pub mod pipe;
mod std;
pub mod stream_buffer;
pub mod timer;
pub mod unix_socket;

pub use buf::{
    KernelReadBuf, KernelWriteBuf, OffsetBuf, ReadBuf, UserBuf, VectoredUserBuf, WriteBuf,
};

pub struct OpenFileDescriptionData<T: ?Sized> {
    /// This reference count counts how many times the file descriptor is
    /// stored in a file descriptor table. When this count reaches zero, the
    /// file descriptor is considered closed. Note that the Arc strong
    /// reference count may still be greater than one. This can happen if the
    /// file descriptor is stored internally within the kernel somewhere e.g.
    /// in a epoll interest list.
    reference_count: AtomicUsize,
    close_notify: Notify,
    ofd: T,
}

impl<T> OpenFileDescriptionData<T>
where
    T: ?Sized,
{
    pub fn is_closed(&self) -> bool {
        self.reference_count.load(Ordering::Relaxed) == 0
    }

    pub async fn wait_until_closed(&self) {
        self.close_notify
            .wait_until(|| (self.reference_count.load(Ordering::Relaxed) == 0).then_some(()))
            .await;
    }
}

impl<T> Deref for OpenFileDescriptionData<T>
where
    T: ?Sized,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.ofd
    }
}

#[derive(Clone)]
pub struct FileDescriptor(Arc<OpenFileDescriptionData<dyn OpenFileDescription>>);

impl FileDescriptor {
    pub fn upgrade(this: &Self) -> Option<StrongFileDescriptor> {
        let mut rc = this.reference_count.load(Ordering::Relaxed);
        loop {
            if rc == 0 {
                break None;
            }
            let res = this.reference_count.compare_exchange(
                rc,
                rc + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            match res {
                Ok(_) => break Some(StrongFileDescriptor(this.clone())),
                Err(new_rc) => rc = new_rc,
            }
        }
    }

    pub fn downgrade(this: &Self) -> WeakFileDescriptor {
        WeakFileDescriptor(Arc::downgrade(&this.0))
    }
}

impl Deref for FileDescriptor {
    type Target = OpenFileDescriptionData<dyn OpenFileDescription>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq for FileDescriptor {
    fn eq(&self, other: &FileDescriptor) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for FileDescriptor {}

impl PartialEq<dyn OpenFileDescription> for FileDescriptor {
    fn eq(&self, other: &dyn OpenFileDescription) -> bool {
        core::ptr::eq(&***self, other)
    }
}

/// Instances of this type are counted in [`OpenFileDescriptionInternal::reference_count`].
/// This prevents fds from being marked as "closed".
pub struct StrongFileDescriptor(FileDescriptor);

impl StrongFileDescriptor {
    pub fn new<T>(ofd: T) -> Self
    where
        T: OpenFileDescription,
    {
        Self(FileDescriptor(Arc::new(OpenFileDescriptionData {
            reference_count: AtomicUsize::new(1),
            close_notify: Notify::new(),
            ofd,
        })))
    }

    pub fn new_cyclic<T>(f: impl FnOnce(&Weak<OpenFileDescriptionData<T>>) -> T) -> Self
    where
        T: OpenFileDescription,
    {
        Self(FileDescriptor(Arc::new_cyclic(|this| {
            OpenFileDescriptionData {
                reference_count: AtomicUsize::new(1),
                close_notify: Notify::new(),
                ofd: f(this),
            }
        })))
    }

    pub fn new_cyclic_with_data<T>(
        f: impl FnOnce(&Weak<OpenFileDescriptionData<T>>) -> T,
    ) -> (Self, Arc<OpenFileDescriptionData<T>>)
    where
        T: OpenFileDescription,
    {
        let mut weak = None;
        let this = Self(FileDescriptor(Arc::new_cyclic(|this| {
            weak = Some(this.clone());
            OpenFileDescriptionData {
                reference_count: AtomicUsize::new(1),
                close_notify: Notify::new(),
                ofd: f(this),
            }
        })));
        let typed = weak.unwrap().upgrade().unwrap();
        (this, typed)
    }

    pub fn downgrade(this: &Self) -> FileDescriptor {
        this.0.clone()
    }
}

impl<T> From<T> for StrongFileDescriptor
where
    T: OpenFileDescription,
{
    fn from(ofd: T) -> Self {
        Self::new(ofd)
    }
}

impl Deref for StrongFileDescriptor {
    type Target = FileDescriptor;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Clone for StrongFileDescriptor {
    fn clone(&self) -> Self {
        let val = self.0.0.reference_count.fetch_add(1, Ordering::Relaxed);
        debug_assert_ne!(val, 0);
        Self(self.0.clone())
    }
}

impl Drop for StrongFileDescriptor {
    fn drop(&mut self) {
        let val = self.0.0.reference_count.fetch_sub(1, Ordering::Relaxed);
        debug_assert_ne!(val, 0);
        if val == 1 {
            self.close_notify.notify();
        }
    }
}

pub struct WeakFileDescriptor(Weak<OpenFileDescriptionData<dyn OpenFileDescription>>);

impl WeakFileDescriptor {
    pub fn upgrade(&self) -> Option<FileDescriptor> {
        self.0.upgrade().map(FileDescriptor)
    }
}

impl PartialEq<FileDescriptor> for WeakFileDescriptor {
    fn eq(&self, other: &FileDescriptor) -> bool {
        core::ptr::addr_eq(self.0.as_ptr(), Arc::as_ptr(&other.0))
    }
}

impl PartialEq<dyn OpenFileDescription> for WeakFileDescriptor {
    fn eq(&self, other: &dyn OpenFileDescription) -> bool {
        const OFFSET: isize = offset_of!(OpenFileDescriptionData::<()>, ofd) as isize;
        let ptr = self.0.as_ptr() as *const c_void;
        let ptr = unsafe { ptr.byte_offset(OFFSET) };
        core::ptr::addr_eq(ptr, other)
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
        fd: impl Into<StrongFileDescriptor>,
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
        fd: impl Into<StrongFileDescriptor>,
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
        fd: impl Into<StrongFileDescriptor>,
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
            .map(|fd| (StrongFileDescriptor::downgrade(&fd.fd), fd.flags))
            .ok_or(err!(BadF))
    }

    pub fn get_strong(&self, fd_num: FdNum) -> Result<StrongFileDescriptor> {
        self.get_strong_with_flags(fd_num).map(|(fd, _flags)| fd)
    }

    pub fn get_strong_with_flags(&self, fd_num: FdNum) -> Result<(StrongFileDescriptor, FdFlags)> {
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
            StrongFileDescriptor::downgrade(&entry.fd),
            entry.file_lock_record.get().clone(),
            entry.watchers.clone(),
        )))
    }

    #[cfg(not(feature = "harden"))]
    pub fn dump(&self, indent: usize, mut write: impl fmt::Write) -> fmt::Result {
        writeln!(write, "{:indent$}fd table:", "")?;
        let indent = indent + 2;
        for (num, fd) in self.table.lock().iter() {
            writeln!(
                write,
                "{:indent$}{num} {} {:?} ino={:?}",
                "",
                fd.fd.type_name(),
                fd.flags,
                fd.fd.stat().map(|stat| stat.ino)
            )?;
        }
        Ok(())
    }
}

struct FileDescriptorTableEntry {
    ino: u64,
    fd: StrongFileDescriptor,
    flags: FdFlags,
    file_lock_record: LazyFileLockRecord,
    watchers: Arc<Watchers>,
}

impl FileDescriptorTableEntry {
    fn new(fd: StrongFileDescriptor, flags: FdFlags) -> Self {
        Self {
            ino: new_ino(),
            fd,
            flags,
            file_lock_record: LazyFileLockRecord::new(),
            watchers: Arc::new(Watchers::new()),
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

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        let _ = buf;
        bail!(Inval)
    }

    fn write(&self, buf: &dyn WriteBuf) -> Result<usize> {
        let _ = buf;
        bail!(Inval)
    }

    fn seek(&self, offset: usize, whence: Whence) -> Result<usize> {
        let _ = offset;
        let _ = whence;
        bail!(SPipe)
    }

    fn pread(&self, pos: usize, buf: &mut dyn ReadBuf) -> Result<usize> {
        let _ = pos;
        let _ = buf;
        bail!(Inval)
    }

    fn pwrite(&self, pos: usize, buf: &dyn WriteBuf) -> Result<usize> {
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

    fn allocate(&self, mode: FallocateMode, offset: usize, len: usize) -> Result<()> {
        let _ = mode;
        let _ = offset;
        let _ = len;
        bail!(BadF)
    }

    fn bind(&self, addr: SocketAddr, ctx: &mut FileAccessContext) -> Result<()> {
        let _ = addr;
        let _ = ctx;
        bail!(NotSock)
    }

    fn listen(&self, backlog: usize) -> Result<()> {
        let _ = backlog;
        bail!(NotSock)
    }

    fn accept(&self, flags: Accept4Flags) -> Result<(StrongFileDescriptor, SocketAddr)> {
        let _ = flags;
        bail!(NotSock)
    }

    async fn connect(&self, addr: SocketAddr, _: &mut FileAccessContext) -> Result<()> {
        let _ = addr;
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

    fn get_socket_name(&self) -> Result<SocketAddr> {
        bail!(NotSock)
    }

    fn get_peer_name(&self) -> Result<SocketAddr> {
        bail!(NotSock)
    }

    fn send_to(
        &self,
        buf: &dyn WriteBuf,
        flags: SentToFlags,
        addr: Option<SocketAddr>,
    ) -> Result<usize> {
        let _ = buf;
        let _ = flags;
        let _ = addr;
        bail!(Inval)
    }

    fn send_msg(
        &self,
        vm: &VirtualMemory,
        abi: Abi,
        msg_hdr: &mut MsgHdr,
        fdtable: &FileDescriptorTable,
    ) -> Result<usize> {
        let _ = vm;
        let _ = abi;
        let _ = msg_hdr;
        let _ = fdtable;
        bail!(Inval)
    }

    fn recv_from(
        &self,
        buf: &mut dyn ReadBuf,
        flags: RecvFromFlags,
    ) -> Result<(usize, Option<SocketAddr>)> {
        let _ = buf;
        let _ = flags;
        bail!(Inval)
    }

    fn recv_msg(
        &self,
        vm: &VirtualMemory,
        abi: Abi,
        msg_hdr: &mut MsgHdr,
        fdtable: &FileDescriptorTable,
        no_file_limit: CurrentNoFileLimit,
    ) -> Result<usize> {
        let _ = vm;
        let _ = abi;
        let _ = msg_hdr;
        let _ = fdtable;
        let _ = no_file_limit;
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

    fn as_dir(&self, ctx: &mut FileAccessContext) -> Result<Link> {
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

    fn futexes(&self) -> Option<Arc<Futexes>> {
        None
    }

    async fn epoll_wait(&self, max_events: usize) -> Result<Vec<EpollEvent>> {
        let _ = max_events;
        bail!(Inval)
    }

    fn epoll_add(&self, fd: &FileDescriptor, event: EpollEvent) -> Result<()> {
        let _ = fd;
        let _ = event;
        bail!(Inval)
    }

    fn epoll_del(&self, fd: &dyn OpenFileDescription) -> Result<()> {
        let _ = fd;
        bail!(Inval)
    }

    fn epoll_mod(&self, fd: &dyn OpenFileDescription, event: EpollEvent) -> Result<()> {
        let _ = fd;
        let _ = event;
        bail!(Inval)
    }

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents>;

    fn epoll_ready(&self, events: Events) -> Result<Option<NonEmptyEvents>> {
        let _ = events;
        bail!(Perm)
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents;

    /// Returns a future that is ready when the file descriptor can process
    /// write of `size` bytes. Note that this doesn't necessairly mean that all
    /// `size` bytes will be written.
    async fn ready_for_write(&self, count: usize) {
        let _ = count;
        self.ready(Events::WRITE).await;
    }

    fn add_watch(&self, node: DynINode, mask: InotifyMask) -> Result<u32> {
        let _ = node;
        let _ = mask;
        bail!(Inval)
    }

    fn rm_watch(&self, wd: u32) -> Result<()> {
        let _ = wd;
        bail!(Inval)
    }

    fn file_lock(&self) -> Result<&FileLock>;

    /// For path file descriptors, this method should return the pointed to
    /// link.
    fn path_fd_link(&self) -> Option<&Link> {
        None
    }

    fn as_tty(&self) -> Option<Arc<PtyData>> {
        None
    }

    fn set_time(&self, flags: SetTimeFlags, new: ITimerspec) -> Result<ITimerspec> {
        let _ = flags;
        let _ = new;
        bail!(Inval)
    }

    fn ioctl(
        &self,
        thread: &mut ThreadGuard,
        cmd: u32,
        arg: Pointer<c_void>,
        abi: Abi,
    ) -> Result<u64> {
        common_ioctl(self, thread, cmd, arg, abi)
    }

    #[cfg(not(feature = "harden"))]
    fn type_name(&self) -> &'static str {
        core::any::type_name::<Self>()
    }
}

pub fn common_ioctl<O>(
    fd: &O,
    thread: &mut ThreadGuard,
    cmd: u32,
    arg: Pointer<c_void>,
    _: Abi,
) -> Result<u64>
where
    O: OpenFileDescription + ?Sized,
{
    match cmd {
        0x5421 => {
            // FIONBIO
            let addr = arg.cast::<u32>();
            let val = thread.virtual_memory().read(addr)? != 0;
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

#[derive(Clone, Copy)]
pub struct NonEmptyEvents(NonZeroU8);

impl NonEmptyEvents {
    pub const READ: Self = Self::new(Events::READ).unwrap();
    pub const WRITE: Self = Self::new(Events::WRITE).unwrap();

    pub const fn new(events: Events) -> Option<Self> {
        if let Some(bits) = NonZeroU8::new(events.bits()) {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub fn zip(lhs: Option<Self>, rhs: Option<Self>) -> Option<Self> {
        match (lhs, rhs) {
            (Some(lhs), Some(rhs)) => Some(lhs | rhs),
            (Some(events), None) | (None, Some(events)) => Some(events),
            (None, None) => None,
        }
    }

    pub async fn select(lhs: impl Future<Output = Self>, rhs: impl Future<Output = Self>) -> Self {
        let lhs = pin!(lhs);
        let rhs = pin!(rhs);
        let res = select(lhs, rhs).await;
        match res {
            Either::Left((mut events, fut)) => {
                if let Some(more) = fut.now_or_never() {
                    events |= more;
                }
                events
            }
            Either::Right((mut events, fut)) => {
                if let Some(more) = fut.now_or_never() {
                    events |= more;
                }
                events
            }
        }
    }
}

impl From<NonEmptyEvents> for Events {
    fn from(value: NonEmptyEvents) -> Self {
        Self::from_bits_retain(value.0.get())
    }
}

impl BitOr for NonEmptyEvents {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for NonEmptyEvents {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
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
                fd.ready(events).await;
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
                fd.ready_for_write(count).await;
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
            let wait = non_blocking.not().then(|| self.record.notify.wait());

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
