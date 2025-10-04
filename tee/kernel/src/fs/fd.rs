use alloc::{
    boxed::Box,
    collections::{BTreeMap, btree_map::Entry},
    format,
    sync::{Arc, Weak},
    vec::Vec,
};
#[cfg(not(feature = "harden"))]
use core::fmt;
use core::{
    cmp,
    ffi::c_void,
    mem::offset_of,
    num::{NonZeroU8, NonZeroUsize},
    ops::{BitOr, BitOrAssign, Bound, Deref, Not},
    pin::pin,
    ptr::NonNull,
    sync::atomic::{AtomicI64, AtomicUsize, Ordering},
};

use async_trait::async_trait;
use bitflags::bitflags;
use futures::{
    FutureExt,
    future::{Either, select},
};

use self::{file::File, inotify::Watchers};
use crate::{
    char_dev::char::PtyData,
    error::{ErrorKind, Result, bail, ensure, err},
    fs::{
        FileSystem,
        node::{
            DirEntry, DirEntryName, DynINode, FileAccessContext, Link, OffsetDirEntry, new_ino,
            procfs::{FdINode, FdInfoFile, ProcFs},
        },
        path::{FileName, Path},
    },
    memory::page::KernelPage,
    rt::notify::Notify,
    spin::{
        lazy::Lazy,
        mutex::{Mutex, MutexGuard},
    },
    user::{
        futex::Futexes,
        memory::{MappingCtrl, VirtualMemory},
        process::limits::CurrentNoFileLimit,
        syscall::{
            args::{
                Accept4Flags, EpollEvent, FallocateMode, FdNum, FileMode, FileType, ITimerspec,
                InotifyMask, MsgHdr, OpenFlags, Pointer, RecvFromFlags, SendMsgFlags, SentToFlags,
                SetTimeFlags, ShutdownHow, SocketAddr, Stat, Timespec, Whence,
            },
            traits::Abi,
        },
        thread::{Gid, ThreadGuard, Uid},
    },
};

mod buf;
pub mod dir;
pub mod epoll;
pub mod eventfd;
pub mod file;
pub mod inotify;
pub mod mem;
pub mod path;
pub mod pipe;
mod std;
pub mod stream_buffer;
pub mod timer;
pub mod unix_socket;

pub use self::buf::{
    KernelPageWriteBuf, KernelReadBuf, KernelWriteBuf, OffsetBuf, ReadBuf, UserBuf,
    VectoredUserBuf, WriteBuf,
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

            // Release all unix locks held by the fd.
            if let Ok(record) = self.ofd.unix_file_lock_record() {
                let owner = UnixLockOwner::ofd(&self.ofd);
                record.unlock_all(owner);
            }
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
    internal: Mutex<InternalFileDescriptorTable>,
}

impl FileDescriptorTable {
    pub const fn empty() -> Self {
        Self {
            internal: Mutex::new(InternalFileDescriptorTable::empty()),
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

    pub fn insert_after(
        &self,
        min: i32,
        fd: impl Into<StrongFileDescriptor>,
        flags: impl Into<FdFlags>,
        no_file_limit: CurrentNoFileLimit,
    ) -> Result<FdNum> {
        self.internal
            .lock()
            .insert_after(min, fd, flags, no_file_limit)
    }

    pub fn replace(
        &self,
        fd_num: FdNum,
        fd: impl Into<StrongFileDescriptor>,
        flags: impl Into<FdFlags>,
        no_file_limit: CurrentNoFileLimit,
    ) -> Result<()> {
        self.internal
            .lock()
            .replace(fd_num, fd, flags, no_file_limit)
    }

    pub fn get(&self, fd_num: FdNum) -> Result<FileDescriptor> {
        self.get_with_flags(fd_num).map(|(fd, _flags)| fd)
    }

    pub fn get_with_flags(&self, fd_num: FdNum) -> Result<(FileDescriptor, FdFlags)> {
        self.internal.lock().get_with_flags(fd_num)
    }

    pub fn get_strong(&self, fd_num: FdNum) -> Result<StrongFileDescriptor> {
        self.get_strong_with_flags(fd_num).map(|(fd, _flags)| fd)
    }

    pub fn get_strong_with_flags(&self, fd_num: FdNum) -> Result<(StrongFileDescriptor, FdFlags)> {
        self.internal.lock().get_strong_with_flags(fd_num)
    }

    pub fn set_flags(&self, fd_num: FdNum, flags: FdFlags) -> Result<()> {
        self.internal.lock().set_flags(fd_num, flags)
    }

    pub fn close(&self, fd_num: FdNum) -> Result<()> {
        self.internal.lock().close(fd_num)
    }

    pub fn prepare_for_execve(&self) -> Self {
        Self {
            internal: Mutex::new(self.internal.lock().prepare_for_execve()),
        }
    }

    pub fn list_entries(&self) -> Vec<DirEntry> {
        self.internal.lock().list_entries()
    }

    pub fn list_fdinfo_entries(&self) -> Vec<DirEntry> {
        self.internal.lock().list_fdinfo_entries()
    }

    pub fn get_node(&self, fs: Arc<ProcFs>, fd_num: FdNum, uid: Uid, gid: Gid) -> Result<DynINode> {
        self.internal.lock().get_node(fs, fd_num, uid, gid)
    }

    pub fn get_info_node(
        &self,
        fs: Arc<ProcFs>,
        fd_num: FdNum,
        uid: Uid,
        gid: Gid,
    ) -> Result<DynINode> {
        self.internal.lock().get_info_node(fs, fd_num, uid, gid)
    }

    #[cfg(not(feature = "harden"))]
    pub fn dump(&self, indent: usize, write: impl fmt::Write) -> fmt::Result {
        self.internal.lock().dump(indent, write)
    }
}

impl Clone for FileDescriptorTable {
    fn clone(&self) -> Self {
        Self {
            internal: self.internal.clone(),
        }
    }
}

struct InternalFileDescriptorTable {
    table: BTreeMap<i32, FileDescriptorTableEntry>,
}

impl InternalFileDescriptorTable {
    pub const fn empty() -> Self {
        Self {
            table: BTreeMap::new(),
        }
    }

    fn find_free_fd_num(&self, min: i32, no_file_limit: CurrentNoFileLimit) -> Result<i32> {
        ensure!(min < no_file_limit.get() as i32, Inval);
        let min = cmp::max(0, min);

        let fd_iter = self.table.keys().copied().skip_while(|i| *i < min);
        let mut counter_iter = min..no_file_limit.get() as i32;

        fd_iter
            .zip(counter_iter.by_ref())
            .find(|(fd, counter)| counter < fd)
            .map(|(_, counter)| counter)
            .or_else(|| counter_iter.next())
            .ok_or(err!(Mfile))
    }

    pub fn insert_after(
        &mut self,
        min: i32,
        fd: impl Into<StrongFileDescriptor>,
        flags: impl Into<FdFlags>,
        no_file_limit: CurrentNoFileLimit,
    ) -> Result<FdNum> {
        let fd_num = self.find_free_fd_num(min, no_file_limit)?;
        self.table.insert(
            fd_num,
            FileDescriptorTableEntry::new(fd.into(), flags.into()),
        );
        Ok(FdNum::new(fd_num))
    }

    pub fn replace(
        &mut self,
        fd_num: FdNum,
        fd: impl Into<StrongFileDescriptor>,
        flags: impl Into<FdFlags>,
        no_file_limit: CurrentNoFileLimit,
    ) -> Result<()> {
        ensure!(fd_num.get() < no_file_limit.get() as i32, BadF);

        // Close the previous ofd. If there was none, that's fine too.
        let _ = self.close(fd_num);

        self.table.insert(
            fd_num.get(),
            FileDescriptorTableEntry::new(fd.into(), flags.into()),
        );

        Ok(())
    }

    pub fn get_with_flags(&self, fd_num: FdNum) -> Result<(FileDescriptor, FdFlags)> {
        self.table
            .get(&fd_num.get())
            .map(|fd| (StrongFileDescriptor::downgrade(&fd.fd), fd.flags))
            .ok_or(err!(BadF))
    }

    pub fn get_strong_with_flags(&self, fd_num: FdNum) -> Result<(StrongFileDescriptor, FdFlags)> {
        self.table
            .get(&fd_num.get())
            .map(|fd| (fd.fd.clone(), fd.flags))
            .ok_or(err!(BadF))
    }

    pub fn set_flags(&mut self, fd_num: FdNum, flags: FdFlags) -> Result<()> {
        let entry = self.table.get_mut(&fd_num.get()).ok_or(err!(BadF))?;
        entry.flags = flags;
        Ok(())
    }

    pub fn close(&mut self, fd_num: FdNum) -> Result<()> {
        let entry = self.table.remove(&fd_num.get()).ok_or(err!(BadF))?;
        if let Ok(record) = entry.fd.unix_file_lock_record() {
            record.unlock_all(UnixLockOwner::fdtable(NonNull::from_ref(self)));
        }
        Ok(())
    }

    pub fn prepare_for_execve(&self) -> Self {
        // Unshare the entries and skip any entries with CLOEXEC set.
        Self {
            table: self
                .table
                .iter()
                .filter(|(_, entry)| !entry.flags.contains(FdFlags::CLOEXEC))
                .map(|(fd, entry)| {
                    (
                        *fd,
                        FileDescriptorTableEntry::new(entry.fd.clone(), entry.flags),
                    )
                })
                .collect(),
        }
    }

    pub fn list_entries(&self) -> Vec<DirEntry> {
        self.table
            .iter()
            .map(|(num, entry)| DirEntry {
                ino: entry.symlink_ino,
                ty: FileType::Link,
                name: DirEntryName::FileName(
                    FileName::new(format!("{num}").as_bytes())
                        .unwrap()
                        .into_owned(),
                ),
            })
            .collect()
    }

    pub fn list_fdinfo_entries(&self) -> Vec<DirEntry> {
        self.table
            .iter()
            .map(|(num, entry)| DirEntry {
                ino: entry.fdinfo_ino,
                ty: FileType::File,
                name: DirEntryName::FileName(
                    FileName::new(format!("{num}").as_bytes())
                        .unwrap()
                        .into_owned(),
                ),
            })
            .collect()
    }

    pub fn get_node(&self, fs: Arc<ProcFs>, fd_num: FdNum, uid: Uid, gid: Gid) -> Result<DynINode> {
        let entry = self.table.get(&fd_num.get()).ok_or(err!(NoEnt))?;
        Ok(Arc::new(FdINode::new(
            fs,
            entry.symlink_ino,
            uid,
            gid,
            StrongFileDescriptor::downgrade(&entry.fd),
            entry.symlink_bsd_file_lock_record.get().clone(),
            entry.symlink_watchers.clone(),
        )))
    }

    pub fn get_info_node(
        &self,
        fs: Arc<ProcFs>,
        fd_num: FdNum,
        uid: Uid,
        gid: Gid,
    ) -> Result<DynINode> {
        let entry = self.table.get(&fd_num.get()).ok_or(err!(NoEnt))?;
        Ok(FdInfoFile::new(
            fs,
            entry.symlink_ino,
            uid,
            gid,
            StrongFileDescriptor::downgrade(&entry.fd),
            entry.fdinfo_file_bsd_file_lock_record.get().clone(),
            entry.fdinfo_file_unix_file_lock_record.get().clone(),
            entry.fdinfo_file_watchers.clone(),
        ))
    }

    #[cfg(not(feature = "harden"))]
    pub fn dump(&self, indent: usize, mut write: impl fmt::Write) -> fmt::Result {
        writeln!(write, "{:indent$}fd table:", "")?;
        let indent = indent + 2;
        for (num, fd) in self.table.iter() {
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

impl Clone for InternalFileDescriptorTable {
    fn clone(&self) -> Self {
        Self {
            table: self
                .table
                .iter()
                .map(|(num, fd)| (*num, FileDescriptorTableEntry::new(fd.fd.clone(), fd.flags)))
                .collect(),
        }
    }
}

impl Drop for InternalFileDescriptorTable {
    fn drop(&mut self) {
        // Close all file descriptors. "Closing" a file descriptor has some
        // more side-effects like releasing all unix locks.
        while let Some(first) = self.table.first_entry() {
            let fd_num = *first.key();
            self.close(FdNum::new(fd_num)).unwrap();
        }
    }
}

struct FileDescriptorTableEntry {
    symlink_ino: u64,
    fdinfo_ino: u64,
    fd: StrongFileDescriptor,
    flags: FdFlags,
    symlink_bsd_file_lock_record: LazyBsdFileLockRecord,
    symlink_watchers: Arc<Watchers>,
    fdinfo_file_bsd_file_lock_record: LazyBsdFileLockRecord,
    fdinfo_file_unix_file_lock_record: LazyUnixFileLockRecord,
    fdinfo_file_watchers: Arc<Watchers>,
}

impl FileDescriptorTableEntry {
    fn new(fd: StrongFileDescriptor, flags: FdFlags) -> Self {
        Self {
            symlink_ino: new_ino(),
            fdinfo_ino: new_ino(),
            fd,
            flags,
            symlink_bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            symlink_watchers: Arc::new(Watchers::new()),
            fdinfo_file_bsd_file_lock_record: LazyBsdFileLockRecord::new(),
            fdinfo_file_unix_file_lock_record: LazyUnixFileLockRecord::new(),
            fdinfo_file_watchers: Arc::new(Watchers::new()),
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

    fn write(&self, buf: &dyn WriteBuf, ctx: &FileAccessContext) -> Result<usize> {
        let _ = buf;
        let _ = ctx;
        bail!(Inval)
    }

    fn seek(&self, offset: usize, whence: Whence, ctx: &mut FileAccessContext) -> Result<usize> {
        let _ = offset;
        let _ = whence;
        let _ = ctx;
        bail!(SPipe)
    }

    fn pread(&self, pos: usize, buf: &mut dyn ReadBuf) -> Result<usize> {
        let _ = pos;
        let _ = buf;
        bail!(Inval)
    }

    fn pwrite(&self, pos: usize, buf: &dyn WriteBuf, ctx: &FileAccessContext) -> Result<usize> {
        let _ = pos;
        let _ = buf;
        let _ = ctx;
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

    fn listen(&self, backlog: usize, ctx: &FileAccessContext) -> Result<()> {
        let _ = backlog;
        let _ = ctx;
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
        ctx: &FileAccessContext,
    ) -> Result<usize> {
        let _ = buf;
        let _ = flags;
        let _ = addr;
        let _ = ctx;
        bail!(NotSock)
    }

    fn send_msg(
        &self,
        vm: &VirtualMemory,
        abi: Abi,
        msg_hdr: &mut MsgHdr,
        flags: SendMsgFlags,
        fdtable: &FileDescriptorTable,
        ctx: &FileAccessContext,
    ) -> Result<usize> {
        let _ = vm;
        let _ = abi;
        let _ = msg_hdr;
        let _ = flags;
        let _ = fdtable;
        let _ = ctx;
        bail!(NotSock)
    }

    fn recv_from(
        &self,
        buf: &mut dyn ReadBuf,
        flags: RecvFromFlags,
    ) -> Result<(usize, Option<SocketAddr>)> {
        let _ = buf;
        let _ = flags;
        bail!(NotSock)
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
        bail!(NotSock)
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

    fn deleted(&self) -> bool {
        false
    }

    fn as_dir(&self, ctx: &mut FileAccessContext) -> Result<Link> {
        let _ = ctx;
        bail!(NotDir)
    }

    fn read_link(&self, ctx: &FileAccessContext) -> Result<Path> {
        let _ = ctx;
        bail!(NoEnt)
    }

    fn getdents64(
        &self,
        capacity: usize,
        ctx: &mut FileAccessContext,
    ) -> Result<Vec<OffsetDirEntry>> {
        let _ = capacity;
        let _ = ctx;
        bail!(NotDir)
    }

    fn link_into(
        &self,
        new_dir: DynINode,
        newname: FileName<'static>,
        ctx: &FileAccessContext,
    ) -> Result<()> {
        let _ = new_dir;
        let _ = newname;
        let _ = ctx;
        bail!(XDev)
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

    fn register(&self, mapping_ctrl: &MappingCtrl) {
        let _ = mapping_ctrl;
    }

    fn unregister(&self, mapping_ctrl: &MappingCtrl) {
        let _ = mapping_ctrl;
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

    fn bsd_file_lock(&self) -> Result<&BsdFileLock>;

    fn unix_file_lock_record(&self) -> Result<&Arc<UnixFileLockRecord>> {
        bail!(BadF)
    }

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

pub struct LazyBsdFileLockRecord {
    bsd_file_lock_record: Lazy<Arc<BsdFileLockRecord>>,
}

impl LazyBsdFileLockRecord {
    pub const fn new() -> Self {
        Self {
            bsd_file_lock_record: Lazy::new(Default::default),
        }
    }

    pub fn get(&self) -> &Arc<BsdFileLockRecord> {
        &self.bsd_file_lock_record
    }
}

pub struct BsdFileLockRecord {
    /// -1  => exclusive
    /// 0   => unlocked
    /// 1.. => shared
    counter: AtomicI64,
    notify: Notify,
}

impl BsdFileLockRecord {
    pub fn new() -> Self {
        Self {
            counter: AtomicI64::new(0),
            notify: Notify::new(),
        }
    }
}

impl Default for BsdFileLockRecord {
    fn default() -> Self {
        Self::new()
    }
}

pub struct BsdFileLock {
    record: Arc<BsdFileLockRecord>,
    state: Mutex<FileLockState>,
}

impl BsdFileLock {
    pub fn new(record: Arc<BsdFileLockRecord>) -> Self {
        Self {
            record,
            state: Mutex::new(FileLockState::Unlocked),
        }
    }

    pub fn anonymous() -> Self {
        Self::new(Arc::new(BsdFileLockRecord::new()))
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

impl Drop for BsdFileLock {
    fn drop(&mut self) {
        self.unlock();
    }
}

enum FileLockState {
    Unlocked,
    Shared,
    Exclusive,
}

pub struct LazyUnixFileLockRecord {
    unix_file_lock_record: Lazy<Arc<UnixFileLockRecord>>,
}

impl LazyUnixFileLockRecord {
    pub const fn new() -> Self {
        Self {
            unix_file_lock_record: Lazy::new(Default::default),
        }
    }

    pub fn get(&self) -> &Arc<UnixFileLockRecord> {
        &self.unix_file_lock_record
    }
}

pub struct UnixFileLockRecord {
    notify: Notify,
    state: Mutex<UnixFileLockRecordState>,
}

impl UnixFileLockRecord {
    pub fn new() -> Self {
        Self {
            notify: Notify::new(),
            state: Mutex::new(UnixFileLockRecordState::new()),
        }
    }

    pub fn find_conflict(&self, lock: UnixLock) -> Option<UnixLock> {
        let guard = self.state.lock();
        guard.find_conflict(lock)
    }

    /// Try to acquire a lock. If there's a conflicting lock, return it.
    pub fn lock(&self, lock: UnixLock) -> Result<(), ()> {
        if lock.len == 0 {
            return Ok(());
        }

        let mut guard = self.state.lock();
        guard.lock(lock)?;
        self.notify.notify();
        Ok(())
    }

    /// Try to acquire a lock. If there's a conflicting lock, return it.
    pub async fn lock_wait(&self, lock: UnixLock) {
        self.notify.wait_until(|| self.lock(lock).ok()).await;
    }

    /// Release a lock.
    pub fn unlock(&self, owner: UnixLockOwner, start: u64, len: u64) {
        if len == 0 {
            return;
        }

        let mut guard = self.state.lock();
        guard.unlock(owner, start, len);
        drop(guard);
        self.notify.notify();
    }

    /// Release a lock.
    pub fn unlock_all(&self, owner: UnixLockOwner) {
        let mut guard = self.state.lock();
        guard.unlock_all(owner);
        drop(guard);
        self.notify.notify();
    }
}

impl Default for UnixFileLockRecord {
    fn default() -> Self {
        Self::new()
    }
}

struct UnixFileLockRecordState {
    locks: BTreeMap<(u64, UnixLockOwner), UnixLockData>,
}

impl UnixFileLockRecordState {
    fn new() -> Self {
        Self {
            locks: BTreeMap::new(),
        }
    }

    /// Try to find a lock that conflicts with the given new lock.
    pub fn find_conflict(&self, lock: UnixLock) -> Option<UnixLock> {
        debug_assert_ne!(lock.len, 0);

        let end = lock.start + lock.len;
        self.locks
            .range(..(end, lock.owner))
            .rev()
            // Only consider locks that overlap.
            .filter(|((start, _), l)| *start < end && lock.start < (*start + l.len))
            // Only consider locks by other owners.
            .filter(|((_, owner), _)| *owner != lock.owner)
            // Check the lock type to determine if there's a conflict.
            .find(|(_, l)| l.ty == UnixLockType::Write || lock.ty == UnixLockType::Write)
            .map(|(&(start, owner), l)| UnixLock {
                owner,
                start,
                len: l.len,
                ty: l.ty,
                pid: l.pid,
            })
    }

    /// Take a lock.
    pub fn lock(&mut self, mut lock: UnixLock) -> Result<(), ()> {
        debug_assert_ne!(lock.len, 0);

        if self.find_conflict(lock).is_some() {
            return Err(());
        }

        // Remove all overlapping locks.
        self.unlock(lock.owner, lock.start, lock.len);

        // Coalesce with a lock starting where this new lock ends if it has the
        // same type and pid.
        let end = lock.start + lock.len;
        if let Entry::Occupied(entry) = self.locks.entry((end, lock.owner))
            && entry.get().ty == lock.ty
            && entry.get().pid == lock.pid
        {
            let removed = entry.remove();
            lock.len += removed.len;
        }

        // Try to find a lock ending where this new lock starts.
        let mut cursor = self
            .locks
            .upper_bound_mut(Bound::Excluded(&(lock.start, lock.owner)));
        let prev = loop {
            let Some((&(current_start, current_owner), l)) = cursor.peek_prev() else {
                break None;
            };

            // Skip over all locks by different owners.
            if current_owner != lock.owner {
                cursor.prev().unwrap();
                continue;
            }

            let current_end = current_start + l.len;
            if current_end == lock.start {
                break Some(l);
            } else {
                debug_assert!(current_end < lock.start);
                break None;
            }
        };

        // If the previous lock has the same type and pid, coalesce.
        if let Some(l) = prev.filter(|l| l.ty == lock.ty && l.pid == lock.pid) {
            l.len += lock.len;
        } else {
            // Otherwise create a new entry.
            self.locks.insert(
                (lock.start, lock.owner),
                UnixLockData {
                    len: lock.len,
                    ty: lock.ty,
                    pid: lock.pid,
                },
            );
        }

        Ok(())
    }

    // Release a lock.
    pub fn unlock(&mut self, owner: UnixLockOwner, start: u64, len: u64) {
        debug_assert_ne!(len, 0);

        // Try to find a lock that starts before `end` and ends after `end`. If
        // there is such a lock, split it in two.
        let end = start + len;
        let mut cursor = self.locks.upper_bound_mut(Bound::Excluded(&(end, owner)));
        loop {
            let Some((&(current_start, current_owner), lock)) = cursor.peek_prev() else {
                return;
            };

            // Skip over all locks by different owners.
            if current_owner != owner {
                cursor.prev().unwrap();
                continue;
            }

            let current_end = current_start + lock.len;
            let Some(new_len) = current_end.checked_sub(end).filter(|&len| len > 0) else {
                break;
            };

            // Shrink the existing lock ...
            lock.len = end - current_start;

            // ... and add a new one after it.
            let new_data = UnixLockData {
                len: new_len,
                ty: lock.ty,
                pid: lock.pid,
            };
            cursor.insert_after((end, owner), new_data).unwrap();
            break;
        }

        // At this point, we know that all locks end at the same offset or
        // before `end`. Remove all locks that start at or after `start`.
        loop {
            let Some((&(current_start, current_owner), _)) = cursor.peek_prev() else {
                return;
            };

            // Skip over all locks by different owners.
            if current_owner != owner {
                cursor.prev().unwrap();
                continue;
            }

            if current_start < start {
                break;
            }

            cursor.remove_prev().unwrap();
        }

        // At this point, we know that all locks end at the same offset or
        // before `end` and start before `start`. If there's a lock that starts
        // before `start` and ends after `start`, truncate it.
        while let Some((&(current_start, current_owner), lock)) = cursor.peek_prev() {
            if current_owner != owner {
                cursor.prev().unwrap();
                continue;
            }

            let current_end = current_start + lock.len;
            if current_end < start {
                break;
            }

            let Some(new_len) = start.checked_sub(current_start).filter(|&len| len > 0) else {
                break;
            };
            lock.len = new_len;
            break;
        }
    }

    /// Release all locks by the given owner.
    pub fn unlock_all(&mut self, owner: UnixLockOwner) {
        self.locks.retain(|&(_, o), _| o != owner);
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct UnixLockData {
    len: u64,
    ty: UnixLockType,
    pid: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UnixLock {
    pub owner: UnixLockOwner,
    pub ty: UnixLockType,
    pub start: u64,
    pub len: u64,
    pub pid: Option<u32>,
}

/// An opaque handle identifying the owner of a lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixLockOwner(NonZeroUsize);

impl UnixLockOwner {
    /// Create an ownership instance associated with a process.
    ///
    /// Despite the name and all the documentation around this, the ownership
    /// is actually tied to the file descriptor table, not the process. If the
    /// file descriptor table is shared between multiple processes, locks will
    /// be shared between these processes even though locks are ostensibly tied
    /// to a single process.
    pub fn process(fdtable: &FileDescriptorTable) -> Self {
        let ptr = fdtable.internal.as_ptr_mut();
        let ptr = unsafe { NonNull::new_unchecked(ptr) };
        Self::fdtable(ptr)
    }

    /// Create an ownership instance associated with a process.
    ///
    /// See [`Self::process`].
    fn fdtable(fdtable: NonNull<InternalFileDescriptorTable>) -> Self {
        Self(fdtable.addr())
    }

    /// Create an ownership instance associated with a open file description.
    pub fn ofd(fd: &dyn OpenFileDescription) -> Self {
        Self(NonNull::from(fd).addr())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnixLockType {
    Read,
    Write,
}
