use alloc::{sync::Arc, vec::Vec};
use core::{
    cmp::{self, Reverse},
    ffi::c_void,
    fmt::{self, Display},
    marker::PhantomData,
    net::{self, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    ops::Add,
};

use bit_field::BitField;
use bytemuck::{CheckedBitPattern, NoUninit, Pod, Zeroable, checked};
use usize_conversions::FromUsize;
use x86_64::VirtAddr;

use self::pointee::{Pointee, PrimitivePointee, Timespec32};
use crate::{
    error::{Error, Result, bail, ensure, err},
    fs::{
        fd::{Events, FdFlags, FileDescriptorTable},
        node::FileAccessContext,
        path::Path,
    },
    user::{
        memory::VirtualMemory,
        syscall::traits::Abi,
        thread::{Gid, SigInfo, Sigset, Thread, ThreadGuard, Uid},
    },
};

pub mod pointee;

pub trait SyscallArg: Send + Copy {
    fn parse(value: u64, abi: Abi) -> Result<Self>;

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        abi: Abi,
        thread: &ThreadGuard<'_>,
    ) -> fmt::Result;
}

/// A thread state that is commonly used by syscall handlers.
/// These states can be used as inputs for syscalls with the `#[state]`
/// attribute.
pub trait ExtractableThreadState: Send {
    fn extract_from_thread(thread: &Arc<Thread>, guard: &ThreadGuard) -> Self;
}

impl ExtractableThreadState for Arc<FileDescriptorTable> {
    fn extract_from_thread(_: &Arc<Thread>, guard: &ThreadGuard) -> Self {
        guard.thread.fdtable.lock().clone()
    }
}

impl ExtractableThreadState for Arc<VirtualMemory> {
    fn extract_from_thread(_: &Arc<Thread>, guard: &ThreadGuard) -> Self {
        guard.virtual_memory().clone()
    }
}

pub trait ThreadArg<'a> {
    fn get(thread: &'a Arc<Thread>) -> Self;
}

impl<'a> ThreadArg<'a> for ThreadGuard<'a> {
    #[cfg_attr(feature = "lock-debugging", track_caller)]
    fn get(thread: &'a Arc<Thread>) -> Self {
        thread.lock()
    }
}

impl<'a> ThreadArg<'a> for &'a Thread {
    fn get(thread: &'a Arc<Thread>) -> Self {
        thread
    }
}

impl<'a> ThreadArg<'a> for &'a Arc<Thread> {
    fn get(thread: &'a Arc<Thread>) -> Self {
        thread
    }
}

macro_rules! bitflags {
    (pub struct $strukt:ident {
        $(
            $(#[$inner:ident $($args:tt)*])*
            const $constant:ident = $expr:expr;
        )*
    }) => {
        bitflags::bitflags! {
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub struct $strukt: u64 {
                $(
                    $(#[$inner $($args)*])*
                    const $constant = $expr;
                )*
            }
        }

        impl Display for $strukt {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{self:?}")
            }
        }

        impl SyscallArg for $strukt {
            fn parse(value: u64, _: Abi) -> Result<Self> {
                Self::from_bits(value).ok_or(err!(Inval))
            }

            fn display(
                f: &mut dyn fmt::Write,
                value: u64,
                _: Abi,
                _thread: &ThreadGuard<'_>,
            ) -> fmt::Result {
                let valid_bits = Self::from_bits_truncate(value);
                let invalid_bits = value & !Self::all().bits();

                write!(f, "{valid_bits}")?;
                if invalid_bits != 0 {
                    write!(f, " | {invalid_bits}")?;
                }
                Ok(())
            }
        }
    };
}

macro_rules! enum_arg {
    (pub enum $enuhm:ident {
        $(
            $variant:ident = $expr:expr,
        )*
    }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $enuhm {
            $(
                $variant = $expr,
            )*
        }

        impl Display for $enuhm {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{self:?}")
            }
        }


        impl SyscallArg for $enuhm {
            fn parse(value: u64, _: Abi) -> Result<Self> {
                match value {
                    $(
                        value if value == Self::$variant as u64 => Ok(Self::$variant),
                    )*
                    _ => bail!(Inval),
                }
            }

            fn display(
                f: &mut dyn fmt::Write,
                value: u64,
                abi: Abi,
                _thread: &ThreadGuard<'_>,
            ) -> fmt::Result {
                match Self::parse(value, abi) {
                    Ok(value) => write!(f, "{value}"),
                    Err(_) => write!(f, "{value}"),
                }
            }
        }
    };
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pointer<T>
where
    T: ?Sized,
{
    value: u64,
    _marker: PhantomData<T>,
}

impl<T> Pointer<T>
where
    T: ?Sized,
{
    pub const NULL: Self = Self::new(0);

    pub const fn new(addr: u64) -> Self {
        Self {
            value: addr,
            _marker: PhantomData,
        }
    }

    pub const fn cast<U>(self) -> Pointer<U> {
        Pointer {
            value: self.value,
            _marker: PhantomData,
        }
    }

    pub fn add(self, count: usize) -> Self
    where
        T: Sized + PrimitivePointee,
    {
        self.bytes_offset(count * size_of::<T>())
    }

    pub fn bytes_offset(self, len: usize) -> Self {
        Self {
            value: self.value + u64::from_usize(len),
            _marker: PhantomData,
        }
    }

    pub fn is_null(&self) -> bool {
        self.value == 0
    }

    pub fn get(self) -> VirtAddr {
        VirtAddr::new(self.value)
    }

    pub fn raw(&self) -> u64 {
        self.value
    }
}

impl<T> Clone for Pointer<T>
where
    T: ?Sized,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Pointer<T> where T: ?Sized {}

impl<T> Display for Pointer<T>
where
    T: ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.value)
    }
}

impl<T> From<VirtAddr> for Pointer<T> {
    fn from(value: VirtAddr) -> Self {
        Self::new(value.as_u64())
    }
}

impl<T> Default for Pointer<T>
where
    T: ?Sized,
{
    fn default() -> Self {
        Self::NULL
    }
}

impl<T> SyscallArg for Pointer<T>
where
    T: Pointee + Send + ?Sized,
{
    fn parse(value: u64, _: Abi) -> Result<Self> {
        Ok(Self {
            value,
            _marker: PhantomData,
        })
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        _: Abi,
        thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        if let Ok(addr) = VirtAddr::try_new(value) {
            T::display(f, addr, thread)
        } else {
            write!(f, "{value:#x} (invalid ptr)")
        }
    }
}

impl SyscallArg for u64 {
    fn parse(value: u64, _: Abi) -> Result<Self> {
        Ok(value)
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        _: Abi,
        _thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        write!(f, "{value}")
    }
}

impl SyscallArg for i64 {
    fn parse(value: u64, abi: Abi) -> Result<Self> {
        match abi {
            Abi::I386 => Ok(value as u32 as i32 as i64),
            Abi::Amd64 => Ok(value as i64),
        }
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        abi: Abi,
        _thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        write!(f, "{}", Self::parse(value, abi).unwrap())
    }
}

impl SyscallArg for u32 {
    fn parse(value: u64, _abi: Abi) -> Result<Self> {
        Ok(value as u32)
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        abi: Abi,
        _thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        write!(f, "{}", Self::parse(value, abi).unwrap())
    }
}

impl SyscallArg for i32 {
    fn parse(value: u64, _abi: Abi) -> Result<Self> {
        Ok(value as u32 as i32)
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        abi: Abi,
        _thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        write!(f, "{}", Self::parse(value, abi).unwrap())
    }
}

bitflags! {
    pub struct OpenFlags {
        const WRONLY = 1 << 0;
        const RDWR = 1 << 1;
        const CREAT = 1 << 6;
        const EXCL = 1 << 7;
        const NOCTTY = 1 << 8;
        const TRUNC = 1 << 9;
        const APPEND = 1 << 10;
        const NONBLOCK = 1 << 11;
        const DSYNC = 1 << 12;
        const LARGEFILE = 1 << 15;
        const DIRECTORY = 1 << 16;
        const NOFOLLOW = 1 << 17;
        const NOATIME = 1 << 18;
        const CLOEXEC = 1 << 19;
        const SYNC = 1 << 20;
        const PATH = 1 << 21;
        const TMPFILE = 1 << 22;

        const _ALL = !0;
    }
}

impl OpenFlags {
    /// Change only the mutable flags.
    pub fn update(&mut self, flags: Self) {
        // FIXME: Add more bits.
        for bit in [Self::APPEND, Self::NOATIME, Self::NONBLOCK] {
            self.set(bit, flags.contains(bit));
        }
    }
}

impl From<OpenFlags> for FdFlags {
    fn from(value: OpenFlags) -> Self {
        let mut flags = Self::empty();
        flags.set(Self::CLOEXEC, value.contains(OpenFlags::CLOEXEC));
        flags
    }
}

bitflags! {
    pub struct FileMode {
        const ALL = 0o777;
        const ALL_READ_WRITE = 0o666;

        const OTHER_EXECUTE = 0o001;
        const OTHER_WRITE = 0o002;
        const OTHER_READ = 0o004;
        const GROUP_EXECUTE = 0o010;
        const GROUP_WRITE = 0o020;
        const GROUP_READ = 0o040;
        const OWNER_EXECUTE = 0o100;
        const OWNER_WRITE = 0o200;
        const OWNER_READ = 0o400;
        const OWNER_ALL = 0o700;
        const STICKY = 0o1000;
        const SET_GROUP_ID = 0o2000;
        const SET_USER_ID = 0o4000;
    }
}

enum_arg! {
    pub enum Whence {
        Set = 0,
        Cur = 1,
        End = 2,
        Data = 3,
        Hole = 4,
    }
}

bitflags! {
    pub struct ProtFlags {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC = 1 << 2;
        const GROWSDOWN = 1 << 24;
    }
}

bitflags! {
    pub struct MmapFlags {
        const SHARED = 1 << 0;
        const PRIVATE = 1 << 1;
        const SHARED_VALIDATE = (1 << 0) | (1 << 1);
        const FIXED = 1 << 4;
        const ANONYMOUS = 1 << 5;
        const _32BIT = 1 << 6;
        const DENYWRITE = 1 << 11;
        const LOCKED = 1 << 13;
        const NORESERVE = 1 << 14;
        const POPULATE = 1 << 15;
        const STACK = 1 << 17;
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Pollfd {
    pub fd: FdNum,
    pub events: PollEvents,
    pub revents: PollEvents,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Pod, Zeroable)]
    #[repr(transparent)]
    pub struct PollEvents: u16 {
        const IN = 0x0001;
        const PRI = 0x0002;
        const OUT = 0x0004;
        const ERR = 0x0008;
        const HUP = 0x0010;
        const NVAL = 0x0020;
        const RDNORM = 0x0040;
        const RDBAND = 0x0080;
        const WRNORM = 0x0100;
        const WRBAND = 0x0200;
        const MSG = 0x0400;
        const REMOVE = 0x1000;
        const RDHUP = 0x2000;
    }
}

impl From<PollEvents> for Events {
    fn from(value: PollEvents) -> Self {
        let mut events = Events::empty();
        events.set(Events::READ, value.contains(PollEvents::IN));
        events.set(Events::WRITE, value.contains(PollEvents::OUT));
        events.set(Events::ERR, value.contains(PollEvents::ERR));
        events.set(Events::HUP, value.contains(PollEvents::HUP));
        events.set(Events::PRI, value.contains(PollEvents::PRI));
        events
    }
}

impl From<Events> for PollEvents {
    fn from(value: Events) -> Self {
        let mut events = PollEvents::empty();
        events.set(PollEvents::IN, value.contains(Events::READ));
        events.set(PollEvents::OUT, value.contains(Events::WRITE));
        events.set(PollEvents::ERR, value.contains(Events::ERR));
        events.set(PollEvents::HUP, value.contains(Events::HUP));
        events.set(PollEvents::PRI, value.contains(Events::PRI));
        events
    }
}

impl Pointee for Pollfd {}
impl PrimitivePointee for Pollfd {}

#[derive(Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct FdNum(i32);

impl FdNum {
    pub const CWD: Self = Self(-100);

    pub fn new(value: i32) -> Self {
        Self(value)
    }

    pub fn get(self) -> i32 {
        self.0
    }
}

impl Display for FdNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::CWD {
            f.pad("AT_CWD")
        } else {
            self.0.fmt(f)
        }
    }
}

impl SyscallArg for FdNum {
    fn parse(value: u64, abi: Abi) -> Result<Self> {
        i32::parse(value, abi).map(Self).map_err(|_| err!(BadF))
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        abi: Abi,
        _thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        match Self::parse(value, abi) {
            Ok(fd) => write!(f, "{fd}"),
            Err(_) => {
                write!(f, "{value} (invalid fd)")
            }
        }
    }
}

enum_arg! {
    pub enum ArchPrctlCode {
        SetFs = 0x1002,
    }
}

enum_arg! {
    pub enum FcntlCmd {
        DupFd = 0,
        GetFd = 1,
        SetFd = 2,
        GetFl = 3,
        SetFl = 4,
        GetLk = 5,
        SetLk = 6,
        SetLkW = 7,
        SetOwn = 8,
        GetOwn = 9,
        SetOwnEx = 15,
        GetOwnEx = 16,
        OfdSetLk = 37,
        OfdSetLkW = 38,
        DupFdCloExec = 1030,
        AddSeals = 1033,
        GetSeals = 1034,
    }
}

enum_arg! {
    pub enum RtSigprocmaskHow {
        Block = 0,
        Unblock = 1,
        SetMask = 2,
    }
}

bitflags! {
    pub struct CloneFlags {
        const CSIGNAL = 0x000000ff;
        const VM = 0x00000100;
        const FS = 0x00000200;
        const FILES = 0x00000400;
        const SIGHAND = 0x00000800;
        const PIDFD = 0x00001000;
        const PTRACE = 0x00002000;
        const VFORK = 0x00004000;
        const PARENT = 0x00008000;
        const THREAD = 0x00010000;
        const NEWNS = 0x00020000;
        const SYSVSEM = 0x00040000;
        const SETTLS = 0x00080000;
        const PARENT_SETTID = 0x00100000;
        const CHILD_CLEARTID = 0x00200000;
        const DETACHED = 0x00400000;
        const UNTRACED = 0x00800000;
        const CHILD_SETTID = 0x01000000;
        const NEWCGROUP = 0x02000000;
        const NEWUTS = 0x04000000;
        const NEWIPC = 0x08000000;
        const NEWUSER = 0x10000000;
        const NEWPID = 0x20000000;
        const NEWNET = 0x40000000;
        const IO = 0x80000000;
    }
}

impl CloneFlags {
    pub fn termination_signal(&self) -> Result<Option<Signal>> {
        let signal = self.bits() as u8;
        (signal != 0).then(|| Signal::new(signal)).transpose()
    }
}

enum_arg! {
    pub enum FutexOp {
        Wait = 0,
        Wake = 1,
        Fd = 2,
        Requeue = 3,
        CmpRequeue = 4,
        WakeOp = 5,
        LockPi = 6,
        UnlockPi = 7,
        TrylockPi = 8,
        WaitBitset = 9,
        WakeBitset = 10,
        WaitRequeuePi = 11,
        CmpRequeuePi = 12,
        LockPi2 = 13,
    }
}

bitflags! {
    pub struct FutexFlags {
        const PRIVATE_FLAG = 1 << 7;
        const CLOCK_REALTIME = 1 << 8;
    }
}

#[derive(Clone, Copy)]
pub struct FutexOpWithFlags {
    pub op: FutexOp,
    pub flags: FutexFlags,
}

impl Display for FutexOpWithFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} | {}", self.op, self.flags)
    }
}

impl SyscallArg for FutexOpWithFlags {
    fn parse(value: u64, abi: Abi) -> Result<Self> {
        let op = FutexOp::parse(value & 0x7f, abi)?;
        let flags = FutexFlags::parse(value & !0x7f, abi)?;
        Ok(Self { op, flags })
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        abi: Abi,
        thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        FutexOp::display(f, value & 0x7f, abi, thread)?;
        write!(f, " | ")?;
        FutexFlags::display(f, value & !0x7f, abi, thread)
    }
}

bitflags! {
    pub struct Pipe2Flags {
        const NON_BLOCK = 1 << 11;
        const DIRECT = 1 << 14;
        const CLOEXEC = 1 << 19;
    }
}

impl From<Pipe2Flags> for OpenFlags {
    fn from(value: Pipe2Flags) -> Self {
        OpenFlags::from_bits(value.bits()).unwrap()
    }
}

impl From<Pipe2Flags> for FdFlags {
    fn from(value: Pipe2Flags) -> Self {
        let mut flags = Self::empty();
        flags.set(Self::CLOEXEC, value.contains(Pipe2Flags::CLOEXEC));
        flags
    }
}

bitflags! {
    pub struct WaitOptions {
        const NOHANG = 1 << 0;
        const UNTRACED = 1 << 1;
        const CONTINUED = 1 << 3;
        const __WALL = 1 << 30;
    }
}

bitflags! {
    pub struct CopyFileRangeFlags {}
}

#[derive(Debug, Clone, Copy)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    pub mode: FileTypeAndMode,
    pub uid: Uid,
    pub gid: Gid,
    pub rdev: u64,
    pub size: i64,
    pub blksize: i64,
    pub blocks: i64,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
}

impl Stat {
    pub fn major(&self) -> u16 {
        self.rdev.get_bits(8..24) as u16
    }

    pub fn minor(&self) -> u8 {
        self.rdev as u8
    }
}

#[derive(Debug, Clone, Copy, Zeroable, NoUninit)]
#[repr(C, packed)]
pub struct Stat64 {
    pub dev: u64,
    pub __pad0: [u8; 4],

    pub __ino: u32,

    pub mode: FileTypeAndMode,
    pub nlink: u32,

    pub uid: Uid,
    pub gid: Gid,

    pub rdev: u64,
    pub __pad3: [u8; 4],

    pub size: i64,
    pub blksize: u32,

    pub blocks: i64,

    pub atime: Timespec32,
    pub mtime: Timespec32,
    pub ctime: Timespec32,

    pub ino: u64,
}

impl From<Stat> for Stat64 {
    fn from(value: Stat) -> Self {
        Self {
            dev: value.dev,
            __pad0: [0; 4],
            __ino: value.ino as u32,
            mode: value.mode,
            nlink: value.nlink as u32,
            uid: value.uid,
            gid: value.gid,
            rdev: value.rdev,
            __pad3: [0; 4],
            size: value.size,
            blksize: value.blksize as u32,
            blocks: value.blocks,
            atime: Timespec32::from(value.atime),
            mtime: Timespec32::from(value.mtime),
            ctime: Timespec32::from(value.ctime),
            ino: value.ino,
        }
    }
}

#[derive(Clone, Copy, Zeroable, NoUninit)]
#[repr(transparent)]
pub struct FileTypeAndMode(u32);

impl fmt::Debug for FileTypeAndMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FileTypeAndMode")
            .field(&self.ty())
            .field(&self.mode())
            .field(&format_args!("{:#08o}", self.0))
            .finish()
    }
}

impl FileTypeAndMode {
    pub fn new(ty: FileType, mode: FileMode) -> Self {
        Self(((ty as u32) << 12) | mode.bits() as u32)
    }

    pub fn ty(&self) -> FileType {
        checked::cast(self.0.get_bits(12..))
    }

    pub fn mode(&self) -> FileMode {
        FileMode::from_bits_truncate(u64::from(self.0))
    }
}

#[derive(Debug, Clone, Copy, CheckedBitPattern, PartialEq, Eq)]
#[repr(u32)]
#[allow(unused)]
pub enum FileType {
    Unknown = 0o00,
    Fifo = 0o01,
    Char = 0o02,
    Dir = 0o04,
    Block = 0o06,
    File = 0o10,
    Link = 0o12,
    Socket = 0o14,
}

#[derive(Debug, Clone, Copy)]
pub struct Iovec {
    pub base: u64,
    pub len: u64,
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct LinuxDirent64 {
    pub ino: u64,
    pub off: i64,
    pub reclen: u16,
    pub ty: u8,
    pub name: [u8; 0],
    pub _padding: [u8; 5],
}

bitflags! {
    pub struct UnlinkOptions {
        const REMOVEDIR = 0x200;
    }
}

bitflags! {
    pub struct LinkOptions {
        const SYMLINK_FOLLOW = 0x400;
        const EMPTY_PATH = 0x1000;
    }
}

enum_arg! {
    pub enum Advice {
        DontNeed = 4,
        Free = 8,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct WStatus(u32);

impl WStatus {
    pub const fn exit(status: u8) -> Self {
        Self((status as u32) << 8)
    }

    pub const fn signaled(signal: Signal) -> Self {
        Self(signal.get() as u32)
    }

    pub const fn stopped(signal: Signal) -> Self {
        Self(((signal.get() as u32) << 8) | 0x7f)
    }

    pub const fn syscall_stop() -> Self {
        Self(((Signal::TRAP.get() as u32) << 8) | 0x7f)
    }

    pub const fn ptrace_event(event: PtraceEvent) -> Self {
        Self(((event as u32) << 16) | ((Signal::TRAP.get() as u32) << 8) | 0x7f)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy)]
pub enum PtraceEvent {
    Exit = 6,
}

bitflags! {
    pub struct MountFlags {}
}

bitflags! {
    pub struct GetRandomFlags {
        const NON_BLOCK = 0x0001;
        const RANDOM = 0x0002;
        const INSECURE = 0x0004;
    }
}

enum_arg! {
    pub enum ClockId {
        Realtime = 0,
        Monotonic = 1,
        MonotonicRaw = 4,
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ExtendedClockId {
    Normal(ClockId),
    ProcessCpuTimeId(u32),
    ThreadCpuTimeId(u32),
}

impl SyscallArg for ExtendedClockId {
    fn parse(value: u64, abi: Abi) -> Result<Self> {
        Ok(match value {
            2 => Self::ProcessCpuTimeId(0),
            3 => Self::ThreadCpuTimeId(0),
            16.. => {
                let id = (!value as u32).get_bits(3..);
                match value.get_bits(0..3) {
                    2 => Self::ProcessCpuTimeId(id),
                    3 => Self::ThreadCpuTimeId(id),
                    _ => bail!(Inval),
                }
            }
            0..16 => Self::Normal(ClockId::parse(value, abi)?),
        })
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        abi: Abi,
        _thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        if let Ok(value) = Self::parse(value, abi) {
            write!(f, "{value:?}")
        } else {
            write!(f, "{value}")
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Timespec {
    pub tv_sec: i32, // TODO: Is this always positive????
    pub tv_nsec: u32,
}

impl Timespec {
    pub const ZERO: Self = Self {
        tv_sec: 0,
        tv_nsec: 0,
    };

    pub const UTIME_NOW: u32 = 0x3FFFFFFF;
    pub const UTIME_OMIT: u32 = 0x3FFFFFFE;

    pub fn from_ms(ms: i64) -> Self {
        Self::from_ns(ms * 1_000_000)
    }

    pub fn from_ns(ns: i64) -> Self {
        Timespec {
            tv_sec: i32::try_from(ns / 1_000_000_000).unwrap(),
            tv_nsec: (ns % 1_000_000_000) as u32,
        }
    }

    pub fn saturating_add(self, rhs: Self) -> Self {
        let mut tv_sec = self.tv_sec.saturating_add(rhs.tv_sec);
        let mut tv_nsec = self.tv_nsec + rhs.tv_nsec;
        if let Some(new_tv_nsec) = tv_nsec.checked_sub(1_000_000_000) {
            tv_nsec = new_tv_nsec;
            tv_sec = tv_sec.saturating_add(1);
        }
        Self { tv_sec, tv_nsec }
    }

    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        if self < rhs {
            return None;
        }

        let mut tv_sec = self.tv_sec - rhs.tv_sec;
        let (mut tv_nsec, overflow) = self.tv_nsec.overflowing_sub(rhs.tv_nsec);
        if overflow {
            tv_sec -= 1;
            tv_nsec = tv_nsec.wrapping_add(1_000_000_000);
        }
        Some(Self { tv_sec, tv_nsec })
    }

    pub fn saturating_sub(self, rhs: Self) -> Self {
        self.checked_sub(rhs).unwrap_or(Self {
            tv_sec: 0,
            tv_nsec: 0,
        })
    }

    pub fn saturating_mul(self, rhs: u64) -> Self {
        let mut acc = Timespec::ZERO;
        // This implements multiplication with double-and-add (similar to
        // square-and-multiply).
        // TODO: Replace this with something more efficient.
        for i in (0..64).rev() {
            acc = acc.saturating_add(acc);
            if rhs.get_bit(i) {
                acc = acc.saturating_add(self);
            }
        }
        acc
    }

    pub fn kernel_ticks(&self) -> u64 {
        u64::try_from(self.tv_sec).unwrap() * 1_000_000 + u64::from(self.tv_nsec).div_ceil(1000)
    }
}

impl Add for Timespec {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut tv_sec = self.tv_sec + rhs.tv_sec;
        let mut tv_nsec = self.tv_nsec + rhs.tv_nsec;
        if let Some(new_tv_nsec) = tv_nsec.checked_sub(1_000_000_000) {
            tv_nsec = new_tv_nsec;
            tv_sec += 1;
        }
        Self { tv_sec, tv_nsec }
    }
}

#[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Timeval {
    pub tv_sec: i32,
    pub tv_usec: u32,
}

impl Timeval {
    pub fn saturating_add(self, rhs: Self) -> Self {
        let tv_sec = self.tv_sec + rhs.tv_sec;
        let tv_usec = self.tv_usec + rhs.tv_usec;
        if let Some(tv_usec) = tv_usec.checked_sub(1_000_000) {
            Self {
                tv_sec: tv_sec + 1,
                tv_usec,
            }
        } else {
            Self { tv_sec, tv_usec }
        }
    }

    pub fn kernel_ticks(&self) -> u64 {
        u64::try_from(self.tv_sec).unwrap() * 1_000_000 + u64::from(self.tv_usec)
    }
}

impl From<Timeval> for Timespec {
    fn from(value: Timeval) -> Self {
        Self {
            tv_sec: value.tv_sec,
            tv_nsec: value.tv_usec * 1000,
        }
    }
}

impl From<Timespec> for Timeval {
    fn from(value: Timespec) -> Self {
        Self {
            tv_sec: value.tv_sec,
            tv_usec: value.tv_nsec / 1000,
        }
    }
}

enum_arg! {
    pub enum Domain {
        Unspec = 0,
        Unix = 1,
        Inet = 2,
        Inet6 = 10,
        Netlink = 16,
    }
}

enum_arg! {
    pub enum SocketType {
        Stream = 1,
        Dgram = 2,
        Raw	= 3,
        Seqpacket = 5,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SocketTypeWithFlags {
    pub socket_type: SocketType,
    pub flags: OpenFlags,
}

impl SocketTypeWithFlags {
    const FLAGS_MASK: u64 = OpenFlags::NONBLOCK.bits() | OpenFlags::CLOEXEC.bits();
}

impl SyscallArg for SocketTypeWithFlags {
    fn parse(value: u64, abi: Abi) -> Result<Self> {
        let socket_type = SocketType::parse(value & !Self::FLAGS_MASK, abi)?;
        let flags = OpenFlags::parse(value & Self::FLAGS_MASK, abi)?;
        Ok(Self { socket_type, flags })
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        abi: Abi,
        thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        SocketType::display(f, value & !Self::FLAGS_MASK, abi, thread)?;

        let value = value & Self::FLAGS_MASK;
        if value != 0 {
            write!(f, " | ")?;
            OpenFlags::display(f, value, abi, thread)?;
        }

        Ok(())
    }
}

impl From<SocketTypeWithFlags> for FdFlags {
    fn from(value: SocketTypeWithFlags) -> Self {
        value.flags.into()
    }
}

enum_arg! {
    pub enum EpollCtlOp {
        Add = 1,
        Del = 2,
        Mod = 3,
    }
}

#[derive(Debug, Clone, Copy, NoUninit, CheckedBitPattern)]
#[repr(C, packed(4))]
pub struct EpollEvent {
    pub events: EpollEvents,
    pub data: u64,
}

impl EpollEvent {
    pub fn new(events: EpollEvents, data: u64) -> Self {
        Self { events, data }
    }
}

impl pointee::Pointee for EpollEvent {}

impl PrimitivePointee for EpollEvent {}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, NoUninit)]
    #[repr(transparent)]
    pub struct EpollEvents: u32 {
        const IN = 1 << 0;
        const PRI = 1 << 1;
        const OUT = 1 << 2;
        const ERR = 1 << 3;
        const HUP = 1 << 4;
        const NVAL = 1 << 5;
        const RDNORM = 1 << 6;
        const RDBAND = 1 << 7;
        const WRNORM = 1 << 8;
        const WRBAND = 1 << 9;
        const MSG = 1 << 10;
        const REMOVE = 1 << 12;
        const RDHUP = 1 << 13;
        const FREE = 1 << 14;
        const BUSY_LOOP = 1 << 15;

        const INPUT_FLAGS = 0xf << 28;
        const EXCLUSIVE = 1 << 28;
        const WAKEUP = 1 << 29;
        const ONESHOT = 1 << 30;
        const ET = 1 << 31;
    }
}

unsafe impl CheckedBitPattern for EpollEvents {
    type Bits = u32;

    fn is_valid_bit_pattern(bits: &Self::Bits) -> bool {
        EpollEvents::from_bits(*bits).is_some()
    }
}

impl From<EpollEvents> for Events {
    fn from(value: EpollEvents) -> Self {
        let mut events = Events::empty();
        events.set(Events::READ, value.contains(EpollEvents::IN));
        events.set(Events::WRITE, value.contains(EpollEvents::OUT));
        events.set(Events::RDHUP, value.contains(EpollEvents::RDHUP));
        events.set(Events::PRI, value.contains(EpollEvents::PRI));
        events
    }
}

impl From<Events> for EpollEvents {
    fn from(value: Events) -> Self {
        let mut events = EpollEvents::empty();
        events.set(EpollEvents::IN, value.contains(Events::READ));
        events.set(EpollEvents::OUT, value.contains(Events::WRITE));
        events.set(EpollEvents::ERR, value.contains(Events::ERR));
        events.set(EpollEvents::RDHUP, value.contains(Events::RDHUP));
        events.set(EpollEvents::HUP, value.contains(Events::HUP));
        events.set(EpollEvents::PRI, value.contains(Events::PRI));
        events
    }
}

bitflags! {
    pub struct EpollCreate1Flags {
        const CLOEXEC = 0x8_0000;
    }
}

impl From<EpollCreate1Flags> for FdFlags {
    fn from(value: EpollCreate1Flags) -> Self {
        let mut flags = Self::empty();
        flags.set(Self::CLOEXEC, value.contains(EpollCreate1Flags::CLOEXEC));
        flags
    }
}

bitflags! {
    pub struct EventFdFlags {
        const NON_BLOCK = 0x800;
        const CLOEXEC = 0x8_0000;
    }
}

impl From<EventFdFlags> for FdFlags {
    fn from(value: EventFdFlags) -> Self {
        let mut flags = Self::empty();
        flags.set(Self::CLOEXEC, value.contains(EventFdFlags::CLOEXEC));
        flags
    }
}

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit)]
#[repr(C)]
pub struct UserDesc {
    pub entry_number: u32,
    pub base_addr: u32,
    pub limit: u32,
    pub flags: UserDescFlags,
}

impl pointee::Pointee for UserDesc {}

impl PrimitivePointee for UserDesc {}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, NoUninit)]
    #[repr(transparent)]
    pub struct UserDescFlags: u32 {
        const SEG_32BIT = 1 << 0;
        const CONTENTS = 3 << 1;
        const READ_EXEC_ONLY = 1 << 3;
        const LIMIT_IN_PAGES = 1 << 4;
        const SEG_NOT_PRESENT = 1 << 5;
        const USEABLE = 1 << 6;
        const LM = 1 << 7;
    }
}

unsafe impl CheckedBitPattern for UserDescFlags {
    type Bits = u32;

    fn is_valid_bit_pattern(bits: &Self::Bits) -> bool {
        Self::from_bits(*bits).is_some()
    }
}

#[derive(Clone, Copy)]
pub struct Offset(#[allow(dead_code)] pub i64);

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct LongOffset(#[allow(dead_code)] pub i64);

bitflags! {
    pub struct AtFlags {
        const AT_SYMLINK_NOFOLLOW = 0x100;
        const AT_NO_AUTOMOUNT = 0x800;
        const AT_EMPTY_PATH = 0x1000;
    }
}

#[derive(Clone, Copy)]
pub struct Time(pub u32);

enum_arg! {
    pub enum Resource {
        FSize = 1,
        Stack = 3,
        Core = 4,
        NProc = 6,
        NoFile = 7,
        As = 9,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RLimit {
    /// Soft limit
    pub rlim_cur: u64,
    /// Hard limit (ceiling for rlim_cur)
    pub rlim_max: u64,
}

impl RLimit {
    pub const INFINITY: u64 = !0;
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct RLimit64 {
    /// Soft limit
    pub rlim_cur: u64,
    /// Hard limit (ceiling for rlim_cur)
    pub rlim_max: u64,
}

impl From<RLimit> for RLimit64 {
    fn from(value: RLimit) -> Self {
        Self {
            rlim_cur: value.rlim_cur,
            rlim_max: value.rlim_max,
        }
    }
}

impl From<RLimit64> for RLimit {
    fn from(value: RLimit64) -> Self {
        Self {
            rlim_cur: value.rlim_cur,
            rlim_max: value.rlim_max,
        }
    }
}

bitflags! {
    pub struct SpliceFlags {
        const NONBLOCK = 1 << 1;
    }
}

bitflags! {
    pub struct Dup3Flags {
        const CLOEXEC = 1 << 19;
    }
}

impl From<Dup3Flags> for FdFlags {
    fn from(value: Dup3Flags) -> Self {
        let mut flags = Self::empty();
        flags.set(Self::CLOEXEC, value.contains(Dup3Flags::CLOEXEC));
        flags
    }
}

bitflags! {
    pub struct ClockNanosleepFlags {
        const TIMER_ABSTIME = 1;
    }
}

// This value is guaranteed to be less than 64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signal(u8);

impl Signal {
    pub const HUP: Self = Self(1);
    pub const INT: Self = Self(2);
    pub const ILL: Self = Self(4);
    pub const TRAP: Self = Self(5);
    pub const ABRT: Self = Self(6);
    pub const BUS: Self = Self(7);
    pub const FPE: Self = Self(8);
    pub const KILL: Self = Self(9);
    pub const USR1: Self = Self(10);
    pub const SEGV: Self = Self(11);
    pub const USR2: Self = Self(12);
    pub const PIPE: Self = Self(13);
    pub const ALRM: Self = Self(14);
    pub const TERM: Self = Self(15);
    pub const CHLD: Self = Self(17);
    pub const CONT: Self = Self(18);
    pub const STOP: Self = Self(19);
    pub const XFSZ: Self = Self(25);

    pub fn new(value: u8) -> Result<Self> {
        ensure!((1..=64).contains(&value), Inval);
        Ok(Self(value))
    }

    pub const fn get(&self) -> usize {
        self.0 as usize
    }
}

impl SyscallArg for Signal {
    fn parse(value: u64, _abi: Abi) -> Result<Self> {
        let value = u8::try_from(value)?;
        Self::new(value)
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        abi: Abi,
        _thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        if let Ok(signal) = Self::parse(value, abi) {
            write!(f, "{signal:?}")
        } else {
            write!(f, "{value}")
        }
    }
}

impl SyscallArg for Option<Signal> {
    fn parse(value: u64, abi: Abi) -> Result<Self> {
        Ok(if value == 0 {
            None
        } else {
            Some(Signal::parse(value, abi)?)
        })
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        abi: Abi,
        _thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        if let Ok(signal) = Self::parse(value, abi) {
            write!(f, "{signal:?}")
        } else {
            write!(f, "{value}")
        }
    }
}

pub struct FdSet {}

impl Pointee for FdSet {}

#[derive(Clone, Copy)]
pub struct SysInfo {
    pub uptime: i64,
    pub loads: [u64; 3],
    pub totalram: u64,
    pub freeram: u64,
    pub sharedram: u64,
    pub bufferram: u64,
    pub totalswap: u64,
    pub freeswap: u64,
    pub procs: u16,
    pub totalhigh: u64,
    pub freehigh: u64,
    pub mem_unit: u32,
}

#[derive(Clone, Copy)]
pub struct PSelectSigsetArg {
    pub ss: Pointer<Sigset>,
    #[allow(dead_code)]
    pub ss_len: usize,
}

bitflags! {
    pub struct FLockOp {
        const SH = 1 << 0;
        const EX = 1 << 1;
        const NB = 1 << 2;
        const UN = 1 << 3;
    }
}

impl SyscallArg for Uid {
    fn parse(value: u64, abi: Abi) -> Result<Self> {
        u32::parse(value, abi).map(Self::new)
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        abi: Abi,
        thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        <u32 as SyscallArg>::display(f, value, abi, thread)
    }
}

impl SyscallArg for Gid {
    fn parse(value: u64, abi: Abi) -> Result<Self> {
        u32::parse(value, abi).map(Self::new)
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        abi: Abi,
        thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        <u32 as SyscallArg>::display(f, value, abi, thread)
    }
}

bitflags! {
    pub struct AccessMode {
        const EXECUTE = 1 << 0;
        const WRITE = 1 << 1;
        const READ = 1 << 2;
    }
}

bitflags! {
    pub struct FaccessatFlags {
        const SYMLINK_NOFOLLOW = 1 << 8;
        const EACCESS = 1 << 9;
    }
}

bitflags! {
    pub struct Renameat2Flags {
        const NOREPLACE = 1 << 0;
        const EXCHANGE = 1 << 1;
    }
}

bitflags! {
    pub struct FchownatFlags {
        const SYMLINK_NOFOLLOW = 1 << 8;
    }
}

bitflags! {
    pub struct Fchmodat2Flags {
        const SYMLINK_NOFOLLOW = 1 << 8;
    }
}

enum_arg! {
    pub enum Which {
        Process = 0,
        ProcessGroup = 1,
        User = 2,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nice(Reverse<i8>);

impl Nice {
    pub const DEFAULT: Self = Self(Reverse(0));

    pub fn get(&self) -> i8 {
        self.0.0
    }

    pub fn as_syscall_return_value(self) -> u64 {
        (20 - self.get()) as u64
    }
}

impl SyscallArg for Nice {
    fn parse(value: u64, _: Abi) -> Result<Self> {
        let value = value as u32 as i32;
        ensure!((-20..=19).contains(&value), Inval);
        Ok(Self(Reverse(value as i8)))
    }

    fn display(f: &mut dyn fmt::Write, value: u64, _: Abi, _: &ThreadGuard<'_>) -> fmt::Result {
        write!(f, "{}", value as u32 as i32)
    }
}

enum_arg! {
    pub enum PrctlOp {
        SetPdeathsig = 1,
        SetDumpable = 4,
        SetName = 15,
        GetName = 16,
        GetSeccomp = 21,
        SetSeccomp = 22,
        CapbsetRead = 23,
        SetNoNewPrivs = 38,
        GetNoNewPrivs = 39,
        CapAmbient = 47,
    }
}

enum_arg! {
    pub enum GetRusageWho {
        Self_ = 0,
        Children	= -1,
        Thread=	1,
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Rusage {
    /// user time used
    pub utime: Timeval,
    /// system time used
    pub stime: Timeval,
    /// maximum resident set size
    pub maxrss: u64,
    /// integral shared memory size
    pub ixrss: u64,
    /// integral unshared data size
    pub idrss: u64,
    /// integral unshared stack size
    pub isrss: u64,
    /// page reclaims
    pub minflt: u64,
    /// page faults
    pub majflt: u64,
    /// swaps
    pub nswap: u64,
    /// block input operations
    pub inblock: u64,
    /// block output operations
    pub oublock: u64,
    /// messages sent
    pub msgsnd: u64,
    /// messages received
    pub msgrcv: u64,
    /// signals received
    pub nsignals: u64,
    /// voluntary context switches
    pub nvcsw: u64,
    /// involuntary context switches
    pub nivcsw: u64,
}

impl Rusage {
    pub fn merge(self, rusage: Self) -> Self {
        Self {
            utime: self.utime.saturating_add(rusage.utime),
            stime: self.stime.saturating_add(rusage.stime),
            maxrss: cmp::max(self.maxrss, rusage.maxrss),
            ixrss: self.ixrss + rusage.ixrss,
            idrss: self.idrss + rusage.idrss,
            isrss: self.isrss + rusage.isrss,
            minflt: self.minflt + rusage.minflt,
            majflt: self.majflt + rusage.majflt,
            nswap: self.nswap + rusage.nswap,
            inblock: self.inblock + rusage.inblock,
            oublock: self.oublock + rusage.oublock,
            msgsnd: self.msgsnd + rusage.msgsnd,
            msgrcv: self.msgrcv + rusage.msgrcv,
            nsignals: self.nsignals + rusage.nsignals,
            nvcsw: self.nvcsw + rusage.nvcsw,
            nivcsw: self.nivcsw + rusage.nivcsw,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SocketAddr {
    Unspecified,
    Unix(SocketAddrUnix),
    Inet(SocketAddrV4),
    Inet6(SocketAddrV6),
    Netlink(SocketAddrNetlink),
}

impl SocketAddr {
    pub fn domain(&self) -> Domain {
        match self {
            SocketAddr::Unspecified => Domain::Unspec,
            SocketAddr::Unix(_) => Domain::Unix,
            SocketAddr::Inet(_) => Domain::Inet,
            SocketAddr::Inet6(_) => Domain::Inet6,
            SocketAddr::Netlink(_) => Domain::Netlink,
        }
    }
}

impl From<net::SocketAddr> for SocketAddr {
    fn from(value: net::SocketAddr) -> Self {
        match value {
            net::SocketAddr::V4(addr) => Self::Inet(addr),
            net::SocketAddr::V6(addr) => Self::Inet6(addr),
        }
    }
}

impl TryFrom<SocketAddr> for net::SocketAddr {
    type Error = Error;

    fn try_from(value: SocketAddr) -> Result<Self> {
        Ok(match value {
            SocketAddr::Inet(addr) => Self::V4(addr),
            SocketAddr::Inet6(addr) => Self::V6(addr),
            _ => bail!(Inval),
        })
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct SocketAddrNetlink {
    pub pid: u32,
    pub groups: u32,
}

bitflags! {
    pub struct SentToFlags {
        const OOB = 1 << 0;
        const NOSIGNAL = 1 << 14;
        const MORE = 1 << 15;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MsgHdr {
    /// Address to send to/receive from.
    pub name: Pointer<SocketAddr>,
    /// Length of address data.
    pub namelen: u32,

    /// Vector of data to send/receive into.
    pub iov: Pointer<Iovec>,
    /// Number of elements in the vector.
    pub iovlen: u64,

    /// Ancillary data (eg BSD filedesc passing).
    pub control: Pointer<CmsgHdr>,
    /// Ancillary data buffer length.
    pub controllen: u64,

    /// Flags on received message.
    pub flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct CmsgHdr {
    /// data byte count, including hdr
    pub len: u64,
    /// originating protocol
    pub level: i32,
    /// protocol-specific type
    pub r#type: i32,
}

bitflags! {
    pub struct RecvMsgFlags {
        const DONTWAIT = 1 << 6;
        const WAITALL = 1 << 8;
        const CMSG_CLOEXEC = 1 << 30;
    }
}

bitflags! {
    pub struct SendMsgFlags {
        const DONTWAIT = 1 << 6;
        const NOSIGNAL = 0x4000;
        const FASTOPEN = 0x20000000;
    }
}

bitflags! {
    pub struct Accept4Flags {
        const CLOEXEC = OpenFlags::CLOEXEC.bits();
        const NONBLOCK = OpenFlags::NONBLOCK.bits();
    }
}

impl From<Accept4Flags> for FdFlags {
    fn from(value: Accept4Flags) -> Self {
        let mut flags = FdFlags::empty();
        flags.set(FdFlags::CLOEXEC, value.contains(Accept4Flags::CLOEXEC));
        flags
    }
}

impl From<Accept4Flags> for OpenFlags {
    fn from(value: Accept4Flags) -> Self {
        OpenFlags::from_bits_truncate(value.bits())
    }
}

enum_arg! {
    pub enum ShutdownHow {
        Rd = 0,
        Wr = 1,
        RdWr = 2,
    }
}

bitflags! {
    pub struct RecvFromFlags {
        const OOB = 1 << 0;
        const PEEK = 1 << 1;
        const DONTWAIT = 1 << 6;
        const WAITALL = 1 << 8;
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Linger {
    pub onoff: i32,
    pub linger: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SocketAddrUnix {
    Pathname(Path),
    Unnamed,
    Abstract(Vec<u8>),
}

#[derive(Debug, Clone, Copy)]
pub struct MMsgHdr {
    /// Message header
    pub hdr: MsgHdr,
    /// Number of received bytes for header
    pub len: u32,
}

bitflags! {
    pub struct RecvMMsgFlags {}
}

impl From<RecvMMsgFlags> for RecvMsgFlags {
    fn from(value: RecvMMsgFlags) -> Self {
        RecvMsgFlags::from_bits_truncate(value.bits())
    }
}

bitflags! {
    pub struct InotifyInit1Flags {
        const NON_BLOCK = 1 << 11;
        const CLOEXEC = 1 << 19;
    }
}

impl From<InotifyInit1Flags> for OpenFlags {
    fn from(value: InotifyInit1Flags) -> Self {
        OpenFlags::from_bits(value.bits()).unwrap()
    }
}

impl From<InotifyInit1Flags> for FdFlags {
    fn from(value: InotifyInit1Flags) -> Self {
        let mut flags = Self::empty();
        flags.set(Self::CLOEXEC, value.contains(InotifyInit1Flags::CLOEXEC));
        flags
    }
}

bitflags! {
    pub struct InotifyMask {
        const ACCESS = 1 << 0;
        const MODIFY = 1 << 1;
        const ATTRIB = 1 << 2;
        const CLOSE_WRITE = 1 << 3;
        const CLOSE_NOWRITE = 1 << 4;
        const OPEN = 1 << 5;
        const MOVED_FROM =1<< 6;
        const MOVED_TO = 1 << 7;
        const CREATE = 1 << 8;
        const DELETE = 1 << 9;
        const DELETE_SELF = 1 << 10;
        const MOVE_SELF = 1 << 11;
        const ONLYDIR = 1 << 24;
        const DONT_FOLLOW = 1 << 25;
        const EXCL_UNLINK = 1 << 26;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Termios {
    pub input_modes: InputMode,
    pub output_modes: OutputMode,
    pub control_modes: ControlMode,
    pub local_modes: LocalMode,
    pub special_characters: SpecialCharacters,
}

impl Default for Termios {
    fn default() -> Self {
        Self {
            input_modes: InputMode::CRNL | InputMode::UTF8,
            output_modes: OutputMode::POST | OutputMode::NLCR,
            control_modes: ControlMode::B38400 | ControlMode::S8 | ControlMode::READ,
            local_modes: LocalMode::ISIG
                | LocalMode::ICANON
                | LocalMode::ECHO
                | LocalMode::ECHOE
                | LocalMode::ECHOK
                | LocalMode::ECHOCTL
                | LocalMode::ECHOKE
                | LocalMode::IEXTEN,
            special_characters: SpecialCharacters {
                intr: 0x03,
                quit: 0x1c,
                erase: 0x7f,
                kill: 0x15,
                eof: 0x04,
                time: 0x00,
                min: 0x01,
                swtc: 0x00,
                start: 0x11,
                stop: 0x13,
                susp: 0x1a,
                eol: 0x00,
                reprint: 0x12,
                discard: 0x0f,
                werase: 0x17,
                lnext: 0x16,
                eol2: 0x00,
                padding: [0x00, 0x00, 0x00],
            },
        }
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct InputMode: u32 {
        const GNBRK = 1 << 0;
        const BRKINT = 1 << 1;
        const GNPAR = 1 << 2;
        const PARMRK = 1 << 3;
        const NPCK = 1 << 4;
        const STRIP = 1 << 5;
        const NLCR = 1 << 6;
        const GNCR = 1 << 7;
        const CRNL = 1 << 8;
        const UCLC = 1 << 9;
        const XON = 1 << 10;
        const XANY = 1 << 11;
        const XOFF = 1 << 12;
        const MAXBEL = 1 << 13;
        const UTF8 = 1 << 14;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct OutputMode: u32 {
        const POST = 1 << 0;
        const LCUC = 1 << 1;
        const NLCR = 1 << 2;
        const CRNL = 1 << 3;
        const NOCR = 1 << 4;
        const NLRET = 1 << 5;
        const FILL = 1 << 6;
        const FDEL = 1 << 7;
        const NLDLY = 1 << 8;
        // const NL0 = 0;
        const NL1 = 1 << 8;
        const CRDLY = 3 << 9;
        // const CR0 = 0x00000;
        const CR1 = 1 << 9;
        const CR2 = 1 << 10;
        const CR3 = 3 << 9;
        const TABDLY = 3 << 11;
        // const TAB0 = 0;
        const TAB1 = 1 << 11;
        const TAB2 = 1 << 12;
        const TAB3 = 3 << 11;
        const XTABS = 3 << 11;
        const BSDLY = 1 << 13;
        // const BS0 = 0x00000;
        const BS1 = 1 << 13;
        const VTDLY = 1 << 14;
        // const VT0 = 0;
        const VT1 = 1 << 14;
        const FFDLY = 1 << 15;
        // const FF0 = 0;
        const FF1 = 1 << 15;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct ControlMode: u32 {
        // const S5 = 0x00000000;
        const S6 = 1 << 4;
        const S7 = 2 << 4;
        const S8 = 3 << 4;
        const STOPB = 1 << 6;
        const READ = 1 << 7;
        const PARENB = 1 << 8;
        const PARODD = 1 << 9;
        const HUPCL = 1 << 10;
        const LOCAL = 1 << 11;
        const BAUDEX = 1 << 12;
        const ADDRB = 1 << 29;
        const MSPAR = 1 << 30;
        const RTSCTS = 1 << 31;

        // const B0 = 0x0;
        const B50 = 0x1;
        const B75 = 0x2;
        const B110 = 0x3;
        const B134 = 0x4;
        const B150 = 0x5;
        const B200 = 0x6;
        const B300 = 0x7;
        const B600 = 0x8;
        const B1200 = 0x9;
        const B1800 = 0xa;
        const B2400 = 0xb;
        const B4800 = 0xc;
        const B9600 = 0xd;
        const B19200 = 0xe;
        const B38400 = 0xf;
        const BOTHER = 0x00001000;
        const B57600 = 0x00001001;
        const B115200 = 0x00001002;
        const B230400 = 0x00001003;
        const B460800 = 0x00001004;
        const B500000 = 0x00001005;
        const B576000 = 0x00001006;
        const B921600 = 0x00001007;
        const B1000000 = 0x00001008;
        const B1152000 = 0x00001009;
        const B1500000 = 0x0000100a;
        const B2000000 = 0x0000100b;
        const B2500000 = 0x0000100c;
        const B3000000 = 0x0000100d;
        const B3500000 = 0x0000100e;
        const B4000000 = 0x0000100f;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct LocalMode: u32 {
        const ISIG = 1 << 0;
        const ICANON = 1 << 1;
        const XCASE = 1 << 2;
        const ECHO = 1 << 3;
        const ECHOE = 1 << 4;
        const ECHOK = 1 << 5;
        const ECHONL = 1 << 6;
        const NOFLSH = 1 << 7;
        const TOSTOP = 1 << 8;
        const ECHOCTL = 1 << 9;
        const ECHOPRT = 1 << 10;
        const ECHOKE = 1 << 11;
        const FLUSHO = 1 << 12;
        const PENDIN = 1 << 14;
        const IEXTEN = 1 << 15;
        const EXTPROC = 1 << 16;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SpecialCharacters {
    pub intr: u8,
    pub quit: u8,
    pub erase: u8,
    pub kill: u8,
    pub eof: u8,
    pub time: u8,
    pub min: u8,
    pub swtc: u8,
    pub start: u8,
    pub stop: u8,
    pub susp: u8,
    pub eol: u8,
    pub reprint: u8,
    pub discard: u8,
    pub werase: u8,
    pub lnext: u8,
    pub eol2: u8,
    padding: [u8; 3],
}

impl From<SpecialCharacters> for [u8; 20] {
    fn from(value: SpecialCharacters) -> Self {
        [
            value.intr,
            value.quit,
            value.erase,
            value.kill,
            value.eof,
            value.time,
            value.min,
            value.swtc,
            value.start,
            value.stop,
            value.susp,
            value.eol,
            value.reprint,
            value.discard,
            value.werase,
            value.lnext,
            value.eol2,
            value.padding[0],
            value.padding[1],
            value.padding[2],
        ]
    }
}

impl From<[u8; 20]> for SpecialCharacters {
    fn from(value: [u8; 20]) -> Self {
        Self {
            intr: value[0],
            quit: value[1],
            erase: value[2],
            kill: value[3],
            eof: value[4],
            time: value[5],
            min: value[6],
            swtc: value[7],
            start: value[8],
            stop: value[9],
            susp: value[10],
            eol: value[11],
            reprint: value[12],
            discard: value[13],
            werase: value[14],
            lnext: value[15],
            eol2: value[16],
            padding: [value[17], value[18], value[19]],
        }
    }
}

#[derive(Debug, Default, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct WinSize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

bitflags! {
    pub struct FallocateMode {}
}

#[derive(Debug, Default, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Timezone {
    pub tz_minuteswest: i32,
    pub tz_dsttime: i32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ITimerval {
    pub interval: Timeval,
    pub value: Timeval,
}

impl From<ITimerspec> for ITimerval {
    fn from(value: ITimerspec) -> Self {
        Self {
            interval: value.interval.into(),
            value: value.value.into(),
        }
    }
}

impl From<ITimerval> for ITimerspec {
    fn from(value: ITimerval) -> Self {
        Self {
            interval: value.interval.into(),
            value: value.value.into(),
        }
    }
}

enum_arg! {
    pub enum ITimerWhich {
        Real = 0,
        Virtual = 1,
        Prof = 2,
    }
}

bitflags! {
    pub struct TimerfdCreateFlags {
        const NONBLOCK = 1 << 11;
        const CLOEXEC = 1 << 19;
    }
}

impl From<TimerfdCreateFlags> for FdFlags {
    fn from(value: TimerfdCreateFlags) -> Self {
        let mut flags = Self::empty();
        flags.set(Self::CLOEXEC, value.contains(TimerfdCreateFlags::CLOEXEC));
        flags
    }
}

impl From<TimerfdCreateFlags> for OpenFlags {
    fn from(value: TimerfdCreateFlags) -> Self {
        let mut flags = Self::empty();
        flags.set(Self::NONBLOCK, value.contains(TimerfdCreateFlags::NONBLOCK));
        flags.set(Self::CLOEXEC, value.contains(TimerfdCreateFlags::CLOEXEC));
        flags
    }
}

bitflags! {
    pub struct SetTimeFlags {
        const ABSTIME = 1 << 0;
        const CANCEL_ON_SET = 1 << 1;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ITimerspec {
    pub interval: Timespec,
    pub value: Timespec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct TimerId(pub i64);

impl SyscallArg for TimerId {
    fn parse(value: u64, abi: Abi) -> Result<Self> {
        match abi {
            Abi::I386 => Ok(Self(value as u32 as i32 as i64)),
            Abi::Amd64 => Ok(Self(value as i64)),
        }
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        abi: Abi,
        _thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        let value = Self::parse(value, abi).unwrap();
        write!(f, "{}", value.0)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SigEvent {
    pub sigev_value: Pointer<c_void>,
    pub sigev_signo: u32,
    pub sigev_notify: SigEventData,
}

#[derive(Debug, Clone, Copy)]
pub enum SigEventData {
    Signal,
    None,
    Thread {
        function: Pointer<c_void>,
        attribute: Pointer<c_void>,
    },
    ThreadId(u32),
}

bitflags! {
    pub struct TimerSettimeFlags {
        const ABSTIME = 1;
    }
}

bitflags! {
    pub struct MremapFlags {
        const MAYMOVE = 1;
        const FIXED = 2;
        const DONTUNMAP = 4;
    }
}

enum_arg! {
    pub enum PtraceOp {
        TraceMe = 0,
        PeekText = 1,
        PeekData = 2,
        // PeekUsr = 3,
        // PokeText = 4,
        // PokeData = 5,
        // PokeUsr = 6,
        Cont = 7,
        // Kill = 8,
        // SingleStep = 9,
        GetRegs = 12,
        // SetRegs = 13,
        // GetFpregs = 14,
        // SetFpregs = 15,
        // GetFpxregs = 18,
        // SetFpxregs = 19,
        Attach = 16,
        Detach = 17,
        // Syscall = 24,
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct UserRegs32 {
    pub bx: u32,
    pub cx: u32,
    pub dx: u32,
    pub si: u32,
    pub di: u32,
    pub bp: u32,
    pub ax: u32,
    pub ds: u32,
    pub es: u32,
    pub fs: u32,
    pub gs: u32,
    pub orig_ax: u32,
    pub ip: u32,
    pub cs: u32,
    pub flags: u32,
    pub sp: u32,
    pub ss: u32,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct UserRegs64 {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub bp: u64,
    pub bx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub ax: u64,
    pub cx: u64,
    pub dx: u64,
    pub si: u64,
    pub di: u64,
    pub orig_ax: u64,
    pub ip: u64,
    pub cs: u64,
    pub flags: u64,
    pub sp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct Ucred {
    pub pid: u32,
    pub uid: Uid,
    pub gid: Gid,
}

impl From<&FileAccessContext> for Ucred {
    fn from(ctx: &FileAccessContext) -> Self {
        Self {
            pid: ctx.process().unwrap().pid(),
            uid: ctx.filesystem_user_id(),
            gid: ctx.filesystem_group_id(),
        }
    }
}

bitflags! {
    pub struct MemfdCreateFlags {
        const CLOEXEC = 1 << 0;
        const ALLOW_SEALING = 1 << 1;
        // const HUGETLB = 1 << 2;
        // const NOEXEC_SEAL = 1 << 3;
        // const EXEC = 1 << 4;
    }
}

impl From<MemfdCreateFlags> for FdFlags {
    fn from(value: MemfdCreateFlags) -> Self {
        let mut flags = Self::empty();
        flags.set(Self::CLOEXEC, value.contains(MemfdCreateFlags::CLOEXEC));
        flags
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Flock {
    pub r#type: FlockType,
    pub whence: FlockWhence,
    pub start: u64,
    pub len: u64,
    pub pid: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum FlockType {
    Rd = 0,
    Wr = 1,
    Un = 2,
}

#[derive(Debug, Clone, Copy)]
pub enum FlockWhence {
    Set = 0,
    Cur = 1,
    End = 2,
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct UserCapHeader {
    pub version: u32,
    pub pid: u32,
}

impl UserCapHeader {
    pub const V3: u32 = 0x20080522;
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct UserCapData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct PktInfo {
    pub ifindex: u32,
    pub spec_dst: Ipv4Addr,
    pub addr: Ipv4Addr,
}

#[derive(Debug, Clone, Copy)]
pub struct PktInfo6 {
    pub spec_dst: Ipv6Addr,
    pub ifindex: u32,
}

bitflags! {
    pub struct SignalFdFlags {
        const NON_BLOCK = 1 << 11;
        const CLOEXEC = 1 << 19;
    }
}

impl From<SignalFdFlags> for OpenFlags {
    fn from(value: SignalFdFlags) -> Self {
        OpenFlags::from_bits(value.bits()).unwrap()
    }
}

impl From<SignalFdFlags> for FdFlags {
    fn from(value: SignalFdFlags) -> Self {
        let mut flags = Self::empty();
        flags.set(Self::CLOEXEC, value.contains(SignalFdFlags::CLOEXEC));
        flags
    }
}

#[derive(Debug, Clone, Copy, NoUninit)]
#[repr(C)]
pub struct SignalfdSiginfo {
    pub signo: u32,
    pub errno: i32,
    pub code: i32,
    pub pid: u32,
    pub uid: u32,
    pub fd: i32,
    pub tid: u32,
    pub band: u32,
    pub overrun: u32,
    pub trapno: u32,
    pub status: i32,
    pub int: i32,
    pub ptr: u64,
    pub utime: u64,
    pub stime: u64,
    pub addr: u64,
    pub addr_lsb: u16,
    __pad2: u16,
    pub syscall: i32,
    pub call_addr: u64,
    pub arch: u32,
    __pad: [u8; 28],
}

impl From<SigInfo> for SignalfdSiginfo {
    fn from(value: SigInfo) -> Self {
        Self {
            signo: value.signal.get() as u32,
            errno: 0,
            code: value.code.get(),
            pid: value.fields.pid(),
            uid: value.fields.uid(),
            fd: value.fields.fd(),
            tid: value.fields.tid(),
            band: value.fields.band(),
            overrun: value.fields.overrun(),
            trapno: value.fields.trapno(),
            status: value.fields.status(),
            int: value.fields.int(),
            ptr: value.fields.ptr(),
            utime: value.fields.utime(),
            stime: value.fields.stime(),
            addr: value.fields.addr(),
            addr_lsb: value.fields.addr_lsb(),
            __pad2: 0,
            syscall: value.fields.syscall(),
            call_addr: value.fields.call_addr(),
            arch: value.fields.arch(),
            __pad: [0; 28],
        }
    }
}

pub struct OpenHow {
    pub flags: OpenFlags,
    pub mode: FileMode,
    pub resolve: ResolveFlags,
}

bitflags! {
    pub struct ResolveFlags {
        const IN_ROOT = 1 << 4;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IpMreq {
    pub multiaddr: Ipv4Addr,
    #[expect(dead_code)]
    pub address: Ipv4Addr,
}

#[derive(Debug, Clone, Copy)]
pub struct IpMreqn {
    pub multiaddr: Ipv4Addr,
    #[expect(dead_code)]
    pub address: Ipv4Addr,
    #[expect(dead_code)]
    pub ifindex: i32,
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv6Mreq {
    pub multiaddr: Ipv6Addr,
    #[expect(dead_code)]
    pub ifindex: i32,
}

bitflags! {
    pub struct Seals {
        /// Prevent further seals from being set
        const SEAL = 0x0001;
        /// Prevent file from shrinking
        const SHRINK = 0x0002;
        /// Prevent file from growing
        const GROW = 0x0004;
    }
}
