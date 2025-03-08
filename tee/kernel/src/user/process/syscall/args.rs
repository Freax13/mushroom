use core::{
    cmp::{self, Reverse},
    fmt::{self, Display},
    marker::PhantomData,
    net::{Ipv4Addr, SocketAddrV4},
    ops::Add,
};

use alloc::{borrow::ToOwned, sync::Arc, vec::Vec};
use bit_field::BitField;
use bitflags::bitflags;
use bytemuck::{CheckedBitPattern, NoUninit, Pod, Zeroable, checked};
use usize_conversions::FromUsize;
use x86_64::VirtAddr;

use crate::{
    error::{Error, Result, bail, ensure, err},
    fs::{
        fd::{Events, FdFlags, FileDescriptorTable},
        path::Path,
    },
    user::process::{
        memory::VirtualMemory,
        thread::{Gid, Sigset, ThreadGuard, Uid},
    },
};

use self::pointee::{Pointee, PrimitivePointee, Timespec32};

use super::traits::Abi;

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
    fn extract_from_thread(guard: &ThreadGuard) -> Self;
}

impl ExtractableThreadState for Arc<FileDescriptorTable> {
    fn extract_from_thread(guard: &ThreadGuard) -> Self {
        guard.thread.fdtable.lock().clone()
    }
}

impl ExtractableThreadState for Arc<VirtualMemory> {
    fn extract_from_thread(guard: &ThreadGuard) -> Self {
        guard.virtual_memory().clone()
    }
}

macro_rules! bitflags {
    (pub struct $strukt:ident {
        $(
            const $constant:ident = $expr:expr;
        )*
    }) => {
        bitflags::bitflags! {
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub struct $strukt: u64 {
                $(
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
        #[derive(Debug, Clone, Copy)]
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

#[derive(Clone, Copy)]
pub struct Ignored(());

impl Display for Ignored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ignored")
    }
}

impl SyscallArg for Ignored {
    fn parse(_value: u64, _: Abi) -> Result<Self> {
        Ok(Self(()))
    }

    fn display(
        f: &mut dyn fmt::Write,
        _value: u64,
        _: Abi,
        _thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        write!(f, "ignored")
    }
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

impl<T> Pointer<T>
where
    T: ?Sized,
{
    pub fn is_null(&self) -> bool {
        self.value == 0
    }

    pub fn get(self) -> VirtAddr {
        VirtAddr::new(self.value)
    }
}

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
    }
}

bitflags! {
    pub struct MmapFlags {
        const SHARED = 1 << 0;
        const PRIVATE = 1 << 1;
        const SHARED_VALIDATE = (1 << 0) | (1 << 1);
        const FIXED = 1 << 4;
        const ANONYMOUS = 1 << 5;
        const DENYWRITE = 1 << 11;
        const LOCKED = 1 << 13;
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
        SetLkW = 7,
        SetOwn = 8,
        GetOwn = 9,
        SetOwnEx = 15,
        GetOwnEx = 16,
        DupFdCloExec = 1030,
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
    pub fn exit(status: u8) -> Self {
        Self(u32::from(status) << 8)
    }

    pub fn signaled(signal: Signal) -> Self {
        Self(signal.get() as u32)
    }

    pub fn raw(self) -> u32 {
        self.0
    }
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
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Timespec {
    pub tv_sec: i32,
    pub tv_nsec: u32,
}

impl Timespec {
    pub const ZERO: Self = Self {
        tv_sec: 0,
        tv_nsec: 0,
    };

    pub const UTIME_NOW: u32 = 0x3FFFFFFF;
    pub const UTIME_OMIT: u32 = 0x3FFFFFFE;

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
        Unix = 1,
        Inet = 2,
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
        const IN = 0x00000001;
        const PRI = 0x00000002;
        const OUT = 0x00000004;
        const ERR = 0x00000008;
        const HUP = 0x00000010;
        const NVAL = 0x00000020;
        const RDNORM = 0x00000040;
        const RDBAND = 0x00000080;
        const WRNORM = 0x00000100;
        const WRBAND = 0x00000200;
        const MSG = 0x00000400;
        const RDHUP = 0x00002000;

        const EXCLUSIVE = 1 << 28;
        const WAKEUP = 1 << 29;
        const ONESHOT = 1 << 30;
        const LET = 1 << 31;
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
        Stack = 3,
        NoFile = 7,
    }
}

#[derive(Clone, Copy)]
pub struct RLimit {
    /// Soft limit
    pub rlim_cur: u32,
    /// Hard limit (ceiling for rlim_cur)
    pub rlim_max: u32,
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
            rlim_cur: u64::from(value.rlim_cur),
            rlim_max: u64::from(value.rlim_max),
        }
    }
}

impl TryFrom<RLimit64> for RLimit {
    type Error = Error;

    fn try_from(value: RLimit64) -> Result<Self> {
        Ok(Self {
            rlim_cur: u32::try_from(value.rlim_cur)?,
            rlim_max: u32::try_from(value.rlim_max)?,
        })
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
    pub const ABRT: Self = Self(6);
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

    pub fn new(value: u8) -> Result<Self> {
        ensure!((1..=64).contains(&value), Inval);
        Ok(Self(value))
    }

    pub fn get(&self) -> usize {
        usize::from(self.0)
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
        SetDumpable = 4,
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

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit)]
#[repr(C, u16)]
pub enum SocketAddr {
    #[expect(dead_code)]
    Unspecified(SocketAddrUnspecified) = 0,
    Inet(SocketAddrInet) = 2,
    #[expect(dead_code)]
    Netlink(SocketAddrNetlink) = 16,
}

#[derive(Default, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct SocketAddrUnspecified {
    _pad: [u8; 14],
}

impl fmt::Debug for SocketAddrUnspecified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketAddrUnspecified")
            .finish_non_exhaustive()
    }
}

#[derive(Default, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct SocketAddrInet {
    /// port in network byte order
    port: u16,
    /// internet address
    pub addr: [u8; 4],
    _pad: [u8; 8],
}

impl fmt::Debug for SocketAddrInet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketAddrInet")
            .field("addr", &self.addr)
            .field("port", &u16::from_be(self.port))
            .finish_non_exhaustive()
    }
}

impl From<SocketAddrInet> for SocketAddrV4 {
    fn from(value: SocketAddrInet) -> Self {
        Self::new(
            Ipv4Addr::new(value.addr[0], value.addr[1], value.addr[2], value.addr[3]),
            u16::from_be(value.port),
        )
    }
}

impl From<SocketAddrV4> for SocketAddrInet {
    fn from(value: SocketAddrV4) -> Self {
        Self {
            port: value.port().to_be(),
            addr: value.ip().octets(),
            _pad: [0; 8],
        }
    }
}

#[derive(Default, Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed(2))]
pub struct SocketAddrNetlink {
    _pad: u16,
    pub pid: u32,
    pub groups: u32,
    _pad2: [u8; 4],
}

bitflags! {
    pub struct SentToFlags {
        const OOB = 1 << 0;
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
        const CMSG_CLOEXEC = 0x40000000;
    }
}

bitflags! {
    pub struct SendMsgFlags {
        const NOSIGNAL = 0x4000;
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
        const DONTWAIT = 1 << 6;
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Linger {
    pub onoff: i32,
    pub linger: i32,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnixAddr {
    Pathname(Path),
    Unnamed,
    Abstract(Vec<u8>),
}

impl UnixAddr {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() >= 2, Inval);
        let (family, path) = bytes.split_first_chunk::<2>().ok_or(err!(Inval))?;
        let family = u16::from_ne_bytes(*family);
        ensure!(family == Domain::Unix as u16, Inval);

        Ok(match path {
            [] => Self::Unnamed,
            [0, name @ ..] => Self::Abstract(name.to_owned()),
            mut path => {
                // Truncate at the null-terminator (if there is one).
                if let Some(idx) = path.iter().position(|&b| b == 0) {
                    path = &path[..idx];
                }
                Self::Pathname(Path::new(path.to_owned())?)
            }
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(Domain::Unix as u16).to_ne_bytes());
        match self {
            UnixAddr::Pathname(path) => bytes.extend_from_slice(path.as_bytes()),
            UnixAddr::Unnamed => {}
            UnixAddr::Abstract(name) => bytes.extend_from_slice(name),
        }
        bytes
    }
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
