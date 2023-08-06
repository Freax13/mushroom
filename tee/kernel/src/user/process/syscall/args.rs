use core::{
    ffi::{c_void, CStr},
    fmt::{self, Display},
    marker::PhantomData,
};

use bit_field::BitField;
use bytemuck::{checked, CheckedBitPattern, NoUninit, Pod, Zeroable};
use x86_64::VirtAddr;

use crate::{
    error::{Error, Result},
    user::process::{
        memory::VirtualMemoryActivator,
        thread::{Sigaction, Sigset, Stack, ThreadGuard},
    },
};

pub trait SyscallArg: Display + Send + Copy {
    fn parse(value: u64) -> Result<Self>;

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result;
}

macro_rules! bitflags {
    (pub struct $strukt:ident {
        $(
            const $constant:ident = $expr:expr;
        )*
    }) => {
        bitflags::bitflags! {
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
            fn parse(value: u64) -> Result<Self> {
                Self::from_bits(value).ok_or(Error::inval(()))
            }

            fn display(
                f: &mut dyn fmt::Write,
                value: u64,
                _thread: &ThreadGuard<'_>,
                _vm_activator: &mut VirtualMemoryActivator,
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
            fn parse(value: u64) -> Result<Self> {
                match value {
                    $(
                        value if value == Self::$variant as u64 => Ok(Self::$variant),
                    )*
                    _ => Err(Error::inval(())),
                }
            }

            fn display(
                f: &mut dyn fmt::Write,
                value: u64,
                _thread: &ThreadGuard<'_>,
                _vm_activator: &mut VirtualMemoryActivator,
            ) -> fmt::Result {
                match Self::parse(value) {
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
    fn parse(_value: u64) -> Result<Self> {
        Ok(Self(()))
    }

    fn display(
        f: &mut dyn fmt::Write,
        _value: u64,
        _thread: &ThreadGuard<'_>,
        _vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        write!(f, "ignored")
    }
}

pub struct Pointer<T>
where
    T: ?Sized,
{
    value: u64,
    _marker: PhantomData<T>,
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

impl<T> SyscallArg for Pointer<T>
where
    T: Pointee + Send + ?Sized,
{
    fn parse(value: u64) -> Result<Self> {
        Ok(Self {
            value,
            _marker: PhantomData,
        })
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        T::display(f, VirtAddr::new(value), thread, vm_activator)
    }
}

pub trait Pointee {
    fn display(
        f: &mut dyn fmt::Write,
        addr: VirtAddr,
        thread: &ThreadGuard,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        let _ = thread;
        let _ = vm_activator;
        write!(f, "{:#x}", addr.as_u64())
    }
}

impl Pointee for CStr {
    fn display(
        f: &mut dyn fmt::Write,
        addr: VirtAddr,
        thread: &ThreadGuard,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        let res = vm_activator.activate(thread.virtual_memory(), |vm| vm.read_cstring(addr, 128));
        match res {
            Ok(value) => write!(f, "{value:?}"),
            Err(_) => write!(f, "{:#x} (invalid ptr)", addr.as_u64()),
        }
    }
}

impl Pointee for [&'static CStr] {}
impl Pointee for [FdNum; 2] {}
impl Pointee for [u8] {}
impl Pointee for c_void {}
impl Pointee for FdNum {}
impl Pointee for Iovec {}
impl Pointee for LinuxDirent64 {}
impl Pointee for Sigaction {}
impl Pointee for Sigset {}
impl Pointee for Stack {}
impl Pointee for Stat {}
impl Pointee for Timespec {}
impl Pointee for u32 {}
impl Pointee for u64 {}
impl Pointee for WStatus {}

impl SyscallArg for u64 {
    fn parse(value: u64) -> Result<Self> {
        Ok(value)
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        _thread: &ThreadGuard<'_>,
        _vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        write!(f, "{value}")
    }
}

impl SyscallArg for i64 {
    fn parse(value: u64) -> Result<Self> {
        Ok(value as i64)
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        _thread: &ThreadGuard<'_>,
        _vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        write!(f, "{}", value as i64)
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
        const LARGEFILE = 1 << 15;
        const DIRECTORY = 1 << 16;
        const NOFOLLOW = 1 << 17;
        const SYNC = 1 << 19;
    }
}

bitflags! {
    pub struct FileMode {
        const ALL = 0o777;

        const EXECUTE = 0o001;
        const WRITE = 0o002;
        const READ = 0o004;
        const GROUP_EXECUTE = 0o010;
        const GROUP_WRITE = 0o020;
        const GROUP_READ = 0o040;
        const OWNER_EXECUTE = 0o100;
        const OWNER_WRITE = 0o200;
        const OWNER_READ = 0o400;
        const OWNER_ALL = 0o700;
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
        const SHARED_VALIDATE = 1 << 0 | 1 << 1;
        const FIXED = 1 << 4;
        const ANONYMOUS = 1 << 5;
        const STACK = 1 << 17;
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Pollfd {
    fd: i32,
    events: u16,
    revents: u16,
}

#[derive(Clone, Copy, PartialEq, Eq)]
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
        write!(f, "{}", self.0)
    }
}

impl SyscallArg for FdNum {
    fn parse(value: u64) -> Result<Self> {
        match i32::try_from(value as i64) {
            Ok(fd) => Ok(Self(fd)),
            _ => Err(Error::bad_f(())),
        }
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        _thread: &ThreadGuard<'_>,
        _vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        match Self::parse(value) {
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
        GetFd = 1,
        SetFd = 2,
        GetFl = 3,
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
    fn parse(value: u64) -> Result<Self> {
        let op = FutexOp::parse(value & 0x7f)?;
        let flags = FutexFlags::parse(value & !0x7f)?;
        Ok(Self { op, flags })
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        FutexOp::display(f, value & 0x7f, thread, vm_activator)?;
        write!(f, " | ")?;
        FutexFlags::display(f, value & !0x7f, thread, vm_activator)
    }
}

bitflags! {
    pub struct Pipe2Flags {
        const DIRECT = 1 << 14;
        const CLOEXEC = 1 << 19;
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

#[derive(Debug, Clone, Copy, Zeroable, NoUninit)]
#[repr(C)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    pub mode: FileTypeAndMode,
    pub uid: u32,
    pub gid: u32,
    pub _pad0: u32,
    pub rdev: u64,
    pub size: i64,
    pub blksize: i64,
    pub blocks: i64,
    pub atime: u64,
    pub atime_nsec: u64,
    pub mtime: u64,
    pub mtime_nsec: u64,
    pub ctime: u64,
    pub ctime_nsec: u64,
    pub _unused: [i64; 3],
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
        Self((ty as u32) << 12 | mode.bits() as u32)
    }

    pub fn ty(&self) -> FileType {
        checked::cast(self.0.get_bits(12..))
    }

    pub fn mode(&self) -> FileMode {
        FileMode::from_bits_truncate(u64::from(self.0))
    }
}

#[derive(Debug, Clone, Copy, CheckedBitPattern)]
#[repr(u32)]
pub enum FileType {
    Fifo = 0o01,
    Char = 0o02,
    Dir = 0o04,
    Block = 0o06,
    File = 0o10,
    Link = 0o12,
    Socket = 0o14,
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
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
        Free = 8,
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct WStatus(u32);

impl WStatus {
    pub fn exit(status: u8) -> Self {
        Self(u32::from(status) << 8)
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

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Timespec {
    pub tv_sec: u64,
    pub tv_nsec: u64,
}
