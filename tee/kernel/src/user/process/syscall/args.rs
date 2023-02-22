use core::fmt::{self, Display};

use bytemuck::{Pod, Zeroable};
use x86_64::VirtAddr;

use crate::error::{Error, Result};

pub trait SyscallArg: Display + Copy {
    fn parse(value: u64) -> Result<Self>;

    fn display(f: &mut dyn fmt::Write, value: u64) -> fmt::Result;
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
                Self::from_bits(value).ok_or(Error::Inval)
            }

            fn display(f: &mut dyn fmt::Write, value: u64) -> fmt::Result {
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
                    _ => Err(Error::Inval),
                }
            }

            fn display(f: &mut dyn fmt::Write, value: u64) -> fmt::Result {
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

    fn display(f: &mut dyn fmt::Write, _value: u64) -> fmt::Result {
        write!(f, "ignored")
    }
}

#[derive(Clone, Copy)]
pub struct Pointer(u64);

impl Pointer {
    pub fn is_null(&self) -> bool {
        self.0 == 0
    }

    pub fn get(self) -> VirtAddr {
        VirtAddr::new(self.0)
    }
}

impl Display for Pointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#}", self.0)
    }
}

impl SyscallArg for Pointer {
    fn parse(value: u64) -> Result<Self> {
        Ok(Self(value))
    }

    fn display(f: &mut dyn fmt::Write, value: u64) -> fmt::Result {
        write!(f, "{value:#x}")
    }
}

impl SyscallArg for u64 {
    fn parse(value: u64) -> Result<Self> {
        Ok(value)
    }

    fn display(f: &mut dyn fmt::Write, value: u64) -> fmt::Result {
        write!(f, "{value}")
    }
}

bitflags! {
    pub struct OpenFlags {
        const WRONLY = 1 << 0;
        const RDWR = 1 << 1;
        const CREAT = 1 << 6;
        const EXCL = 1 << 9;
        const SYNC = 1 << 19;
    }
}

bitflags! {
    pub struct FileMode {
        const EXECUTE = 1 << 0;
        const WRITE = 1 << 1;
        const READ = 1 << 2;
        const GROUP_EXECUTE = 1 << 3;
        const GROUP_WRITE = 1 << 4;
        const GROUP_READ = 1 << 5;
        const OWNER_EXECUTE = 1 << 6;
        const OWNER_WRITE = 1 << 7;
        const OWNER_READ = 1 << 8;
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

#[derive(Clone, Copy)]
pub struct Fd(i32);

impl Fd {
    pub fn new(value: i32) -> Self {
        Self(value)
    }

    pub fn get(self) -> i32 {
        self.0
    }
}

impl Display for Fd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl SyscallArg for Fd {
    fn parse(value: u64) -> Result<Self> {
        match i32::try_from(value) {
            Ok(fd) if fd >= 0 => Ok(Self(fd)),
            _ => Err(Error::BadF),
        }
    }

    fn display(f: &mut dyn fmt::Write, value: u64) -> fmt::Result {
        match Self::parse(value) {
            Ok(fd) => write!(f, "{fd}"),
            Err(_) => write!(f, "{value} (invalid fd)"),
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
        SetFd = 2,
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
        REQUEUE = 3,
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

    fn display(f: &mut dyn fmt::Write, value: u64) -> fmt::Result {
        FutexOp::display(f, value & 0x7f);
        write!(f, " | ")?;
        FutexFlags::display(f, value & !0x7f)
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
