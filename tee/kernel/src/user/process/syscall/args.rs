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
