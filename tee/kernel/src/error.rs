use core::{convert::Infallible, num::TryFromIntError};

use alloc::collections::TryReserveError;
use bytemuck::checked::CheckedCastError;
use x86_64::addr::VirtAddrNotValid;

/// Construct an error of the given kind.
macro_rules! err {
    ($err:ident) => {
        const { crate::error::Error::from_kind(crate::error::ErrorKind::$err) }
    };
}

/// Construct and return with an error of the given kind.
macro_rules! bail {
    ($err:ident) => {
        return Err(crate::error::err!($err))
    };
}

/// Check an condition and return with an error of the given kind if the
/// expression is false.
macro_rules! ensure {
    ($condition:expr, $err:ident) => {
        if !$condition {
            crate::error::bail!($err);
        }
    };
}

pub(crate) use {bail, ensure, err};

#[derive(Clone, Copy)]
pub struct Error {
    kind: ErrorKind,
    #[cfg(not(feature = "harden"))]
    caller_location: &'static core::panic::Location<'static>,
}

impl Error {
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    #[doc(hidden)]
    #[cfg_attr(not(feature = "harden"), track_caller)]
    pub const fn from_kind(kind: ErrorKind) -> Self {
        Self {
            kind,
            #[cfg(not(feature = "harden"))]
            caller_location: core::panic::Location::caller(),
        }
    }
}

#[cfg(feature = "harden")]
impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.kind)
    }
}

#[cfg(not(feature = "harden"))]
impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?} at {}", self.kind, self.caller_location)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Perm = 1,
    NoEnt = 2,
    Srch = 3,
    Intr = 4,
    Io = 5,
    NxIo = 6,
    NoExec = 8,
    BadF = 9,
    Child = 10,
    Again = 11,
    NoMem = 12,
    Acces = 13,
    Fault = 14,
    Busy = 16,
    Exist = 17,
    XDev = 18,
    NoDev = 19,
    NotDir = 20,
    IsDir = 21,
    Inval = 22,
    Mfile = 24,
    NoTty = 25,
    NoSpc = 28,
    SPipe = 29,
    Pipe = 32,
    Range = 34,
    NameTooLong = 36,
    NoSys = 38,
    NotEmpty = 39,
    Loop = 40,
    NotSock = 88,
    MsgSize = 90,
    OpNotSupp = 95,
    AFNoSupport = 97,
    AddrInUse = 98,
    AddrNotAvail = 99,
    NetUnreach = 101,
    ConnReset = 104,
    IsConn = 106,
    NotConn = 107,
    TimedOut = 110,
    ConnRefused = 111,
    RestartNoIntr = 512,
}

impl From<TryFromIntError> for Error {
    #[track_caller]
    fn from(_: TryFromIntError) -> Self {
        err!(Inval)
    }
}

impl From<CheckedCastError> for Error {
    #[track_caller]
    fn from(_: CheckedCastError) -> Self {
        err!(Inval)
    }
}

impl From<Infallible> for Error {
    fn from(err: Infallible) -> Self {
        match err {}
    }
}

impl From<VirtAddrNotValid> for Error {
    #[track_caller]
    fn from(_: VirtAddrNotValid) -> Self {
        err!(Fault)
    }
}

impl From<TryReserveError> for Error {
    #[track_caller]
    fn from(_: TryReserveError) -> Self {
        err!(NoMem)
    }
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
