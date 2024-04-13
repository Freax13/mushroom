use core::{convert::Infallible, num::TryFromIntError, panic::Location};

use bytemuck::checked::CheckedCastError;
use x86_64::addr::VirtAddrNotValid;

/// Construct an error of the given kind.
macro_rules! err {
    ($err:ident) => {
        crate::error::Error::from_kind(crate::error::ErrorKind::$err)
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
    caller_location: &'static Location<'static>,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    #[doc(hidden)]
    #[track_caller]
    pub fn from_kind(kind: ErrorKind) -> Self {
        Self {
            kind,
            caller_location: Location::caller(),
        }
    }
}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?} at {}", self.kind, self.caller_location)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Perm = 1,
    NoEnt = 2,
    Intr = 4,
    Io = 5,
    XIo = 6,
    NoExec = 8,
    BadF = 9,
    Child = 10,
    Again = 11,
    NoMem = 12,
    Acces = 13,
    Fault = 14,
    Exist = 17,
    NoDev = 19,
    NotDir = 20,
    IsDir = 21,
    Inval = 22,
    Mfile = 24,
    NoTty = 25,
    SPipe = 29,
    Pipe = 32,
    Range = 34,
    NoSys = 38,
    NotEmpty = 39,
    NameTooLong = 78,
    Loop = 90,
    TimedOut = 110,
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

pub type Result<T, E = Error> = core::result::Result<T, E>;
