use core::{intrinsics::caller_location, num::TryFromIntError, panic::Location};

#[derive(Clone, Copy)]
pub struct Error {
    kind: ErrorKind,
    caller_location: &'static Location<'static>,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    #[track_caller]
    fn from_kind(kind: ErrorKind) -> Self {
        Self {
            kind,
            caller_location: caller_location(),
        }
    }
}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?} at {}", self.kind, self.caller_location)
    }
}

macro_rules! errors {
    (
        $($variant:ident $fn:ident $expr:expr,)*
    ) => {
        #[derive(Debug, Clone, Copy)]
        pub enum ErrorKind {
            $($variant = $expr,)*
        }

        impl Error {
            $(
                #[track_caller]
                pub fn $fn((): ()) -> Self {
                    Self::from_kind(ErrorKind::$variant)
                }
            )*
        }
    };
}

errors! {
    NoEnt no_ent 2,
    Io io 5,
    NoExec no_exec 8,
    BadF bad_f 9,
    Child child 10,
    Again again 11,
    NoMem no_mem 12,
    Acces acces 13,
    Fault fault 14,
    Exist exist 17,
    NoDev no_dev 19,
    NotDir not_dir 20,
    IsDir is_dir 21,
    Inval inval 22,
    NoTty no_tty 25,
    NoSys no_sys 38,
    NameTooLong name_too_long 78,
    Loop r#loop 90,
}

impl From<TryFromIntError> for Error {
    #[track_caller]
    fn from(_: TryFromIntError) -> Self {
        Error::inval(())
    }
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
