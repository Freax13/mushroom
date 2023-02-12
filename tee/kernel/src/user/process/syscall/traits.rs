use log::warn;

use crate::{
    error::{Error, Result},
    user::process::thread::Thread,
};

pub trait Syscall0 {
    const NO: usize;

    fn execute(thread: &mut Thread) -> Result<u64>;
}

pub trait Syscall1 {
    const NO: usize;

    fn execute(thread: &mut Thread, arg0: u64) -> Result<u64>;
}

pub trait Syscall2 {
    const NO: usize;

    fn execute(thread: &mut Thread, arg0: u64, arg1: u64) -> Result<u64>;
}

pub trait Syscall3 {
    const NO: usize;

    fn execute(thread: &mut Thread, arg0: u64, arg1: u64, arg2: u64) -> Result<u64>;
}

pub trait Syscall4 {
    const NO: usize;

    fn execute(thread: &mut Thread, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> Result<u64>;
}

pub trait Syscall5 {
    const NO: usize;

    fn execute(
        thread: &mut Thread,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
    ) -> Result<u64>;
}

pub trait Syscall6 {
    const NO: usize;

    fn execute(
        thread: &mut Thread,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> Result<u64>;
}

impl<T> Syscall1 for T
where
    T: Syscall0,
{
    const NO: usize = <T as Syscall0>::NO;

    fn execute(thread: &mut Thread, arg0: u64) -> Result<u64> {
        <T as Syscall0>::execute(thread)
    }
}

impl<T> Syscall2 for T
where
    T: Syscall1,
{
    const NO: usize = <T as Syscall1>::NO;

    fn execute(thread: &mut Thread, arg0: u64, arg1: u64) -> Result<u64> {
        <T as Syscall1>::execute(thread, arg0)
    }
}

impl<T> Syscall3 for T
where
    T: Syscall2,
{
    const NO: usize = <T as Syscall2>::NO;

    fn execute(thread: &mut Thread, arg0: u64, arg1: u64, arg2: u64) -> Result<u64> {
        <T as Syscall2>::execute(thread, arg0, arg1)
    }
}

impl<T> Syscall4 for T
where
    T: Syscall3,
{
    const NO: usize = <T as Syscall3>::NO;

    fn execute(thread: &mut Thread, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> Result<u64> {
        <T as Syscall3>::execute(thread, arg0, arg1, arg2)
    }
}

impl<T> Syscall5 for T
where
    T: Syscall4,
{
    const NO: usize = <T as Syscall4>::NO;

    fn execute(
        thread: &mut Thread,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
    ) -> Result<u64> {
        <T as Syscall4>::execute(thread, arg0, arg1, arg2, arg3)
    }
}

impl<T> Syscall6 for T
where
    T: Syscall5,
{
    const NO: usize = <T as Syscall5>::NO;

    fn execute(
        thread: &mut Thread,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> Result<u64> {
        <T as Syscall5>::execute(thread, arg0, arg1, arg2, arg3, arg4)
    }
}

const MAX_SYSCALL_HANDLER: usize = 232;

pub struct SyscallHandlers {
    handlers: [Option<
        fn(
            thread: &mut Thread,
            arg0: u64,
            arg1: u64,
            arg2: u64,
            arg3: u64,
            arg4: u64,
            arg5: u64,
        ) -> Result<u64>,
    >; MAX_SYSCALL_HANDLER],
}

impl SyscallHandlers {
    pub const fn new() -> Self {
        Self {
            handlers: [None; MAX_SYSCALL_HANDLER],
        }
    }

    pub const fn register<T>(&mut self, val: T)
    where
        T: Syscall6,
    {
        self.handlers[T::NO] = Some(T::execute);
        core::mem::forget(val);
    }

    pub fn execute(
        &self,
        thread: &mut Thread,
        syscall_no: u64,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> Result<u64> {
        let syscall_no = usize::try_from(syscall_no).unwrap();
        let handler = self
            .handlers
            .get(syscall_no)
            .copied()
            .flatten()
            .ok_or_else(|| {
                warn!("unsupported syscall: {syscall_no}");
                Error::NoSys
            })?;
        (handler)(thread, arg0, arg1, arg2, arg3, arg4, arg5)
    }
}
