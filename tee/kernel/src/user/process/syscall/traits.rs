use alloc::{boxed::Box, sync::Arc};
use core::{
    cell::RefCell,
    fmt::{self, Display},
    future::Future,
    pin::Pin,
};

use log::{trace, warn};

use crate::{
    error::{Error, Result},
    per_cpu::PerCpu,
    user::process::{
        memory::VirtualMemoryActivator,
        thread::{Thread, ThreadGuard},
    },
};

use super::args::{Ignored, SyscallArg};

pub type SyscallResult = Result<u64>;

impl SyscallArg for u32 {
    fn parse(value: u64) -> Result<Self> {
        Ok(u32::try_from(value)?)
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        _thread: &ThreadGuard<'_>,
        _vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        if let Ok(value) = u32::try_from(value) {
            write!(f, "{value}")
        } else {
            write!(f, "{value} (out of bounds)")
        }
    }
}

pub trait Syscall0 {
    const NO: usize;
    const NAME: &'static str;

    async fn execute(thread: Arc<Thread>) -> SyscallResult;

    fn display(
        f: &mut dyn fmt::Write,
        _thread: &ThreadGuard<'_>,
        _vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        write!(f, "{}()", Self::NAME)
    }
}

pub trait Syscall1 {
    const NO: usize;
    const NAME: &'static str;

    type Arg0: SyscallArg;
    const ARG0_NAME: &'static str;

    async fn execute(thread: Arc<Thread>, arg0: Self::Arg0) -> SyscallResult;

    fn display(
        f: &mut dyn fmt::Write,
        arg0: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        write!(f, "{}({}=", Self::NAME, Self::ARG0_NAME)?;
        <Self::Arg0>::display(f, arg0, thread, vm_activator)?;
        write!(f, ")")
    }
}

pub trait Syscall2 {
    const NO: usize;
    const NAME: &'static str;

    type Arg0: SyscallArg;
    const ARG0_NAME: &'static str;
    type Arg1: SyscallArg;
    const ARG1_NAME: &'static str;

    async fn execute(thread: Arc<Thread>, arg0: Self::Arg0, arg1: Self::Arg1) -> SyscallResult;

    fn display(
        f: &mut dyn fmt::Write,
        arg0: u64,
        arg1: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        write!(f, "{}({}=", Self::NAME, Self::ARG0_NAME)?;
        <Self::Arg0>::display(f, arg0, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG1_NAME)?;
        <Self::Arg1>::display(f, arg1, thread, vm_activator)?;
        write!(f, ")")
    }
}

pub trait Syscall3 {
    const NO: usize;
    const NAME: &'static str;

    type Arg0: SyscallArg;
    const ARG0_NAME: &'static str;
    type Arg1: SyscallArg;
    const ARG1_NAME: &'static str;
    type Arg2: SyscallArg;
    const ARG2_NAME: &'static str;

    async fn execute(
        thread: Arc<Thread>,
        arg0: Self::Arg0,
        arg1: Self::Arg1,
        arg2: Self::Arg2,
    ) -> SyscallResult;

    fn display(
        f: &mut dyn fmt::Write,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        write!(f, "{}({}=", Self::NAME, Self::ARG0_NAME)?;
        <Self::Arg0>::display(f, arg0, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG1_NAME)?;
        <Self::Arg1>::display(f, arg1, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG2_NAME)?;
        <Self::Arg2>::display(f, arg2, thread, vm_activator)?;
        write!(f, ")")
    }
}

pub trait Syscall4 {
    const NO: usize;
    const NAME: &'static str;

    type Arg0: SyscallArg;
    const ARG0_NAME: &'static str;
    type Arg1: SyscallArg;
    const ARG1_NAME: &'static str;
    type Arg2: SyscallArg;
    const ARG2_NAME: &'static str;
    type Arg3: SyscallArg;
    const ARG3_NAME: &'static str;

    async fn execute(
        thread: Arc<Thread>,
        arg0: Self::Arg0,
        arg1: Self::Arg1,
        arg2: Self::Arg2,
        arg3: Self::Arg3,
    ) -> SyscallResult;

    fn display(
        f: &mut dyn fmt::Write,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        write!(f, "{}({}=", Self::NAME, Self::ARG0_NAME)?;
        <Self::Arg0>::display(f, arg0, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG1_NAME)?;
        <Self::Arg1>::display(f, arg1, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG2_NAME)?;
        <Self::Arg2>::display(f, arg2, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG3_NAME)?;
        <Self::Arg3>::display(f, arg3, thread, vm_activator)?;
        write!(f, ")")
    }
}

pub trait Syscall5 {
    const NO: usize;
    const NAME: &'static str;

    type Arg0: SyscallArg;
    const ARG0_NAME: &'static str;
    type Arg1: SyscallArg;
    const ARG1_NAME: &'static str;
    type Arg2: SyscallArg;
    const ARG2_NAME: &'static str;
    type Arg3: SyscallArg;
    const ARG3_NAME: &'static str;
    type Arg4: SyscallArg;
    const ARG4_NAME: &'static str;

    async fn execute(
        thread: Arc<Thread>,
        arg0: Self::Arg0,
        arg1: Self::Arg1,
        arg2: Self::Arg2,
        arg3: Self::Arg3,
        arg4: Self::Arg4,
    ) -> SyscallResult;

    #[allow(clippy::too_many_arguments)]
    fn display(
        f: &mut dyn fmt::Write,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        write!(f, "{}({}=", Self::NAME, Self::ARG0_NAME)?;
        <Self::Arg0>::display(f, arg0, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG1_NAME)?;
        <Self::Arg1>::display(f, arg1, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG2_NAME)?;
        <Self::Arg2>::display(f, arg2, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG3_NAME)?;
        <Self::Arg3>::display(f, arg3, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG4_NAME)?;
        <Self::Arg4>::display(f, arg4, thread, vm_activator)?;
        write!(f, ")")
    }
}

pub trait Syscall6 {
    const NO: usize;
    const NAME: &'static str;

    type Arg0: SyscallArg;
    const ARG0_NAME: &'static str;
    type Arg1: SyscallArg;
    const ARG1_NAME: &'static str;
    type Arg2: SyscallArg;
    const ARG2_NAME: &'static str;
    type Arg3: SyscallArg;
    const ARG3_NAME: &'static str;
    type Arg4: SyscallArg;
    const ARG4_NAME: &'static str;
    type Arg5: SyscallArg;
    const ARG5_NAME: &'static str;

    #[allow(clippy::too_many_arguments)]
    async fn execute(
        thread: Arc<Thread>,
        arg0: Self::Arg0,
        arg1: Self::Arg1,
        arg2: Self::Arg2,
        arg3: Self::Arg3,
        arg4: Self::Arg4,
        arg5: Self::Arg5,
    ) -> SyscallResult;

    #[allow(clippy::too_many_arguments)]
    fn display(
        f: &mut dyn fmt::Write,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        write!(f, "{}({}=", Self::NAME, Self::ARG0_NAME)?;
        <Self::Arg0>::display(f, arg0, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG1_NAME)?;
        <Self::Arg1>::display(f, arg1, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG2_NAME)?;
        <Self::Arg2>::display(f, arg2, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG3_NAME)?;
        <Self::Arg3>::display(f, arg3, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG4_NAME)?;
        <Self::Arg4>::display(f, arg4, thread, vm_activator)?;
        write!(f, ", {}=", Self::ARG5_NAME)?;
        <Self::Arg5>::display(f, arg5, thread, vm_activator)?;
        write!(f, ")")
    }
}

impl<T> Syscall1 for T
where
    T: Syscall0,
{
    const NO: usize = <T as Syscall0>::NO;
    const NAME: &'static str = <T as Syscall0>::NAME;

    type Arg0 = Ignored;
    const ARG0_NAME: &'static str = "ignored";

    async fn execute(thread: Arc<Thread>, _arg0: Self::Arg0) -> SyscallResult {
        <T as Syscall0>::execute(thread).await
    }

    fn display(
        f: &mut dyn fmt::Write,
        _arg0: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        <T as Syscall0>::display(f, thread, vm_activator)
    }
}

impl<T> Syscall2 for T
where
    T: Syscall1,
{
    const NO: usize = <T as Syscall1>::NO;
    const NAME: &'static str = <T as Syscall1>::NAME;

    type Arg0 = <T as Syscall1>::Arg0;
    const ARG0_NAME: &'static str = <T as Syscall1>::ARG0_NAME;
    type Arg1 = Ignored;
    const ARG1_NAME: &'static str = "ignored";

    async fn execute(thread: Arc<Thread>, arg0: Self::Arg0, _arg1: Self::Arg1) -> SyscallResult {
        <T as Syscall1>::execute(thread, arg0).await
    }

    fn display(
        f: &mut dyn fmt::Write,
        arg0: u64,
        _arg1: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        <T as Syscall1>::display(f, arg0, thread, vm_activator)
    }
}

impl<T> Syscall3 for T
where
    T: Syscall2,
{
    const NO: usize = <T as Syscall2>::NO;
    const NAME: &'static str = <T as Syscall2>::NAME;

    type Arg0 = <T as Syscall2>::Arg0;
    const ARG0_NAME: &'static str = <T as Syscall2>::ARG0_NAME;
    type Arg1 = <T as Syscall2>::Arg1;
    const ARG1_NAME: &'static str = <T as Syscall2>::ARG1_NAME;
    type Arg2 = Ignored;
    const ARG2_NAME: &'static str = "ignored";

    async fn execute(
        thread: Arc<Thread>,
        arg0: Self::Arg0,
        arg1: Self::Arg1,
        _arg2: Self::Arg2,
    ) -> SyscallResult {
        <T as Syscall2>::execute(thread, arg0, arg1).await
    }

    fn display(
        f: &mut dyn fmt::Write,
        arg0: u64,
        arg1: u64,
        _arg2: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        <T as Syscall2>::display(f, arg0, arg1, thread, vm_activator)
    }
}

impl<T> Syscall4 for T
where
    T: Syscall3,
{
    const NO: usize = <T as Syscall3>::NO;
    const NAME: &'static str = <T as Syscall3>::NAME;

    type Arg0 = <T as Syscall3>::Arg0;
    const ARG0_NAME: &'static str = <T as Syscall3>::ARG0_NAME;
    type Arg1 = <T as Syscall3>::Arg1;
    const ARG1_NAME: &'static str = <T as Syscall3>::ARG1_NAME;
    type Arg2 = <T as Syscall3>::Arg2;
    const ARG2_NAME: &'static str = <T as Syscall3>::ARG2_NAME;
    type Arg3 = Ignored;
    const ARG3_NAME: &'static str = "ignored";

    async fn execute(
        thread: Arc<Thread>,
        arg0: Self::Arg0,
        arg1: Self::Arg1,
        arg2: Self::Arg2,
        _arg3: Self::Arg3,
    ) -> SyscallResult {
        <T as Syscall3>::execute(thread, arg0, arg1, arg2).await
    }

    fn display(
        f: &mut dyn fmt::Write,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        _arg3: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        <T as Syscall3>::display(f, arg0, arg1, arg2, thread, vm_activator)
    }
}

impl<T> Syscall5 for T
where
    T: Syscall4,
{
    const NO: usize = <T as Syscall4>::NO;
    const NAME: &'static str = <T as Syscall4>::NAME;

    type Arg0 = <T as Syscall4>::Arg0;
    const ARG0_NAME: &'static str = <T as Syscall4>::ARG0_NAME;
    type Arg1 = <T as Syscall4>::Arg1;
    const ARG1_NAME: &'static str = <T as Syscall4>::ARG1_NAME;
    type Arg2 = <T as Syscall4>::Arg2;
    const ARG2_NAME: &'static str = <T as Syscall4>::ARG2_NAME;
    type Arg3 = <T as Syscall4>::Arg3;
    const ARG3_NAME: &'static str = <T as Syscall4>::ARG3_NAME;
    type Arg4 = Ignored;
    const ARG4_NAME: &'static str = "ignored";

    async fn execute(
        thread: Arc<Thread>,
        arg0: Self::Arg0,
        arg1: Self::Arg1,
        arg2: Self::Arg2,
        arg3: Self::Arg3,
        _arg4: Self::Arg4,
    ) -> SyscallResult {
        <T as Syscall4>::execute(thread, arg0, arg1, arg2, arg3).await
    }

    fn display(
        f: &mut dyn fmt::Write,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        _arg4: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        <T as Syscall4>::display(f, arg0, arg1, arg2, arg3, thread, vm_activator)
    }
}

impl<T> Syscall6 for T
where
    T: Syscall5,
{
    const NO: usize = <T as Syscall5>::NO;
    const NAME: &'static str = <T as Syscall5>::NAME;

    type Arg0 = <T as Syscall5>::Arg0;
    const ARG0_NAME: &'static str = <T as Syscall5>::ARG0_NAME;
    type Arg1 = <T as Syscall5>::Arg1;
    const ARG1_NAME: &'static str = <T as Syscall5>::ARG1_NAME;
    type Arg2 = <T as Syscall5>::Arg2;
    const ARG2_NAME: &'static str = <T as Syscall5>::ARG2_NAME;
    type Arg3 = <T as Syscall5>::Arg3;
    const ARG3_NAME: &'static str = <T as Syscall5>::ARG3_NAME;
    type Arg4 = <T as Syscall5>::Arg4;
    const ARG4_NAME: &'static str = <T as Syscall5>::ARG4_NAME;
    type Arg5 = Ignored;
    const ARG5_NAME: &'static str = "ignored";

    async fn execute(
        thread: Arc<Thread>,
        arg0: Self::Arg0,
        arg1: Self::Arg1,
        arg2: Self::Arg2,
        arg3: Self::Arg3,
        arg4: Self::Arg4,
        _arg5: Self::Arg5,
    ) -> SyscallResult {
        <T as Syscall5>::execute(thread, arg0, arg1, arg2, arg3, arg4).await
    }

    fn display(
        f: &mut dyn fmt::Write,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        _arg5: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        <T as Syscall5>::display(f, arg0, arg1, arg2, arg3, arg4, thread, vm_activator)
    }
}

const MAX_SYSCALL_HANDLER: usize = 327;

#[derive(Clone, Copy)]
struct SyscallHandler {
    #[allow(clippy::type_complexity)]
    execute: fn(
        thread: Arc<Thread>,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> Pin<Box<dyn Future<Output = SyscallResult> + Send>>,
    #[allow(clippy::type_complexity)]
    display: fn(
        f: &mut dyn fmt::Write,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result,
}

impl SyscallHandler {
    const fn new<T>() -> Self
    where
        T: Syscall6<execute(): Send>,
    {
        Self {
            execute: |thread: Arc<Thread>,
                      arg0: u64,
                      arg1: u64,
                      arg2: u64,
                      arg3: u64,
                      arg4: u64,
                      arg5: u64| {
                Box::pin(async move {
                    let arg0 = SyscallArg::parse(arg0)?;
                    let arg1 = SyscallArg::parse(arg1)?;
                    let arg2 = SyscallArg::parse(arg2)?;
                    let arg3 = SyscallArg::parse(arg3)?;
                    let arg4 = SyscallArg::parse(arg4)?;
                    let arg5 = SyscallArg::parse(arg5)?;
                    T::execute(thread, arg0, arg1, arg2, arg3, arg4, arg5).await
                })
            },
            display: T::display,
        }
    }
}

pub struct SyscallHandlers {
    handlers: [Option<SyscallHandler>; MAX_SYSCALL_HANDLER],
}

impl SyscallHandlers {
    pub const fn new() -> Self {
        Self {
            handlers: [None; MAX_SYSCALL_HANDLER],
        }
    }

    pub const fn register<T>(&mut self, val: T)
    where
        T: Syscall6<execute(): Send>,
    {
        self.handlers[T::NO] = Some(SyscallHandler::new::<T>());
        core::mem::forget(val);
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn execute(
        &self,
        thread: Arc<Thread>,
        syscall_no: u64,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> SyscallResult {
        let syscall_no = usize::try_from(syscall_no).unwrap();
        let handler = self
            .handlers
            .get(syscall_no)
            .copied()
            .flatten()
            .ok_or_else(|| {
                warn!("unsupported syscall: {syscall_no}");
                Error::no_sys(())
            })?;

        // Whether the syscall should occur in the debug logs.
        let enable_log = !matches!(syscall_no, 0 | 1) && thread.tid() != 1;

        let res = (handler.execute)(thread.clone(), arg0, arg1, arg2, arg3, arg4, arg5).await;

        if enable_log {
            VirtualMemoryActivator::r#do(move |vm_activator| {
                let guard = thread.lock();
                let formatted_syscall = FormattedSyscall {
                    handler,
                    arg0,
                    arg1,
                    arg2,
                    arg3,
                    arg4,
                    arg5,
                    thread: &guard,
                    vm_activator: RefCell::new(vm_activator),
                };

                trace!(
                    "core={} tid={} @ {formatted_syscall} = {res:?}",
                    PerCpu::get().idx,
                    guard.tid()
                );
            })
            .await;
        }

        res
    }
}

struct FormattedSyscall<'a> {
    handler: SyscallHandler,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    thread: &'a ThreadGuard<'a>,
    vm_activator: RefCell<&'a mut VirtualMemoryActivator>,
}

impl Display for FormattedSyscall<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (self.handler.display)(
            f,
            self.arg0,
            self.arg1,
            self.arg2,
            self.arg3,
            self.arg4,
            self.arg5,
            self.thread,
            &mut self.vm_activator.borrow_mut(),
        )
    }
}
