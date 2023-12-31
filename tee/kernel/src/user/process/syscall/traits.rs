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

use super::args::SyscallArg;

#[derive(Clone, Copy)]
pub struct SyscallArgs {
    pub abi: Abi,
    pub no: u64,
    pub args: [u64; 6],
}

/// The ABI used during a syscall.
#[derive(Debug, Clone, Copy)]
pub enum Abi {
    I386,
    Amd64,
}

pub type SyscallResult = Result<u64>;

impl SyscallArg for u32 {
    fn parse(value: u64, _abi: Abi) -> Result<Self> {
        Ok(u32::try_from(value)?)
    }

    fn display(
        f: &mut dyn fmt::Write,
        value: u64,
        _abi: Abi,
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

pub trait Syscall {
    const NO_I386: Option<usize>;
    const NO_AMD64: Option<usize>;
    const NAME: &'static str;

    #[allow(clippy::too_many_arguments)]
    async fn execute(thread: Arc<Thread>, syscall_args: SyscallArgs) -> SyscallResult;

    #[allow(clippy::too_many_arguments)]
    fn display(
        f: &mut dyn fmt::Write,
        syscall_args: SyscallArgs,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result;
}

const MAX_SYSCALL_I386_HANDLER: usize = 385;
const MAX_SYSCALL_AMD64_HANDLER: usize = 327;

#[derive(Clone, Copy)]
struct SyscallHandler {
    #[allow(clippy::type_complexity)]
    execute: fn(
        thread: Arc<Thread>,
        args: SyscallArgs,
    ) -> Pin<Box<dyn Future<Output = SyscallResult> + Send>>,
    #[allow(clippy::type_complexity)]
    display: fn(
        f: &mut dyn fmt::Write,
        args: SyscallArgs,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result,
}

impl SyscallHandler {
    const fn new<T>() -> Self
    where
        T: Syscall<execute(): Send>,
    {
        Self {
            execute: |thread: Arc<Thread>, args: SyscallArgs| {
                Box::pin(async move { T::execute(thread, args).await })
            },
            display: T::display,
        }
    }
}

pub struct SyscallHandlers {
    i386_handlers: [Option<SyscallHandler>; MAX_SYSCALL_I386_HANDLER],
    amd64_handlers: [Option<SyscallHandler>; MAX_SYSCALL_AMD64_HANDLER],
}

impl SyscallHandlers {
    pub const fn new() -> Self {
        Self {
            i386_handlers: [None; MAX_SYSCALL_I386_HANDLER],
            amd64_handlers: [None; MAX_SYSCALL_AMD64_HANDLER],
        }
    }

    pub const fn register<T>(&mut self, val: T)
    where
        T: Syscall<execute(): Send>,
    {
        if let Some(no) = T::NO_I386 {
            self.i386_handlers[no] = Some(SyscallHandler::new::<T>());
        }
        if let Some(no) = T::NO_AMD64 {
            self.amd64_handlers[no] = Some(SyscallHandler::new::<T>());
        }
        core::mem::forget(val);
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn execute(&self, thread: Arc<Thread>, args: SyscallArgs) -> SyscallResult {
        let syscall_no = usize::try_from(args.no).unwrap();

        let handlers: &[_] = match args.abi {
            Abi::I386 => &self.i386_handlers,
            Abi::Amd64 => &self.amd64_handlers,
        };

        let handler = handlers.get(syscall_no).copied().flatten().ok_or_else(|| {
            warn!("unsupported syscall: no={syscall_no}, abi={:?}", args.abi);
            Error::no_sys(())
        })?;

        // Whether the syscall should occur in the debug logs.
        let enable_log = !matches!(syscall_no, 0 | 1 | 202 | 228) && thread.tid() != 1;

        let res = (handler.execute)(thread.clone(), args).await;

        if enable_log {
            VirtualMemoryActivator::r#do(move |vm_activator| {
                let guard = thread.lock();
                let formatted_syscall = FormattedSyscall {
                    handler,
                    args,
                    thread: &guard,
                    vm_activator: RefCell::new(vm_activator),
                };

                trace!(
                    "core={} tid={} abi={:?} @ {formatted_syscall} = {res:?}",
                    PerCpu::get().idx,
                    guard.tid(),
                    args.abi,
                );
            })
            .await;
        }

        res
    }
}

struct FormattedSyscall<'a> {
    handler: SyscallHandler,
    args: SyscallArgs,
    thread: &'a ThreadGuard<'a>,
    vm_activator: RefCell<&'a mut VirtualMemoryActivator>,
}

impl Display for FormattedSyscall<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (self.handler.display)(
            f,
            self.args,
            self.thread,
            &mut self.vm_activator.borrow_mut(),
        )
    }
}
