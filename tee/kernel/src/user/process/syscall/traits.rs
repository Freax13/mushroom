use alloc::sync::Arc;
#[cfg(not(feature = "harden"))]
use core::fmt::Write;
use core::{
    fmt::{self, Display},
    marker::PhantomPinned,
    mem::{MaybeUninit, align_of, size_of},
    ops::{Deref, DerefMut},
    pin::{Pin, pin},
    ptr::Pointee,
};
use usize_conversions::usize_from;

use log::{trace, warn};

use crate::{
    error::{Result, err},
    per_cpu::PerCpu,
    user::process::thread::{Thread, ThreadGuard},
};

use super::{SYSCALL_HANDLERS, args::SyscallArg};

#[derive(Clone, Copy, Debug)]
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

    fn execute(
        thread: Arc<Thread>,
        syscall_args: SyscallArgs,
    ) -> impl Future<Output = SyscallResult> + Send + 'static;

    fn display(
        f: &mut dyn fmt::Write,
        syscall_args: SyscallArgs,
        thread: &ThreadGuard<'_>,
    ) -> fmt::Result;
}

const MAX_SYSCALL_I386_HANDLER: usize = 453;
const MAX_SYSCALL_AMD64_HANDLER: usize = 453;

type DynFuture = dyn Future<Output = SyscallResult> + Send;

#[derive(Clone, Copy)]
struct SyscallHandler {
    create_future: for<'a> fn(
        Pin<&'a mut SyscallHandlerSlot>,
        thread: Arc<Thread>,
        args: SyscallArgs,
    ) -> Pin<Placed<'a>>,
    display: fn(f: &mut dyn fmt::Write, args: SyscallArgs, thread: &ThreadGuard<'_>) -> fmt::Result,
}

impl SyscallHandler {
    const fn new<T>() -> Self
    where
        T: Syscall,
    {
        Self {
            create_future: |slot, thread: Arc<Thread>, args: SyscallArgs| {
                slot.place(T::execute(thread, args))
            },
            display: T::display,
        }
    }
}

pub struct SyscallHandlers {
    i386_handlers: [Option<SyscallHandler>; MAX_SYSCALL_I386_HANDLER],
    amd64_handlers: [Option<SyscallHandler>; MAX_SYSCALL_AMD64_HANDLER],
    /// This value keeps track of the size of the biggest future returned by a
    /// syscall handler.
    future_size: usize,
    /// This value keeps track of the alignment of the future with the biggest
    /// alignment requirement returned by a syscall handler.
    future_align: usize,
}

impl SyscallHandlers {
    pub const fn new() -> Self {
        Self {
            i386_handlers: [None; MAX_SYSCALL_I386_HANDLER],
            amd64_handlers: [None; MAX_SYSCALL_AMD64_HANDLER],
            future_size: 0,
            future_align: 1,
        }
    }

    pub const fn register<T>(&mut self, val: T)
    where
        T: Syscall,
    {
        if let Some(no) = T::NO_I386 {
            assert!(self.i386_handlers[no].is_none());
            self.i386_handlers[no] = Some(SyscallHandler::new::<T>());
        }
        if let Some(no) = T::NO_AMD64 {
            assert!(self.amd64_handlers[no].is_none());
            self.amd64_handlers[no] = Some(SyscallHandler::new::<T>());
        }
        core::mem::forget(val);

        // Keep track of the future size and alignment.

        /// Returns the size of the return type of `T::execute`.
        const fn return_size<T>(
            _: fn(thread: Arc<Thread>, syscall_args: SyscallArgs) -> T,
        ) -> usize {
            size_of::<T>()
        }
        let return_size = return_size(T::execute);
        if self.future_size < return_size {
            self.future_size = return_size;
        }

        /// Returns the alignment of the return type of `T::execute`.
        const fn return_align<T>(
            _: fn(thread: Arc<Thread>, syscall_args: SyscallArgs) -> T,
        ) -> usize {
            core::mem::align_of::<T>()
        }
        let return_align = return_align(T::execute);
        if self.future_align < return_align {
            self.future_align = return_align;
        }
    }

    pub async fn execute(&self, thread: Arc<Thread>, args: SyscallArgs) -> SyscallResult {
        let syscall_no = usize_from(args.no);

        let handlers: &[_] = match args.abi {
            Abi::I386 => &self.i386_handlers,
            Abi::Amd64 => &self.amd64_handlers,
        };

        let handler = handlers.get(syscall_no).copied().flatten().ok_or_else(|| {
            warn!("unsupported syscall: no={syscall_no}, abi={:?}", args.abi);
            err!(NoSys)
        })?;

        // Whether the syscall should occur in the debug logs.
        let enable_log = !matches!(syscall_no, 0 | 1 | 202 | 228) && thread.tid() != 1;

        let mut slot = SyscallHandlerSlot::new();
        let slot = pin!(slot);
        let placed = (handler.create_future)(slot, thread.clone(), args);
        let res = placed.await;

        if enable_log {
            let guard = thread.lock();
            let formatted_syscall = FormattedSyscall {
                handler,
                args,
                thread: &guard,
            };

            trace!(
                "core={} tid={} abi={:?} @ {formatted_syscall} = ({res:?})",
                PerCpu::get().idx,
                guard.tid(),
                args.abi,
            );
        }

        res
    }
}

#[cfg(not(feature = "harden"))]
pub fn dump_syscall_exit(
    thread: &ThreadGuard,
    args: SyscallArgs,
    indent: usize,
    mut write: impl Write,
) -> fmt::Result {
    let handlers = match args.abi {
        Abi::I386 => SYSCALL_HANDLERS.i386_handlers.as_slice(),
        Abi::Amd64 => SYSCALL_HANDLERS.amd64_handlers.as_slice(),
    };

    if let Some(handler) = handlers.get(usize_from(args.no)).cloned().flatten() {
        let formatted_syscall = FormattedSyscall {
            handler,
            args,
            thread,
        };
        writeln!(write, "{:indent$}{formatted_syscall}", "")
    } else {
        writeln!(write, "{:indent$}unknown syscall", "")
    }
}

const SIZE: usize = SYSCALL_HANDLERS.future_size;
const ALIGN: usize = SYSCALL_HANDLERS.future_align;

/// A chunk of memory that can be used to store future returned by a syscall
/// handler.
#[repr(align(8))]
struct SyscallHandlerSlot {
    bytes: MaybeUninit<[u8; SIZE]>,
    _marker: PhantomPinned,
}

impl SyscallHandlerSlot {
    pub const fn new() -> Self {
        assert!(align_of::<Self>() == ALIGN);

        Self {
            bytes: MaybeUninit::uninit(),
            _marker: PhantomPinned,
        }
    }

    pub fn place<T>(mut self: Pin<&mut Self>, future: T) -> Pin<Placed<'_>>
    where
        T: Future<Output = SyscallResult> + Send + 'static,
    {
        let metadata = core::ptr::metadata(&future as *const DynFuture);

        assert!(size_of::<T>() <= SIZE);
        assert!(align_of::<T>() <= align_of::<Self>());
        unsafe {
            // SAFETY: We're not moving the data out. We checked size and
            // alignment requirements for the future.
            let this = self.as_mut().get_unchecked_mut();
            this.bytes.as_mut_ptr().cast::<T>().write(future);
        }

        let placed = Placed {
            metadata,
            slot: self,
        };
        unsafe {
            // Safety:
            Pin::new_unchecked(placed)
        }
    }
}

/// A smart pointer representing a future that has been placed in a
/// `SyscallHandlerSlot`.
struct Placed<'a> {
    metadata: <DynFuture as Pointee>::Metadata,
    slot: Pin<&'a mut SyscallHandlerSlot>,
}

impl Placed<'_> {
    fn as_ptr(&self) -> *const DynFuture {
        core::ptr::from_raw_parts(self.slot.bytes.as_ptr().cast::<()>(), self.metadata)
    }

    fn as_mut_ptr(&mut self) -> *mut DynFuture {
        core::ptr::from_raw_parts_mut(
            self.slot.bytes.as_ptr().cast_mut().cast::<()>(),
            self.metadata,
        )
    }
}

impl Deref for Placed<'_> {
    type Target = DynFuture;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.as_ptr() }
    }
}

impl DerefMut for Placed<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.as_mut_ptr() }
    }
}

impl Drop for Placed<'_> {
    fn drop(&mut self) {
        unsafe {
            core::ptr::drop_in_place(self.as_mut_ptr());
        }
    }
}

struct FormattedSyscall<'a> {
    handler: SyscallHandler,
    args: SyscallArgs,
    thread: &'a ThreadGuard<'a>,
}

impl Display for FormattedSyscall<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (self.handler.display)(f, self.args, self.thread)
    }
}
