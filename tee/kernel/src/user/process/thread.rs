use core::{
    ffi::{c_void, CStr},
    fmt::Debug,
    future::Future,
    ops::{BitAnd, BitAndAssign, BitOrAssign, Deref, DerefMut, Not},
    sync::atomic::{AtomicU32, Ordering},
};

use crate::{
    error::bail,
    fs::{
        fd::{FileDescriptor, FileDescriptorTable},
        node::{DynINode, FileAccessContext},
    },
    rt::notify::Notify,
    spin::mutex::{Mutex, MutexGuard},
    user::process::{
        memory::PageFaultError,
        thread::running_state::{ExitAction, ThreadRunningState},
    },
};
use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
};
use bit_field::BitField;
use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
use futures::{select_biased, FutureExt};
use x86_64::VirtAddr;

use crate::{
    error::Result,
    fs::{node::ROOT_NODE, path::Path},
    rt::{oneshot, spawn},
};

use super::{
    memory::VirtualMemory,
    syscall::{
        args::{FileMode, Pointer, RLimit, Resource, Signal, UserDesc},
        cpu_state::{CpuState, Exit, PageFaultExit},
        traits::SyscallArgs,
    },
    Process,
};

pub mod running_state;

pub fn new_tid() -> u32 {
    static PID_COUNTER: AtomicU32 = AtomicU32::new(1);
    PID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

pub type WeakThread = Weak<Thread>;

pub struct Thread {
    // Immutable state.
    tid: u32,
    process: Arc<Process>,
    signal_notify: Notify,
    running_state: ThreadRunningState,

    // Mutable state.
    state: Mutex<ThreadState>,
    // Mutable state specific to the ABI the thread is running with.
    pub cpu_state: Mutex<CpuState>,
}

pub struct ThreadState {
    virtual_memory: Arc<VirtualMemory>,

    pub signal_handler_table: Arc<SignalHandlerTable>,
    pub sigmask: Sigset,
    /// A signal that should be delivered the next time userspace is entered.
    pub pending_signal_info: Option<SigInfo>,
    /// A list of signals that may or may not be delivered eventually.
    pub pending_signals: PendingSignals,
    pub sigaltstack: Stack,
    pub clear_child_tid: Pointer<u32>,
    pub cwd: DynINode,
    pub vfork_done: Option<oneshot::Sender<()>>,
    // FIXME: Use this field.
    pub umask: FileMode,
    fdtable: Arc<FileDescriptorTable>,
}

impl Thread {
    #[allow(clippy::too_many_arguments)]
    fn new(
        tid: u32,
        process: Arc<Process>,
        signal_handler_table: Arc<SignalHandlerTable>,
        sigmask: Sigset,
        virtual_memory: Arc<VirtualMemory>,
        fdtable: Arc<FileDescriptorTable>,
        cwd: DynINode,
        vfork_done: Option<oneshot::Sender<()>>,
        cpu_state: CpuState,
        umask: FileMode,
    ) -> Self {
        Self {
            tid,
            process,
            signal_notify: Notify::new(),
            running_state: ThreadRunningState::new(),
            state: Mutex::new(ThreadState {
                virtual_memory,
                signal_handler_table,
                sigmask,
                pending_signal_info: None,
                pending_signals: PendingSignals::new(),
                sigaltstack: Stack::default(),
                clear_child_tid: Pointer::NULL,
                cwd,
                vfork_done,
                fdtable,
                umask,
            }),
            cpu_state: Mutex::new(cpu_state),
        }
    }

    pub fn spawn(self: Arc<Self>) {
        spawn(self.run());
    }

    pub fn empty(tid: u32) -> Self {
        Self::new(
            tid,
            Process::new(tid, Weak::new(), None),
            Arc::new(SignalHandlerTable::new()),
            Sigset::empty(),
            Arc::new(VirtualMemory::new()),
            Arc::new(FileDescriptorTable::with_standard_io()),
            ROOT_NODE.clone(),
            None,
            CpuState::new(0, 0, 0),
            FileMode::empty(),
        )
    }

    pub fn lock(&self) -> ThreadGuard {
        ThreadGuard {
            thread: self,
            state: self.state.lock(),
        }
    }

    pub fn tid(&self) -> u32 {
        self.tid
    }

    pub fn process(&self) -> &Arc<Process> {
        &self.process
    }

    pub fn is_thread_group_leader(&self) -> bool {
        self.process.pid == self.tid
    }

    pub async fn run(self: Arc<Self>) {
        self.process.add_thread(Arc::downgrade(&self));

        loop {
            let exit_action = {
                let running_state = self.watch();
                let run_future = async {
                    loop {
                        self.try_deliver_signal().await.unwrap();

                        let clone = self.clone();
                        let exit = clone.run_userspace().unwrap();

                        match exit {
                            Exit::DivideError => {
                                let sig_info = SigInfo {
                                    signal: Signal::FPE,
                                    code: SigInfoCode::FPE_INTDIV,
                                    fields: SigFields::SigFault(SigFault {
                                        addr: self.cpu_state.lock().faulting_instruction(),
                                    }),
                                };
                                assert!(self.queue_signal(sig_info));
                            }
                            Exit::Syscall(args) => self.clone().execute_syscall(args).await,
                            Exit::GeneralProtectionFault => {
                                let sig_info = SigInfo {
                                    signal: Signal::SEGV,
                                    code: SigInfoCode::KERNEL,
                                    fields: SigFields::SigFault(SigFault {
                                        addr: self.cpu_state.lock().faulting_instruction(),
                                    }),
                                };
                                assert!(self.queue_signal(sig_info));
                            }
                            Exit::PageFault(page_fault) => self.handle_page_fault(page_fault),
                        }
                    }
                };

                select_biased! {
                    exit_action = running_state.fuse() => exit_action,
                    _ = run_future.fuse() => unreachable!(),
                }
            };
            match exit_action {
                ExitAction::Terminate => return,
                ExitAction::WaitForExecve(pending) => {
                    let Some(params) = pending.get().await else {
                        return;
                    };
                    let mut guard = self.lock();
                    guard.execve(params.virtual_memory, params.cpu_state, params.fdtable);
                    continue;
                }
            }
        }
    }

    fn run_userspace(&self) -> Result<Exit> {
        let virtual_memory = self.lock().virtual_memory().clone();
        let mut guard = self.cpu_state.lock();
        guard.run_user(&virtual_memory)
    }

    fn handle_page_fault(self: &Arc<Self>, page_fault: PageFaultExit) {
        let virtual_memory = self.lock().virtual_memory().clone();
        let res = virtual_memory.handle_page_fault(page_fault.addr, page_fault.code);
        if let Err(err) = res {
            let code = match err {
                PageFaultError::Unmapped(_) => SigInfoCode::SEGV_MAPERR,
                PageFaultError::MissingPermissions(_) => SigInfoCode::SEGV_ACCERR,
                PageFaultError::Other(_) => SigInfoCode::KERNEL,
            };
            let sig_info = SigInfo {
                signal: Signal::SEGV,
                code,
                fields: SigFields::SigFault(SigFault {
                    addr: page_fault.addr,
                }),
            };
            assert!(self.queue_signal(sig_info));
        }
    }

    /// Returns true if the signal was not already queued.
    pub fn queue_signal(&self, sig_info: SigInfo) -> bool {
        let mut guard = self.lock();
        let res = guard.pending_signals.add(sig_info);
        self.signal_notify.notify();
        res
    }

    async fn try_deliver_signal(self: &Arc<Self>) -> Result<()> {
        let mut state = self.lock();
        while let Some(sig_info) = state.pop_signal() {
            let virtual_memory = state.virtual_memory.clone();
            let sigaction = state.signal_handler_table.get(sig_info.signal);

            match sigaction.sa_handler_or_sigaction {
                Sigaction::SIG_DFL => match sig_info.signal {
                    Signal::CHLD => {
                        // Ignore
                        continue;
                    }
                    signal => {
                        todo!("unimplemented default for signal {signal:?}")
                    }
                },
                Sigaction::SIG_IGN => continue,
                _ => {}
            }

            let thread_sigmask = state.sigmask;
            state.sigmask |= sigaction.sa_mask;
            if !sigaction.sa_flags.contains(SigactionFlags::NODEFER) {
                state.sigmask.add(sig_info.signal);
            }
            let sigaltstack = state.sigaltstack;
            if sigaltstack.flags.contains(StackFlags::AUTODISARM)
                && sigaction.sa_flags.contains(SigactionFlags::ONSTACK)
            {
                state.sigaltstack.flags |= StackFlags::DISABLE;
            }
            drop(state);

            let mut cpu_state = self.cpu_state.lock();
            return cpu_state.start_signal_handler(
                sig_info,
                sigaction,
                sigaltstack,
                thread_sigmask,
                &virtual_memory,
            );
        }

        Ok(())
    }

    /// Returns a future that resolves when the process has a pending signal
    /// and returns whether the running syscall should be restarted.
    async fn wait_for_signal(&self) -> bool {
        loop {
            let thread_notify_wait = self.signal_notify.wait();
            let process_notify_wait = self.process.signals_notify.wait();

            let mut guard = self.lock();
            if let Some(restartable) = guard.get_pending_signal() {
                return restartable;
            }
            drop(guard);

            select_biased! {
                () = thread_notify_wait.fuse() => {},
                () = process_notify_wait.fuse() => {}
            }
        }
    }

    pub async fn interruptable<R>(
        &self,
        f: impl Future<Output = Result<R>>,
        restartable: bool,
    ) -> Result<R> {
        select_biased! {
            should_restart = self.wait_for_signal().fuse() => {
                if should_restart && restartable {
                    bail!(RestartNoIntr)
                }
                bail!(Intr)
            },
            res = f.fuse() => res,
        }
    }
}

pub struct ThreadGuard<'a> {
    pub thread: &'a Thread,
    state: MutexGuard<'a, ThreadState>,
}

impl ThreadGuard<'_> {
    #[allow(clippy::too_many_arguments)]
    pub fn clone(
        &self,
        new_tid: u32,
        new_process: Option<Arc<Process>>,
        new_virtual_memory: Option<Arc<VirtualMemory>>,
        new_signal_handler_table: Option<Arc<SignalHandlerTable>>,
        fdtable: Arc<FileDescriptorTable>,
        stack: VirtAddr,
        new_clear_child_tid: Option<Pointer<u32>>,
        new_tls: Option<NewTls>,
        vfork_done: Option<oneshot::Sender<()>>,
    ) -> Thread {
        let process = new_process.unwrap_or_else(|| self.process().clone());
        let virtual_memory = new_virtual_memory.unwrap_or_else(|| self.virtual_memory().clone());
        let signal_handler_table =
            new_signal_handler_table.unwrap_or_else(|| self.signal_handler_table.clone());
        let cpu_state = self.thread.cpu_state.lock().clone();

        let thread = Thread::new(
            new_tid,
            process,
            signal_handler_table,
            self.sigmask,
            virtual_memory,
            fdtable,
            self.cwd.clone(),
            vfork_done,
            cpu_state,
            self.umask,
        );

        let mut guard = thread.lock();
        if let Some(clear_child_tid) = new_clear_child_tid {
            guard.clear_child_tid = clear_child_tid;
        }
        drop(guard);

        let mut guard = thread.cpu_state.lock();

        // Set the return value to 0 for the new thread.
        guard.set_syscall_result(Ok(0)).unwrap();

        // Switch to a new stack if one is provided.
        if !stack.is_null() {
            guard.set_stack_pointer(stack.as_u64());
        }

        if let Some(tls) = new_tls {
            match tls {
                NewTls::Fs(tls) => guard.set_fs_base(tls),
                NewTls::UserDesc(u_info) => {
                    guard.add_user_desc(u_info).unwrap();
                }
            }
        }

        drop(guard);

        thread
    }

    pub fn tid(&self) -> u32 {
        self.thread.tid
    }

    pub fn process(&self) -> &Arc<Process> {
        &self.thread.process
    }

    pub fn virtual_memory(&self) -> &Arc<VirtualMemory> {
        &self.virtual_memory
    }

    pub fn fdtable(&self) -> &Arc<FileDescriptorTable> {
        &self.fdtable
    }

    /// Replaces the file descriptor table with an emtpy one.
    pub fn close_all_fds(&mut self) {
        self.fdtable = Arc::new(FileDescriptorTable::empty());
    }

    pub fn execve(
        &mut self,
        virtual_memory: VirtualMemory,
        cpu_state: CpuState,
        fdtable: FileDescriptorTable,
    ) {
        self.virtual_memory = Arc::new(virtual_memory);
        *self.thread.cpu_state.lock() = cpu_state;
        self.fdtable = Arc::new(fdtable);

        self.clear_child_tid = Pointer::NULL;
        self.signal_handler_table = Arc::new(SignalHandlerTable::new());
        self.sigaltstack = Stack::default();
    }

    pub fn start_executable(
        &mut self,
        path: &Path,
        file: &FileDescriptor,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        ctx: &mut FileAccessContext,
    ) -> Result<()> {
        let virtual_memory = VirtualMemory::new();

        // Load the elf.
        let cpu_state =
            virtual_memory.start_executable(path, file, argv, envp, ctx, self.cwd.clone())?;

        // Success! Commit the new state to the thread.

        self.virtual_memory = Arc::new(virtual_memory);
        *self.thread.cpu_state.lock() = cpu_state;
        self.clear_child_tid = Pointer::NULL;

        Ok(())
    }

    pub fn getrlimit(&self, resource: Resource) -> RLimit {
        match resource {
            Resource::NoFile => {
                let limit = u32::try_from(FileDescriptorTable::MAX_FD).unwrap();
                RLimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                }
            }
        }
    }

    /// Determines whether a signal is pending and whether the currently
    /// running syscall should be restarted (if it's capable of being
    /// restarted).
    fn get_pending_signal(&mut self) -> Option<bool> {
        loop {
            // Determine the signal that should be handled next.
            let mask = self.sigmask;
            if self.pending_signal_info.is_none() {
                self.pending_signal_info = self.pending_signals.pop(mask);
            }
            if self.pending_signal_info.is_none() {
                self.pending_signal_info = self.process().pop_signal(mask);
            }
            let pending_signal_info = self.pending_signal_info?;

            // Check if the signal needs to be handled. If the signal handler
            // wants to ignore the signal we just skip it.
            let handler = self.signal_handler_table.get(pending_signal_info.signal);
            let ignored = match handler.sa_handler_or_sigaction {
                Sigaction::SIG_DFL => match pending_signal_info.signal {
                    Signal::CHLD => true,
                    signal => {
                        todo!("unimplemented default for signal {}", signal.get())
                    }
                },
                Sigaction::SIG_IGN => true,
                _ => false,
            };
            if ignored {
                // Try again.
                self.pending_signal_info = None;
                continue;
            }

            // Otherwise we found our signal.
            let restartable = handler.sa_flags.contains(SigactionFlags::RESTART);
            return Some(restartable);
        }
    }

    fn pop_signal(&mut self) -> Option<SigInfo> {
        self.get_pending_signal()?;
        self.pending_signal_info.take()
    }
}

impl Deref for ThreadGuard<'_> {
    type Target = ThreadState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl DerefMut for ThreadGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Sigaction {
    pub sa_handler_or_sigaction: u64,
    pub sa_flags: SigactionFlags,
    pub sa_restorer: u64,
    pub sa_mask: Sigset,
}

impl Sigaction {
    const DEFAULT: Self = Self {
        sa_handler_or_sigaction: Self::SIG_DFL,
        sa_flags: SigactionFlags::empty(),
        sa_restorer: 0,
        sa_mask: Sigset::empty(),
    };

    const SIG_DFL: u64 = 0;
    const SIG_IGN: u64 = 1;
}

#[derive(Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct Sigset(u64);

impl Sigset {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn add(&mut self, signal: Signal) {
        self.0 |= 1 << (signal.get() - 1);
    }

    pub fn contains(&self, signal: Signal) -> bool {
        self.0 & (1 << (signal.get() - 1)) != 0
    }

    pub fn to_bits(self) -> u64 {
        self.0
    }

    pub fn from_bits(bits: u64) -> Self {
        Self(bits)
    }
}

impl BitOrAssign for Sigset {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for Sigset {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for Sigset {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl Not for Sigset {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

impl Debug for Sigset {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_set = f.debug_set();
        for i in 0..64 {
            if self.0.get_bit(i) {
                let signal = Signal::new(i as u8 + 1).unwrap();
                debug_set.entry(&signal);
            }
        }
        debug_set.finish()
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct SigactionFlags: u32 {
        const SIGINFO = 0x00000004;
        const RESTORER = 0x04000000;
        const ONSTACK = 0x08000000;
        const RESTART = 0x10000000;
        const NODEFER = 0x40000000;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Stack {
    pub sp: u64,
    pub flags: StackFlags,
    pub size: u64,
}

impl Default for Stack {
    fn default() -> Self {
        Self {
            sp: Default::default(),
            flags: StackFlags::DISABLE,
            size: Default::default(),
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    #[repr(transparent)]
    pub struct StackFlags: i32 {
        const ONSTACK = 1 << 0;
        const DISABLE = 1 << 1;
        const AUTODISARM = 1 << 31;
    }
}

pub enum NewTls {
    Fs(u64),
    UserDesc(UserDesc),
}

pub struct PendingSignals {
    pending_signals: VecDeque<SigInfo>,
}

impl PendingSignals {
    pub const fn new() -> Self {
        Self {
            pending_signals: VecDeque::new(),
        }
    }

    /// Add the signal to the set of pending signals.
    ///
    /// Returns true if the signal was added.
    pub fn add(&mut self, sig_info: SigInfo) -> bool {
        let is_pending = self
            .pending_signals
            .iter()
            .any(|s| s.signal == sig_info.signal);
        // Only queue the signal if it's not already pending.
        if !is_pending {
            self.pending_signals.push_back(sig_info);
            true
        } else {
            false
        }
    }

    pub fn pop(&mut self, mask: Sigset) -> Option<SigInfo> {
        let idx = self
            .pending_signals
            .iter()
            .position(|s| !mask.contains(s.signal))?;
        let sig_info = self.pending_signals.remove(idx).unwrap();
        Some(sig_info)
    }
}

impl Default for PendingSignals {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SigInfo {
    pub signal: Signal,
    pub code: SigInfoCode,
    pub fields: SigFields,
}

#[derive(Debug, Clone, Copy)]
pub struct SigInfoCode(i32);

impl SigInfoCode {
    pub fn get(self) -> i32 {
        self.0
    }

    pub const CLD_EXITED: Self = Self(1);
    pub const FPE_INTDIV: Self = Self(1);
    pub const SEGV_MAPERR: Self = Self(1);
    pub const SEGV_ACCERR: Self = Self(2);
    pub const KERNEL: Self = Self(0x80);
}

#[derive(Debug, Clone, Copy)]
pub enum SigFields {
    None,
    SigChld(SigChld),
    SigFault(SigFault),
}

#[derive(Debug, Clone, Copy)]
pub struct SigChld {
    pub pid: i32,
    pub uid: u32,
    pub status: i32,
    pub utime: i64,
    pub stime: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct SigFault {
    pub addr: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct UContext {
    pub stack: Stack,
    pub mcontext: SigContext,
    pub sigmask: Sigset,
    // implementation specific
    pub syscall_restart_args: Option<SyscallArgs>,
}

#[derive(Debug, Clone, Copy)]
pub struct SigContext {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub gs: u16,
    pub fs: u16,
    pub ss: u16,
    pub err: u64,
    pub trapno: u64,
    pub oldmask: u64,
    pub cr2: u64,
    pub fpstate: Pointer<c_void>,
}

#[derive(Clone)]
pub struct SignalHandlerTable {
    sigactions: Mutex<[Sigaction; 64]>,
}

impl SignalHandlerTable {
    pub fn new() -> Self {
        Self {
            sigactions: Mutex::new([Sigaction::DEFAULT; 64]),
        }
    }

    pub fn get(&self, signal: Signal) -> Sigaction {
        self.sigactions.lock()[signal.get() - 1]
    }

    pub fn set(&self, signal: Signal, sigaction: Sigaction) -> Sigaction {
        core::mem::replace(&mut self.sigactions.lock()[signal.get() - 1], sigaction)
    }
}

impl Default for SignalHandlerTable {
    fn default() -> Self {
        Self::new()
    }
}
