use core::{
    ffi::{c_void, CStr},
    ops::{BitAnd, BitAndAssign, BitOrAssign, Deref, DerefMut, Not},
    sync::atomic::{AtomicU32, Ordering},
};

use crate::{
    fs::{
        fd::{FileDescriptorTable, OpenFileDescription},
        node::{DynINode, FileAccessContext},
    },
    rt::once::OnceCell,
    spin::mutex::{Mutex, MutexGuard},
};
use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
use futures::{select_biased, FutureExt};
use usize_conversions::FromUsize;
use x86_64::VirtAddr;

use crate::{
    error::{Error, Result},
    fs::{
        node::{lookup_and_resolve_node, ROOT_NODE},
        path::Path,
    },
    rt::{oneshot, spawn},
};

use super::{
    memory::VirtualMemory,
    syscall::{
        args::{FileMode, OpenFlags, Pointer, RLimit, Resource, Signal, UserDesc},
        cpu_state::{CpuState, Exit, PageFaultExit},
    },
    Process,
};

pub static THREADS: Threads = Threads::new();

pub fn new_tid() -> u32 {
    static PID_COUNTER: AtomicU32 = AtomicU32::new(1);
    PID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

pub struct Threads {
    map: Mutex<BTreeMap<u32, Arc<Thread>>>,
}

impl Threads {
    const fn new() -> Self {
        Self {
            map: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn add(&self, thread: Arc<Thread>) -> u32 {
        let tid = thread.tid;
        self.map.lock().insert(tid, thread);
        tid
    }

    pub fn by_id(&self, tid: u32) -> Option<Arc<Thread>> {
        self.map.lock().get(&tid).cloned()
    }

    pub fn remove(&self, tid: u32) {
        self.map.lock().remove(&tid);
    }
}

pub type WeakThread = Weak<Thread>;

pub struct Thread {
    // Immutable state.
    tid: u32,
    process: Arc<Process>,
    pub exited: OnceCell<()>,

    // Mutable state.
    state: Mutex<ThreadState>,
    // Mutable state specific to the ABI the thread is running with.
    pub cpu_state: Mutex<CpuState>,
}

pub struct ThreadState {
    virtual_memory: Arc<VirtualMemory>,

    pub signal_handler_table: Arc<SignalHandlerTable>,
    pub sigmask: Sigset,
    pub pending_signals: Sigset,
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
            exited: OnceCell::new(),
            state: Mutex::new(ThreadState {
                virtual_memory,
                signal_handler_table,
                sigmask: Sigset(0),
                pending_signals: Sigset(0),
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

    pub fn spawn(self) {
        let arc = Arc::new(self);

        // Register the thread.
        THREADS.add(arc.clone());

        spawn(arc.run());
    }

    pub fn empty(tid: u32) -> Self {
        Self::new(
            tid,
            Process::new(tid, Weak::new()),
            Arc::new(SignalHandlerTable::new()),
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

    pub async fn run(self: Arc<Self>) {
        let thread_exit_future = self.exited.get();
        let process_exit_future = self.process.exit_status();
        let run_future = async {
            loop {
                self.try_deliver_signal().await.unwrap();

                let clone = self.clone();
                let exit = clone.run_userspace().unwrap();

                match exit {
                    Exit::DivideError => {
                        assert!(self.queue_signal(Signal::FPE));
                    }
                    Exit::Syscall(args) => self.clone().execute_syscall(args).await,
                    Exit::GeneralProtectionFault => {
                        assert!(self.queue_signal(Signal::SEGV));
                    }
                    Exit::PageFault(page_fault) => self.handle_page_fault(page_fault),
                }
            }
        };

        select_biased! {
            _ = thread_exit_future.fuse() => {}
            status = process_exit_future.fuse() => self.clone().exit(status),
            _ = run_future.fuse() => unreachable!(),
        }
    }

    fn exit(self: Arc<Self>, status: u8) {
        let mut guard = self.lock();
        guard.exit()
    }

    fn run_userspace(&self) -> Result<Exit> {
        let virtual_memory = self.lock().virtual_memory().clone();
        let mut guard = self.cpu_state.lock();
        guard.run_user(&virtual_memory)
    }

    fn handle_page_fault(self: &Arc<Self>, page_fault: PageFaultExit) {
        let virtual_memory = self.lock().virtual_memory().clone();
        let handled = virtual_memory.handle_page_fault(page_fault.addr, page_fault.code);
        if !handled {
            assert!(self.queue_signal(Signal::SEGV));
        }
    }

    /// Returns true if the signal was not already queued.
    pub fn queue_signal(&self, signum: Signal) -> bool {
        let mut guard = self.lock();
        let new_sigset = Sigset(1 << signum.get());
        if guard.pending_signals & new_sigset != Sigset(0) {
            return false;
        }
        guard.pending_signals |= new_sigset;
        true
    }

    async fn try_deliver_signal(self: &Arc<Self>) -> Result<()> {
        let mut state = self.lock();
        let Some(signal) = state.pop_signal() else {
            return Ok(());
        };

        let virtual_memory = state.virtual_memory.clone();
        let sigaction = state.signal_handler_table.get(signal);
        let thread_sigmask = state.sigmask;
        state.sigmask |= sigaction.sa_mask;
        if !sigaction.sa_flags.contains(SigactionFlags::NODEFER) {
            state.sigmask |= Sigset(1 << signal.get());
        }
        let sigaltstack = state.sigaltstack;
        if sigaltstack.flags.contains(StackFlags::AUTODISARM)
            && sigaction.sa_flags.contains(SigactionFlags::ONSTACK)
        {
            state.sigaltstack.flags |= StackFlags::DISABLE;
        }
        drop(state);

        let sig_info = SigInfo {
            si_signo: signal.get() as i32,
            si_errno: 0,
            si_code: 0,
            __pad: [0; 29],
        };

        let this = self.clone();
        let mut cpu_state = this.cpu_state.lock();
        cpu_state.start_signal_handler(
            u64::from_usize(signal.get()),
            sig_info,
            sigaction,
            sigaltstack,
            thread_sigmask,
            &virtual_memory,
        )
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
        path: &Path,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        ctx: &mut FileAccessContext,
    ) -> Result<()> {
        let node = lookup_and_resolve_node(self.cwd.clone(), path, ctx)?;
        if !node.mode().contains(FileMode::EXECUTE) {
            return Err(Error::acces(()));
        }

        let file = node.open(OpenFlags::empty())?;
        self.start_executable(path, &*file, argv, envp, ctx)
    }

    pub fn start_executable(
        &mut self,
        path: &Path,
        file: &dyn OpenFileDescription,
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

    fn pop_signal(&mut self) -> Option<Signal> {
        let signals = !self.sigmask & self.pending_signals;
        if signals.0 == 0 {
            return None;
        }

        let signal = signals.0.trailing_zeros() as u8;
        self.pending_signals &= Sigset(!(1 << signal));
        Some(Signal::new(signal).unwrap())
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
        sa_handler_or_sigaction: 0,
        sa_flags: SigactionFlags::empty(),
        sa_restorer: 0,
        sa_mask: Sigset(0),
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct Sigset(pub u64);

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

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct SigactionFlags: u32 {
        const ONSTACK = 0x08000000;
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

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct SigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub __pad: [i32; 29],
}

#[derive(Debug, Clone, Copy)]
pub struct UContext {
    pub stack: Stack,
    pub mcontext: SigContext,
    pub sigmask: Sigset,
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
        self.sigactions.lock()[signal.get()]
    }

    pub fn set(&self, signal: Signal, sigaction: Sigaction) -> Sigaction {
        core::mem::replace(&mut self.sigactions.lock()[signal.get()], sigaction)
    }
}
