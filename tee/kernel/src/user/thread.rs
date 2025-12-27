use alloc::{
    collections::VecDeque,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    ffi::{CStr, c_void},
    fmt::{self, Debug},
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Deref, DerefMut, Not},
    pin::{Pin, pin},
    sync::atomic::{AtomicU32, Ordering},
    task::{Context, Poll, Waker},
};

use arrayvec::ArrayVec;
use bit_field::BitField;
use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
use constants::{ApBitmap, AtomicApBitmap};
use crossbeam_utils::atomic::AtomicCell;
use futures::{FutureExt, select_biased};
use pin_project::pin_project;
use x86_64::{
    VirtAddr,
    structures::paging::{PageSize, Size4KiB},
};

use self::running_state::{ExitAction, ThreadRunningState};
use crate::{
    error::{Result, bail, ensure},
    exception::eoi,
    fs::{
        fd::{FileDescriptor, FileDescriptorTable, epoll::EventCounter},
        node::{FileAccessContext, Link, LinkLocation, ROOT_NODE, procfs::ThreadInos},
        path::{FileName, Path},
    },
    rt::{PreemptionState, notify::Notify, oneshot, spawn},
    spin::mutex::{Mutex, MutexGuard},
    time,
    user::{
        memory::{PageFaultError, VirtualMemory, WriteToVec},
        process::{
            Process, ProcessGroup, Session, TASK_COMM_CAPACITY, WaitFilter, WaitResult,
            limits::{CurrentStackLimit, Limits},
            usage::{self, ThreadUsage},
        },
        syscall::{
            args::{
                FileMode, Nice, Pointer, PtraceEvent, PtraceOptions, Rusage, SchedParam,
                SchedulingPolicy, Signal, TimerId, Timespec, UserDesc, WStatus,
            },
            cpu_state::{CpuState, Exit, PageFaultExit, SimdFloatingPointError},
        },
    },
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
    pub signal_notify: Notify,
    running_state: ThreadRunningState,
    usage: ThreadUsage,

    // Mutable state.
    state: Mutex<ThreadState>,
    // Mutable state specific to the ABI the thread is running with.
    pub cpu_state: Mutex<CpuState>,
    // Rarely mutable state.
    pub fdtable: Mutex<Arc<FileDescriptorTable>>,
    pub affinity: AtomicApBitmap, // TODO: Use this
    pub nice: AtomicCell<Nice>,
    pub inos: ThreadInos,
    /// Notifications sent from the tracer to the tracee.
    pub ptrace_tracer_notify: Notify,
    /// Notifications sent from the tracee to the tracer.
    pub ptrace_tracee_notify: Notify,
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
    pub vfork_done: Option<oneshot::Sender<()>>,
    task_comm: Option<ArrayVec<u8, TASK_COMM_CAPACITY>>,
    no_new_privs: bool,

    /// The thread that traces this thread.
    pub tracer: Weak<Thread>,
    pub ptrace_state: PtraceState,
    pub ptrace_options: PtraceOptions,
    /// Threads that are traced by this thread.
    pub tracees: Vec<Weak<Thread>>,

    pub capabilities: Capabilities,
    pub scheduling_settings: SchedulingSettings,
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
        vfork_done: Option<oneshot::Sender<()>>,
        cpu_state: CpuState,
        affinity: ApBitmap,
        nice: Nice,
        capabilities: Capabilities,
        scheduling_settings: SchedulingSettings,
    ) -> Arc<Self> {
        let thread = Self {
            tid,
            process: process.clone(),
            signal_notify: Notify::new(),
            running_state: ThreadRunningState::new(),
            usage: ThreadUsage::default(),
            state: Mutex::new(ThreadState {
                virtual_memory,
                signal_handler_table,
                sigmask,
                pending_signal_info: None,
                pending_signals: PendingSignals::new(),
                sigaltstack: Stack::default(),
                clear_child_tid: Pointer::NULL,
                vfork_done,
                task_comm: None,
                no_new_privs: false,
                tracer: Weak::new(),
                ptrace_state: PtraceState::default(),
                ptrace_options: PtraceOptions::empty(),
                tracees: Vec::new(),
                capabilities,
                scheduling_settings,
            }),
            cpu_state: Mutex::new(cpu_state),
            fdtable: Mutex::new(fdtable),
            affinity: AtomicApBitmap::new(affinity),
            nice: AtomicCell::new(nice),
            inos: ThreadInos::new(),
            ptrace_tracer_notify: Notify::new(),
            ptrace_tracee_notify: Notify::new(),
        };
        let thread = Arc::new(thread);
        process.add_thread(Arc::downgrade(&thread));
        thread
    }

    pub fn spawn(self: Arc<Self>) {
        #[pin_project]
        struct RecordingFuture<F> {
            thread: Arc<Thread>,
            #[pin]
            future: F,
        }

        impl<F> Future for RecordingFuture<F>
        where
            F: Future<Output = ()>,
        {
            type Output = ();

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let this = self.project();

                let start = time::default_backend_offset();
                this.thread.usage.start(start);

                let res = this.future.poll(cx);

                let end = time::default_backend_offset();
                this.thread.usage.stop(end);
                this.thread
                    .process
                    .cpu_time
                    .backend()
                    .add(end.saturating_sub(start));

                res
            }
        }

        spawn(RecordingFuture {
            thread: self.clone(),
            future: self.run(),
        });
    }

    pub fn empty(tid: u32) -> Arc<Self> {
        Self::new(
            tid,
            Process::new(
                tid,
                Weak::new(),
                None,
                Link {
                    location: LinkLocation::new(ROOT_NODE.clone(), FileName::new(b"init").unwrap()),
                    node: ROOT_NODE.clone(), // This is nonsense.
                },
                Credentials::super_user(),
                Link::root(),
                ProcessGroup::new(tid, Arc::new(Session::new(tid))),
                Limits::default(),
                FileMode::GROUP_WRITE | FileMode::OTHER_WRITE,
                VirtAddr::zero(),
                VirtAddr::zero(),
            ),
            Arc::new(SignalHandlerTable::new()),
            Sigset::empty(),
            Arc::new(VirtualMemory::new()),
            Arc::new(FileDescriptorTable::with_standard_io()),
            None,
            CpuState::new(0, 0, 0),
            ApBitmap::all(),
            Nice::DEFAULT,
            Capabilities::new(),
            SchedulingSettings::default(),
        )
    }

    pub fn try_lock(&self) -> Option<ThreadGuard<'_>> {
        let state = self.state.try_lock()?;
        Some(ThreadGuard {
            thread: self,
            state,
        })
    }

    pub fn lock(&self) -> ThreadGuard<'_> {
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
        self.process.pid() == self.tid
    }

    pub async fn run(self: Arc<Self>) {
        let mut preemption_state = PreemptionState::new();
        loop {
            let exit_action = {
                let running_state = self.watch();
                let run_future = async {
                    loop {
                        self.deliver_signals().await.unwrap();

                        let exit = self.run_userspace().unwrap();

                        match exit {
                            Exit::Syscall(args) => self.execute_syscall(args).await,
                            Exit::DivideError => {
                                let sig_info = SigInfo {
                                    signal: Signal::FPE,
                                    code: SigInfoCode::FPE_INTDIV,
                                    fields: SigFields::SigFault(SigFault {
                                        addr: self.cpu_state.lock().faulting_instruction(),
                                    }),
                                };
                                self.queue_signal_or_die(sig_info).await;
                            }
                            Exit::Breakpoint => {
                                let sig_info = SigInfo {
                                    signal: Signal::TRAP,
                                    code: SigInfoCode::KERNEL,
                                    fields: SigFields::SigFault(SigFault { addr: 0 }),
                                };
                                self.queue_signal_or_die(sig_info).await;
                            }
                            Exit::InvalidOpcode => {
                                let sig_info = SigInfo {
                                    signal: Signal::ILL,
                                    code: SigInfoCode::ILL_ILLOPN,
                                    fields: SigFields::SigFault(SigFault {
                                        addr: self.cpu_state.lock().faulting_instruction(),
                                    }),
                                };
                                self.queue_signal_or_die(sig_info).await;
                            }
                            Exit::GeneralProtectionFault => {
                                let sig_info = SigInfo {
                                    signal: Signal::SEGV,
                                    code: SigInfoCode::KERNEL,
                                    fields: SigFields::SigFault(SigFault {
                                        addr: self.cpu_state.lock().faulting_instruction(),
                                    }),
                                };
                                self.queue_signal_or_die(sig_info).await;
                            }
                            Exit::PageFault(page_fault) => self.handle_page_fault(page_fault).await,
                            Exit::SimdFloatingPoint(error) => {
                                let code = match error {
                                    SimdFloatingPointError::InvalidOperation => {
                                        SigInfoCode::FPE_FLTINV
                                    }
                                    SimdFloatingPointError::Denormal => SigInfoCode::FPE_FLTUND,
                                    SimdFloatingPointError::DivideByZero => SigInfoCode::FPE_FLTDIV,
                                    SimdFloatingPointError::Overflow => SigInfoCode::FPE_FLTOVF,
                                    SimdFloatingPointError::Underflow => SigInfoCode::FPE_FLTUND,
                                    SimdFloatingPointError::Precision => SigInfoCode::FPE_FLTRES,
                                };
                                let sig_info = SigInfo {
                                    signal: Signal::FPE,
                                    code,
                                    fields: SigFields::SigFault(SigFault {
                                        addr: self.cpu_state.lock().faulting_instruction(),
                                    }),
                                };
                                self.queue_signal_or_die(sig_info).await;
                            }
                            Exit::Timer => {
                                // Handle the timer interrupt.
                                time::expire_timers();

                                // Signal that we're done handling the interrupt.
                                eoi();
                            }
                        }

                        preemption_state.check().await;
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
        virtual_memory.modify().handle_async_unmap();
        let mut guard = self.cpu_state.lock();
        let start = time::default_backend_offset();
        let exit = guard.run_user(&virtual_memory)?;
        let end = time::default_backend_offset();
        drop(guard);

        self.usage.record_user_execution_time(end - start);
        if matches!(exit, Exit::Syscall(_)) {
            self.usage.record_voluntary_context_switch();
        }

        Ok(exit)
    }

    async fn handle_page_fault(self: &Arc<Self>, page_fault: PageFaultExit) {
        let virtual_memory = self.lock().virtual_memory().clone();
        let res = virtual_memory.handle_page_fault(page_fault.addr, page_fault.code);
        if let Err(err) = res {
            let (signal, code) = match err {
                PageFaultError::Unmapped(_) => (Signal::SEGV, SigInfoCode::SEGV_MAPERR),
                PageFaultError::MissingPermissions(_) => (Signal::SEGV, SigInfoCode::SEGV_ACCERR),
                PageFaultError::Other(_) => (Signal::BUS, SigInfoCode::BUS_ADRERR),
            };
            let sig_info = SigInfo {
                signal,
                code,
                fields: SigFields::SigFault(SigFault {
                    addr: page_fault.addr,
                }),
            };
            self.queue_signal_or_die(sig_info).await;
        }
    }

    pub fn pending_signals(&self) -> Sigset {
        self.lock().pending_signals.pending_signals()
    }

    pub fn pending_signals_with_counter(&self) -> (Sigset, EventCounter) {
        let guard = self.lock();
        (
            guard.pending_signals.pending_signals(),
            guard.pending_signals.queue_counter(),
        )
    }

    /// Returns true if the signal was not already queued.
    pub fn queue_signal(&self, sig_info: SigInfo) -> bool {
        self.lock().queue_signal(sig_info)
    }

    /// Try to queue a signal and kill the process if the signal is already pending.
    pub async fn queue_signal_or_die(&self, sig_info: SigInfo) {
        if !self.queue_signal(sig_info) {
            self.process()
                .exit_group(WStatus::signaled(sig_info.signal))
                .await;
        }
    }

    async fn deliver_signals(self: &Arc<Self>) -> Result<()> {
        let mut wait_thread = self.signal_notify.wait();
        let mut ptrace_wait = self.ptrace_tracee_notify.wait();
        let mut wait_process = self.process.signals_notify.wait();
        loop {
            let process_not_stopped_fut = self.process.wait_until_not_stopped().fuse();
            let mut process_not_stopped_fut = pin!(process_not_stopped_fut);

            let mut state = self.lock();
            loop {
                let (sig_info, bypass_ptrace) = if let Some(sig_info) = state.pop_signal() {
                    (sig_info, false)
                } else if let PtraceState::SignalRestart(sig_info) = state.ptrace_state {
                    state.ptrace_state = PtraceState::Running;
                    (sig_info, true)
                } else {
                    break;
                };

                if !bypass_ptrace
                    && sig_info.signal != Signal::KILL
                    && let Some(tracer) = state.tracer.upgrade()
                {
                    state.ptrace_state = PtraceState::Signal {
                        sig_info,
                        reported: false,
                    };
                    drop(state);

                    tracer.ptrace_tracer_notify.notify();
                    drop(tracer);

                    state = self.lock();
                    continue;
                }

                let virtual_memory = state.virtual_memory.clone();

                let mut guard = state.signal_handler_table.sigactions.lock();
                let entry = &mut guard[sig_info.signal.get() - 1];
                let sigaction = *entry;
                if entry.sa_flags.contains(SigactionFlags::RESETHAND) {
                    entry.sa_handler_or_sigaction = Sigaction::SIG_DFL;
                }
                drop(guard);

                match (sigaction.sa_handler_or_sigaction, sig_info.signal) {
                    (Sigaction::SIG_DFL, Signal::CHLD | Signal::CONT) => {
                        // Ignore
                        continue;
                    }
                    (
                        Sigaction::SIG_DFL,
                        signal @ (Signal::HUP
                        | Signal::INT
                        | Signal::ILL
                        | Signal::TRAP
                        | Signal::ABRT
                        | Signal::USR1
                        | Signal::SEGV
                        | Signal::USR2
                        | Signal::PIPE
                        | Signal::ALRM
                        | Signal::TERM),
                    )
                    | (_, signal @ Signal::KILL) => {
                        // Terminate.
                        drop(state);
                        self.process.exit_group(WStatus::signaled(signal)).await;
                        return core::future::pending().await;
                    }
                    (_, Signal::STOP) => continue,
                    (Sigaction::SIG_DFL, signal) => {
                        todo!("unimplemented default for signal {signal:?}")
                    }
                    (Sigaction::SIG_IGN, _) => continue,
                    _ => {}
                }

                let thread_sigmask = state.sigmask;
                state.sigmask |= sigaction.sa_mask;
                if !sigaction.sa_flags.contains(SigactionFlags::NODEFER) {
                    state.sigmask.add(sig_info.signal);
                }
                let sigaltstack = state.sigaltstack;
                state.sigaltstack.flags |= StackFlags::ONSTACK;
                if sigaltstack.flags.contains(StackFlags::AUTODISARM)
                    && sigaction.sa_flags.contains(SigactionFlags::ONSTACK)
                {
                    state.sigaltstack.flags |= StackFlags::DISABLE;
                }
                drop(state);

                let mut cpu_state = self.cpu_state.lock();
                cpu_state.start_signal_handler(
                    sig_info,
                    sigaction,
                    sigaltstack,
                    thread_sigmask,
                    &virtual_memory,
                )?;

                state = self.lock();
            }

            // If the process is not stopped and the thread is not in a ptrace
            // stop, return. Following this, the event loop will enter
            // userspace. If that's not the case, we want and potentially
            // deliver more signals.
            let is_process_not_stopped = process_not_stopped_fut
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready();
            let is_in_ptrace_stop = state.ptrace_state.is_stopped();
            if !is_in_ptrace_stop && is_process_not_stopped {
                return Ok(());
            }
            drop(state);

            select_biased! {
                _ = wait_thread.next().fuse() => {}
                _ = wait_process.next().fuse() => {}
                _ = process_not_stopped_fut => {}
                _ = ptrace_wait.next().fuse() => {}
            }
        }
    }

    /// Returns a future that resolves when the process has a pending signal
    /// and returns whether the running syscall should be restarted.
    pub async fn wait_for_signal(&self) -> bool {
        let mut thread_notify_wait = self.signal_notify.wait();
        let mut ptrace_tracee_wait = self.ptrace_tracee_notify.wait();
        let mut process_notify_wait = self.process.signals_notify.wait();
        loop {
            let mut guard = self.lock();
            if let Some(restartable) = guard.get_pending_signal() {
                return restartable;
            }
            drop(guard);
            select_biased! {
                () = thread_notify_wait.next().fuse() => {}
                () = ptrace_tracee_wait.next().fuse() => {}
                () = process_notify_wait.next().fuse() => {}
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

    pub fn cpu_time(&self) -> Timespec {
        Timespec::from_ns(self.usage.cpu_time() as i64)
    }

    #[cfg(not(feature = "harden"))]
    pub fn dump(&self, indent: usize, mut write: impl fmt::Write) -> fmt::Result {
        use crate::user::syscall::traits::dump_syscall_exit;

        writeln!(write, "{:indent$}thread tid={}", "", self.tid)?;
        let indent = indent + 2;
        if let Some(exit) = self.cpu_state.try_lock().map(|guard| guard.last_exit()) {
            if let Some(exit) = exit {
                match exit {
                    Exit::Syscall(args) => {
                        if let Some(thread) = self.try_lock() {
                            dump_syscall_exit(&thread, args, indent, &mut write)?;
                        } else {
                            writeln!(
                                write,
                                "{:indent$}thread is locked. raw syscall args: {args:?}",
                                ""
                            )?;
                        }
                    }
                    Exit::DivideError
                    | Exit::Breakpoint
                    | Exit::InvalidOpcode
                    | Exit::GeneralProtectionFault
                    | Exit::PageFault(_)
                    | Exit::SimdFloatingPoint(_)
                    | Exit::Timer => writeln!(write, "{:indent$}{exit:?}", "")?,
                }
            } else {
                writeln!(write, "{:indent$}thread has never exited", "")?;
            }
        } else {
            writeln!(write, "{:indent$}cpu state is locked", "")?;
        }
        self.fdtable.lock().dump(indent, write)?;
        Ok(())
    }

    pub fn find_by_tid(tid: u32) -> Option<Arc<Self>> {
        Process::all().find_map(|p| {
            p.threads
                .lock()
                .iter()
                .filter_map(Weak::upgrade)
                .find(|t| t.tid() == tid)
        })
    }

    pub fn poll_wait_for_tracee(&self, filter: WaitFilter) -> WaitResult {
        let children = self
            .lock()
            .tracees
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|tracee| match filter {
                WaitFilter::Any => true,
                WaitFilter::ExactPid(pid) => tracee.tid() == pid,
                WaitFilter::ExactPgid(_) => false, // TODO
            })
            .collect::<Vec<_>>();
        let mut children = children
            .iter()
            .map(|tracee| (tracee, tracee.lock()))
            .filter(|(_, guard)| core::ptr::eq(guard.tracer.as_ptr(), self))
            .peekable();
        if children.peek().is_none() {
            return WaitResult::NoChild;
        }

        children
            .find_map(|(tracee, mut guard)| {
                let wstatus = match guard.ptrace_state {
                    PtraceState::Running | PtraceState::SignalRestart { .. } => return None,
                    PtraceState::Signal {
                        sig_info,
                        ref mut reported,
                    } => {
                        if *reported {
                            return None;
                        }
                        *reported = true;
                        WStatus::stopped(sig_info.signal)
                    }
                    PtraceState::Exit { ref mut reported } => {
                        if *reported {
                            return None;
                        }
                        *reported = true;
                        WStatus::ptrace_event(PtraceEvent::Exit)
                    }
                };
                Some(WaitResult::Ready {
                    pid: tracee.tid(),
                    wstatus,
                    rusage: guard.get_rusage(),
                })
            })
            .unwrap_or(WaitResult::NotReady)
    }

    pub fn set_tracer(self: &Arc<Self>, tracer: Weak<Thread>, stop: bool) -> Result<()> {
        if core::ptr::eq(Arc::as_ptr(self), tracer.as_ptr()) {
            todo!()
        }

        if let Some(tracer) = tracer.upgrade() {
            let mut guard = tracer.lock();
            guard.tracees.push(Arc::downgrade(self));
        }

        let mut guard = self.lock();
        ensure!(guard.tracer.strong_count() == 0, Perm);
        guard.tracer = tracer;

        if stop {
            guard.queue_signal(SigInfo {
                signal: Signal::STOP,
                code: SigInfoCode::KERNEL,
                fields: SigFields::None,
            });
        }

        drop(guard);

        Ok(())
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
    ) -> Arc<Thread> {
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
            vfork_done,
            cpu_state,
            self.thread.affinity.get_all(),
            self.thread.nice.load(),
            self.capabilities,
            self.scheduling_settings,
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

    /// Replaces the file descriptor table with an emtpy one.
    pub fn close_all_fds(&mut self) {
        *self.thread.fdtable.lock() = Arc::new(FileDescriptorTable::empty());
    }

    pub fn execve(
        &mut self,
        virtual_memory: VirtualMemory,
        cpu_state: CpuState,
        fdtable: FileDescriptorTable,
    ) {
        self.virtual_memory = Arc::new(virtual_memory);
        *self.thread.cpu_state.lock() = cpu_state;
        *self.thread.fdtable.lock() = Arc::new(fdtable);

        self.clear_child_tid = Pointer::NULL;
        let signal_handler_table = Arc::make_mut(&mut self.signal_handler_table);
        // Reset the signal dispositions of signals that are not ignored.
        signal_handler_table
            .sigactions
            .get_mut()
            .iter_mut()
            .filter(|sa| !matches!(sa.sa_handler_or_sigaction, Sigaction::SIG_IGN))
            .for_each(|sa| *sa = Sigaction::DEFAULT);
        self.sigaltstack = Stack::default();

        let mut guard = self.thread.process.credentials.write();
        guard.saved_set_user_id = guard.effective_user_id;
        guard.saved_set_group_id = guard.effective_group_id;
    }

    #[expect(clippy::too_many_arguments)]
    pub fn start_executable(
        &mut self,
        path: Path,
        link: Link,
        fd: &FileDescriptor,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        ctx: &mut FileAccessContext,
        stack_limit: CurrentStackLimit,
    ) -> Result<()> {
        let virtual_memory = VirtualMemory::new();

        // Load the elf.
        let process = self.process().clone();
        let res = virtual_memory.start_executable(
            path,
            link,
            fd,
            argv,
            envp,
            ctx,
            process.cwd(),
            stack_limit,
        )?;

        // Success! Commit the new state to the thread.

        self.virtual_memory = Arc::new(virtual_memory);
        *self.thread.cpu_state.lock() = res.cpu_state;
        self.clear_child_tid = Pointer::NULL;
        *process.exe.write() = res.exe;
        process.set_mm_arg_start(res.mm_arg_start);
        process.set_mm_arg_end(res.mm_arg_end);

        Ok(())
    }

    /// Determines whether a signal is pending and whether the currently
    /// running syscall should be restarted (if it's capable of being
    /// restarted).
    fn get_pending_signal(&mut self) -> Option<bool> {
        loop {
            // Determine the signal that should be handled next.
            let mut mask = self.sigmask;
            // "SIGKILL and SIGSTOP cannot be (...) blocked (...)."
            mask.remove(Signal::KILL);
            mask.remove(Signal::STOP);

            // If the thread is in a ptrace stop, only SIGKILL can be
            // delivered. All other signals have to wait until the thread exits
            // the ptrace stop.
            if self.ptrace_state.is_stopped() {
                mask = Sigset::all();
                mask.remove(Signal::KILL);
            }

            if self.pending_signal_info.is_none() {
                self.pending_signal_info = self.get_signal(mask);
            }
            let pending_signal_info = self.pending_signal_info?;

            // Check if the signal needs to be handled. If the signal handler
            // wants to ignore the signal we just skip it.
            let handler = self.signal_handler_table.get(pending_signal_info.signal);
            let mut ignored = match (handler.sa_handler_or_sigaction, pending_signal_info.signal) {
                (Sigaction::SIG_DFL, Signal::CHLD | Signal::CONT) => true,
                (
                    Sigaction::SIG_DFL,
                    Signal::HUP
                    | Signal::INT
                    | Signal::ILL
                    | Signal::TRAP
                    | Signal::ABRT
                    | Signal::USR1
                    | Signal::SEGV
                    | Signal::USR2
                    | Signal::PIPE
                    | Signal::ALRM
                    | Signal::TERM,
                ) => false,
                (_, Signal::STOP) => true,
                (_, Signal::KILL) => false,
                (Sigaction::SIG_DFL, signal) => {
                    log::debug!("{pending_signal_info:?}");
                    let maps = self.virtual_memory.maps();
                    let str = String::from_utf8_lossy(&maps);
                    log::debug!("{str}");
                    todo!("unimplemented default for signal {}", signal.get())
                }
                (Sigaction::SIG_IGN, _) => true,
                _ => false,
            };
            // If the thread is being traced, we alway deliver a signal stop
            // event.
            if self.tracer.strong_count() != 0 {
                ignored = false;
            }
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

    pub fn get_signal(&mut self, mask: Sigset) -> Option<SigInfo> {
        self.pending_signals
            .pop(mask)
            .or_else(|| self.process().pop_signal(mask))
    }

    pub fn get_rusage(&self) -> Rusage {
        usage::collect(self.virtual_memory.usage(), &self.thread.usage)
    }

    pub fn stat(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        write!(buffer, "{}", self.process().pid()).unwrap();

        buffer.extend_from_slice(b" (");
        buffer.extend_from_slice(&self.process().task_comm());
        buffer.extend_from_slice(b")");

        buffer.extend_from_slice(b" R"); // TODO: Don't always display the thread as running.

        write!(buffer, " {}", self.process().ppid()).unwrap();

        write!(buffer, " {}", self.process().pgid()).unwrap();

        write!(buffer, " {}", self.process().sid()).unwrap();

        buffer.extend_from_slice(b" 1"); // TODO: tty_nr

        write!(buffer, " {}", self.process().pgid()).unwrap(); // TODO: tpgid

        buffer.extend_from_slice(b" 0"); // TODO: flags

        let rusage = self.get_rusage();
        let children_rusage = *self.process().children_usage.lock();
        write!(buffer, " {}", rusage.minflt).unwrap();
        write!(buffer, " {}", children_rusage.minflt).unwrap();
        write!(buffer, " {}", rusage.majflt).unwrap();
        write!(buffer, " {}", children_rusage.majflt).unwrap();
        write!(buffer, " {}", rusage.utime.kernel_ticks()).unwrap();
        write!(buffer, " {}", rusage.stime.kernel_ticks()).unwrap();
        write!(buffer, " {}", children_rusage.utime.kernel_ticks()).unwrap();
        write!(buffer, " {}", children_rusage.stime.kernel_ticks()).unwrap();

        let nice = self.thread.nice.load();
        write!(buffer, " {}", nice.as_syscall_return_value()).unwrap();
        write!(buffer, " {}", nice.get()).unwrap();

        write!(buffer, " {}", self.process().threads.lock().len()).unwrap();

        buffer.extend_from_slice(b" 0"); // hard-coded to be 0.

        write!(buffer, " {}", self.process().start_time.kernel_ticks()).unwrap();

        write!(buffer, " {}", self.virtual_memory().size()).unwrap();

        let virtual_memory_usage = self.virtual_memory.usage();
        write!(buffer, " {}", virtual_memory_usage.rss()).unwrap();

        buffer.extend_from_slice(b" 18446744073709551615"); // rsslim

        buffer.extend_from_slice(b" 0"); // TODO: startcode
        buffer.extend_from_slice(b" 18446744073709551615"); // TODO: encode

        buffer.extend_from_slice(b" 0"); // TODO: startstack
        buffer.extend_from_slice(b" 0"); // TODO: kstkesp
        buffer.extend_from_slice(b" 0"); // TODO: kstkeip

        buffer.extend_from_slice(b" 0"); // TODO: signal
        buffer.extend_from_slice(b" 0"); // TODO: blocked
        buffer.extend_from_slice(b" 0"); // TODO: sigignore
        buffer.extend_from_slice(b" 0"); // TODO: sigcatch

        buffer.extend_from_slice(b" 0"); // wchan

        buffer.extend_from_slice(b" 0"); // nswap
        buffer.extend_from_slice(b" 0"); // cnswap

        write!(
            buffer,
            " {}",
            self.process().termination_signal.map_or(0, |s| s.get())
        )
        .unwrap();

        buffer.extend_from_slice(b" 0"); // processor

        buffer.extend_from_slice(b" 0"); // rt_priority

        buffer.extend_from_slice(b" 0"); // policy

        buffer.extend_from_slice(b" 0"); // delayacct_blkio_ticks

        buffer.extend_from_slice(b" 0"); // guest_time
        buffer.extend_from_slice(b" 0"); // cguest_time

        buffer.extend_from_slice(b" 0"); // TODO: start_data
        buffer.extend_from_slice(b" 18446744073709551615"); // TODO: end_data

        buffer.extend_from_slice(b" 0"); // TODO: start_brk

        buffer.extend_from_slice(b" 0"); // TODO: arg_start
        buffer.extend_from_slice(b" 18446744073709551615"); // TODO: arg_end

        buffer.extend_from_slice(b" 0"); // TODO: env_start
        buffer.extend_from_slice(b" 18446744073709551615"); // TODO: env_end

        buffer.extend_from_slice(b" 0"); // TODO: exit_code

        buffer.push(b'\n');

        buffer
    }

    pub fn status(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        write!(buffer, "Name:\t").unwrap();
        buffer.extend_from_slice(&self.task_comm());
        writeln!(buffer).unwrap();

        writeln!(buffer, "Umask:\t{0:4o}", self.process().umask()).unwrap();

        writeln!(buffer, "Tgid:\t{}", self.process().pid()).unwrap();

        writeln!(buffer, "Ngid:\t0").unwrap();

        writeln!(buffer, "Pid:\t{}", self.process().pid()).unwrap();

        writeln!(buffer, "Ppid:\t{}", self.process().ppid()).unwrap();

        writeln!(
            buffer,
            "Ppid:\t{}",
            self.tracer.upgrade().map_or(0, |thread| thread.tid())
        )
        .unwrap();

        let usage = self.virtual_memory.usage();
        writeln!(
            buffer,
            "VmPeak:\t{} kB",
            (usage.vmpeak() * Size4KiB::SIZE) / 1024
        )
        .unwrap();
        writeln!(
            buffer,
            "VmSize:\t{} kB",
            (usage.vmsize() * Size4KiB::SIZE) / 1024
        )
        .unwrap();

        // TODO: More

        buffer
    }

    pub fn task_comm(&self) -> ArrayVec<u8, TASK_COMM_CAPACITY> {
        self.task_comm
            .clone()
            .unwrap_or_else(|| self.process().task_comm())
    }

    pub fn set_task_comm(&mut self, task_comm: ArrayVec<u8, TASK_COMM_CAPACITY>) {
        self.task_comm = Some(task_comm);
    }

    pub fn no_new_privs(&self) -> bool {
        self.no_new_privs
    }

    pub fn set_no_new_privs(&mut self) {
        self.no_new_privs = true;
    }

    /// Returns true if the signal was not already queued.
    pub fn queue_signal(&mut self, sig_info: SigInfo) -> bool {
        match sig_info.signal {
            Signal::CONT | Signal::KILL => self.process().stop_state.cont(),
            Signal::STOP => self.process().stop_state.stop(),
            _ => {}
        }

        let added = self.pending_signals.add(sig_info);
        if added {
            self.thread.signal_notify.notify();
        }
        added
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

impl Drop for Thread {
    fn drop(&mut self) {
        let this = self as *const _;
        let state = self.state.get_mut();
        for tracee in state.tracees.iter().filter_map(Weak::upgrade) {
            let mut guard = tracee.lock();
            if core::ptr::eq(guard.tracer.as_ptr(), this) {
                guard.ptrace_state = PtraceState::Running;
                drop(guard);
                tracee.ptrace_tracee_notify.notify();
            }
        }
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

    pub const fn all() -> Self {
        Self(!0)
    }

    pub fn add(&mut self, signal: Signal) {
        self.0 |= 1 << (signal.get() - 1);
    }

    pub fn remove(&mut self, signal: Signal) {
        self.0 &= !(1 << (signal.get() - 1));
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

    pub fn is_empty(&self) -> bool {
        *self == Self::empty()
    }
}

impl BitOr for Sigset {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Sigset {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
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

impl FromIterator<Signal> for Sigset {
    fn from_iter<T: IntoIterator<Item = Signal>>(iter: T) -> Self {
        let mut sigset = Self::empty();
        for signal in iter {
            sigset.add(signal);
        }
        sigset
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
        const RESETHAND = 0x80000000;
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
    queue_counter: EventCounter,
}

impl PendingSignals {
    pub const fn new() -> Self {
        Self {
            pending_signals: VecDeque::new(),
            queue_counter: EventCounter::new(),
        }
    }

    pub fn pending_signals(&self) -> Sigset {
        self.pending_signals
            .iter()
            .map(|sig_info| sig_info.signal)
            .collect()
    }

    pub fn queue_counter(&self) -> EventCounter {
        self.queue_counter.clone()
    }

    /// Add the signal to the set of pending signals.
    ///
    /// Returns true if the signal was added.
    pub fn add(&mut self, sig_info: SigInfo) -> bool {
        self.queue_counter.inc();
        let is_pending = self
            .pending_signals
            .iter()
            .any(|s| s.signal == sig_info.signal);
        // Only queue the signal if it's not already pending.
        if !is_pending {
            // Prioritize SIGKILL over everything else.
            if sig_info.signal == Signal::KILL {
                self.pending_signals.push_front(sig_info);
            } else {
                self.pending_signals.push_back(sig_info);
            }
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

    pub const USER: Self = Self(0);
    pub const CLD_EXITED: Self = Self(1);
    pub const FPE_INTDIV: Self = Self(1);
    pub const SEGV_MAPERR: Self = Self(1);
    pub const SEGV_ACCERR: Self = Self(2);
    pub const ILL_ILLOPN: Self = Self(2);
    pub const BUS_ADRERR: Self = Self(2);
    pub const FPE_FLTDIV: Self = Self(3);
    pub const FPE_FLTOVF: Self = Self(4);
    pub const FPE_FLTUND: Self = Self(5);
    pub const FPE_FLTRES: Self = Self(6);
    pub const FPE_FLTINV: Self = Self(7);
    pub const KERNEL: Self = Self(0x80);
    pub const TIMER: Self = Self(-2);
    pub const TKILL: Self = Self(-6);
}

#[derive(Debug, Clone, Copy)]
pub enum SigFields {
    None,
    Kill(SigKill),
    Timer(SigTimer),
    SigChld(SigChld),
    SigFault(SigFault),
}

impl SigFields {
    /// PID of sender
    pub fn pid(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Kill(sig_kill) => sig_kill.pid,
            Self::Timer(_) => 0,
            Self::SigChld(sig_chld) => sig_chld.pid as u32,
            Self::SigFault(_) => 0,
        }
    }

    /// Real UID of sender
    pub fn uid(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Kill(sig_kill) => sig_kill.uid.get(),
            Self::Timer(_) => 0,
            Self::SigChld(sig_chld) => sig_chld.uid,
            Self::SigFault(_) => 0,
        }
    }

    /// File descriptor (SIGIO)
    pub fn fd(&self) -> i32 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(_) => 0,
            Self::SigChld(_) => 0,
            Self::SigFault(_) => 0,
        }
    }

    /// Kernel timer ID (POSIX timer)
    pub fn tid(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(sig_timer) => sig_timer.tid.0 as u32,
            Self::SigChld(_) => 0,
            Self::SigFault(_) => 0,
        }
    }

    /// Band event (SIGIO)
    pub fn band(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(_) => 0,
            Self::SigChld(_) => 0,
            Self::SigFault(_) => 0,
        }
    }

    /// POSIX timer overrun count
    pub fn overrun(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(sig_timer) => sig_timer.overrun,
            Self::SigChld(_) => 0,
            Self::SigFault(_) => 0,
        }
    }

    /// Trap number that caused signal
    pub fn trapno(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(_) => 0,
            Self::SigChld(_) => 0,
            Self::SigFault(_) => 0,
        }
    }

    /// Exit status or signal (SIGCHLD)
    pub fn status(&self) -> i32 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(_) => 0,
            Self::SigChld(sig_chld) => sig_chld.status.raw() as i32,
            Self::SigFault(_) => 0,
        }
    }

    /// Integer sent by sigqueue(3)
    pub fn int(&self) -> i32 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(_) => 0,
            Self::SigChld(_) => 0,
            Self::SigFault(_) => 0,
        }
    }

    /// Pointer sent by sigqueue(3)
    pub fn ptr(&self) -> u64 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(_) => 0,
            Self::SigChld(_) => 0,
            Self::SigFault(_) => 0,
        }
    }

    /// User CPU time consumed (SIGCHLD)
    pub fn utime(&self) -> u64 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(_) => 0,
            Self::SigChld(sig_chld) => sig_chld.utime as u64,
            Self::SigFault(_) => 0,
        }
    }

    /// System CPU time consumed (SIGCHLD)
    pub fn stime(&self) -> u64 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(_) => 0,
            Self::SigChld(sig_chld) => sig_chld.stime as u64,
            Self::SigFault(_) => 0,
        }
    }

    /// Address that generated signal (for hardware-generated signals)
    pub fn addr(&self) -> u64 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(_) => 0,
            Self::SigChld(_) => 0,
            Self::SigFault(sig_fault) => sig_fault.addr,
        }
    }

    pub fn addr_lsb(&self) -> u16 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(_) => 0,
            Self::SigChld(_) => 0,
            Self::SigFault(_) => 0,
        }
    }

    pub fn syscall(&self) -> i32 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(_) => 0,
            Self::SigChld(_) => 0,
            Self::SigFault(_) => 0,
        }
    }

    pub fn call_addr(&self) -> u64 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(_) => 0,
            Self::SigChld(_) => 0,
            Self::SigFault(_) => 0,
        }
    }

    pub fn arch(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Kill(_) => 0,
            Self::Timer(_) => 0,
            Self::SigChld(_) => 0,
            Self::SigFault(_) => 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SigKill {
    pub pid: u32,
    pub uid: Uid,
}

#[derive(Debug, Clone, Copy)]
pub struct SigTimer {
    pub tid: TimerId,
    pub overrun: u32,
    pub sigval: Pointer<c_void>,
}

#[derive(Debug, Clone, Copy)]
pub struct SigChld {
    pub pid: i32,
    pub uid: u32,
    pub status: WStatus,
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

#[derive(Clone)]
pub struct Credentials {
    pub real_user_id: Uid,
    pub real_group_id: Gid,
    pub effective_user_id: Uid,
    pub effective_group_id: Gid,
    pub saved_set_user_id: Uid,
    pub saved_set_group_id: Gid,
    pub filesystem_user_id: Uid,
    pub filesystem_group_id: Gid,
    pub supplementary_group_ids: Arc<[Gid]>,
}

impl Credentials {
    pub fn super_user() -> Self {
        Self {
            real_user_id: Uid::SUPER_USER,
            real_group_id: Gid::SUPER_USER,
            effective_user_id: Uid::SUPER_USER,
            effective_group_id: Gid::SUPER_USER,
            saved_set_user_id: Uid::SUPER_USER,
            saved_set_group_id: Gid::SUPER_USER,
            filesystem_user_id: Uid::SUPER_USER,
            filesystem_group_id: Gid::SUPER_USER,
            supplementary_group_ids: Arc::new([]),
        }
    }

    pub fn is_super_user(&self) -> bool {
        self.effective_user_id == Uid::SUPER_USER
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct Uid(u32);

impl Uid {
    pub const SUPER_USER: Self = Self(0);
    pub const UNCHANGED: Self = Self(!0);

    pub fn new(uid: u32) -> Self {
        Self(uid)
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct Gid(u32);

impl Gid {
    pub const SUPER_USER: Self = Self(0);
    pub const UNCHANGED: Self = Self(!0);

    pub fn new(gid: u32) -> Self {
        Self(gid)
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    bounding: CapabilitySet,
    ambient: CapabilitySet,
}

impl Capabilities {
    pub fn new() -> Self {
        Self {
            bounding: CapabilitySet::all(),
            ambient: CapabilitySet::empty(),
        }
    }

    pub fn bounding_set_read(&self, cap: Capability) -> bool {
        self.bounding.get(cap)
    }

    pub fn ambient_is_set(&self, cap: Capability) -> bool {
        self.ambient.get(cap)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Capability {
    Chown = 0,
    DacOverride = 1,
    DacReadSearch = 2,
    Fowner = 3,
    Fsetid = 4,
    Kill = 5,
    Setgid = 6,
    Setuid = 7,
    Setpcap = 8,
    LinuxImmutable = 9,
    NetBindService = 10,
    NetBroadcast = 11,
    NetAdmin = 12,
    NetRaw = 13,
    IpcLock = 14,
    IpcOwner = 15,
    SysModule = 16,
    SysRawio = 17,
    SysChroot = 18,
    SysPtrace = 19,
    SysPacct = 20,
    SysAdmin = 21,
    SysBoot = 22,
    SysNice = 23,
    SysResource = 24,
    SysTime = 25,
    SysTtyConfig = 26,
    Mknod = 27,
    Lease = 28,
    AuditWrite = 29,
    AuditControl = 30,
    Setfcap = 31,
    MacOverride = 32,
    MacAdmin = 33,
    Syslog = 34,
    WakeAlarm = 35,
    BlockSuspend = 36,
    AuditRead = 37,
    Perfmon = 38,
    Bpf = 39,
    CheckpointRestore = 40,
}

impl Capability {
    const ALL: [Self; 41] = [
        Self::Chown,
        Self::DacOverride,
        Self::DacReadSearch,
        Self::Fowner,
        Self::Fsetid,
        Self::Kill,
        Self::Setgid,
        Self::Setuid,
        Self::Setpcap,
        Self::LinuxImmutable,
        Self::NetBindService,
        Self::NetBroadcast,
        Self::NetAdmin,
        Self::NetRaw,
        Self::IpcLock,
        Self::IpcOwner,
        Self::SysModule,
        Self::SysRawio,
        Self::SysChroot,
        Self::SysPtrace,
        Self::SysPacct,
        Self::SysAdmin,
        Self::SysBoot,
        Self::SysNice,
        Self::SysResource,
        Self::SysTime,
        Self::SysTtyConfig,
        Self::Mknod,
        Self::Lease,
        Self::AuditWrite,
        Self::AuditControl,
        Self::Setfcap,
        Self::MacOverride,
        Self::MacAdmin,
        Self::Syslog,
        Self::WakeAlarm,
        Self::BlockSuspend,
        Self::AuditRead,
        Self::Perfmon,
        Self::Bpf,
        Self::CheckpointRestore,
    ];

    pub const fn new(value: u8) -> Option<Self> {
        let mut i = 0;
        while i < Capability::ALL.len() {
            let cap = Capability::ALL[i];
            if cap as u8 == value {
                return Some(cap);
            }
            i += 1;
        }
        None
    }
}

#[derive(Clone, Copy)]
pub struct CapabilitySet {
    bits: u64,
}

impl Debug for CapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(Capability::ALL.into_iter().filter(|&cap| self.get(cap)))
            .finish()
    }
}

impl CapabilitySet {
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    pub const fn all() -> Self {
        let mut this = Self::empty();
        let mut i = 0;
        while i < Capability::ALL.len() {
            let cap = Capability::ALL[i];
            this.set(cap, true);
            i += 1;
        }
        this
    }

    pub const fn set(&mut self, cap: Capability, set: bool) {
        let mask = 1 << cap as usize;
        if set {
            self.bits |= mask;
        } else {
            self.bits &= !mask;
        }
    }

    pub const fn get(&self, cap: Capability) -> bool {
        self.bits & (1 << cap as usize) != 0
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub enum PtraceState {
    /// The thread is running.
    #[default]
    Running,
    /// The thread was just restarted with a signal, but hasn't started running
    /// yet. It will start running after the signal has been queued.
    SignalRestart(SigInfo),
    /// The thread has stopped because a signal occured.
    Signal { sig_info: SigInfo, reported: bool },
    /// The thread exited. Either explicitly via exit(2) or implicitely via
    /// exit_group(2) or execve(2).
    Exit { reported: bool },
}

impl PtraceState {
    pub fn is_stopped(&self) -> bool {
        match self {
            PtraceState::Running | PtraceState::SignalRestart { .. } => false,
            PtraceState::Signal { .. } | PtraceState::Exit { .. } => true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SchedulingSettings {
    policy: SchedulingPolicy,
    priority: i32,
}

impl SchedulingSettings {
    pub fn new(policy: SchedulingPolicy, param: SchedParam) -> Result<Self> {
        ensure!(
            policy.priority_range().contains(&param.sched_priority),
            Inval
        );
        Ok(Self {
            policy,
            priority: param.sched_priority,
        })
    }

    pub fn policy(&self) -> SchedulingPolicy {
        self.policy
    }

    pub fn param(&self) -> SchedParam {
        SchedParam {
            sched_priority: self.priority,
        }
    }

    pub fn set_param(&mut self, param: SchedParam) -> Result<()> {
        *self = Self::new(self.policy, param)?;
        Ok(())
    }
}

impl Default for SchedulingSettings {
    fn default() -> Self {
        Self {
            policy: SchedulingPolicy::Normal,
            priority: 0,
        }
    }
}
