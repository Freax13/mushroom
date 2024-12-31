#[cfg(not(feature = "harden"))]
use core::fmt::{self, Write};
use core::{
    ffi::CStr,
    iter::from_fn,
    ops::Not,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[cfg(not(feature = "harden"))]
use alloc::string::String;
use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
    vec::Vec,
};
use arrayvec::ArrayVec;
use futures::{select_biased, FutureExt};
use limits::{CurrentStackLimit, Limits};
use syscall::args::{ClockId, Rusage, Timespec};
use thread::{Credentials, Gid, Uid};

use crate::{
    error::{err, Result},
    fs::{
        fd::FileDescriptorTable,
        node::{
            procfs::ProcessInos,
            tmpfs::{TmpFs, TmpFsFile},
            DynINode, FileAccessContext, INode,
        },
        path::{Path, PathSegment},
        StaticFile,
    },
    rt::{notify::Notify, once::OnceCell, oneshot, spawn},
    spin::{lazy::Lazy, mutex::Mutex, rwlock::RwLock},
    supervisor,
    time::{now, sleep_until},
    user::process::syscall::args::{ExtractableThreadState, FileMode, OpenFlags},
};

use self::{
    futex::Futexes,
    memory::VirtualMemory,
    syscall::{
        args::{Signal, WStatus},
        cpu_state::CpuState,
    },
    thread::{
        new_tid, running_state::ExecveValues, PendingSignals, SigChld, SigFields, SigInfo,
        SigInfoCode, Sigset, Thread, WeakThread,
    },
};

mod exec;
mod futex;
pub mod limits;
pub mod memory;
pub mod syscall;
pub mod thread;
pub mod usage;

const TASK_COMM_CAPACITY: usize = 16;

pub struct Process {
    pid: u32,
    start_time: Timespec,
    futexes: Arc<Futexes>,
    exit_status: OnceCell<WStatus>,
    parent: Weak<Self>,
    children: Mutex<Vec<Arc<Self>>>,
    child_death_notify: Notify,
    termination_signal: Option<Signal>,
    pending_signals: Mutex<PendingSignals>,
    signals_notify: Notify,
    threads: Mutex<Vec<WeakThread>>,
    /// The number of running threads.
    running: AtomicUsize,
    pub inos: ProcessInos,
    exe: RwLock<Path>,
    task_comm: Mutex<ArrayVec<u8, TASK_COMM_CAPACITY>>,
    alarm: Mutex<Option<AlarmState>>,
    stop_state: StopState,
    pub credentials: Mutex<Credentials>,
    cwd: Mutex<DynINode>,
    process_group: Mutex<Arc<ProcessGroup>>,
    pub limits: RwLock<Limits>,
    pub umask: Mutex<FileMode>,
    /// The usage of all terminated threads.
    pub self_usage: Mutex<Rusage>,
    pub children_usage: Mutex<Rusage>,
}

impl Process {
    #[allow(clippy::too_many_arguments)]
    fn new(
        first_tid: u32,
        parent: Weak<Self>,
        termination_signal: Option<Signal>,
        exe: Path,
        credentials: Credentials,
        cwd: DynINode,
        process_group: Arc<ProcessGroup>,
        limits: Limits,
        umask: FileMode,
    ) -> Arc<Self> {
        let PathSegment::FileName(last_path_segment) = exe.segments().last().unwrap() else {
            unreachable!()
        };
        let task_comm = last_path_segment
            .as_bytes()
            .iter()
            .copied()
            .take(TASK_COMM_CAPACITY)
            .collect();

        let this = Self {
            pid: first_tid,
            start_time: now(ClockId::Monotonic),
            futexes: Arc::new(Futexes::new()),
            exit_status: OnceCell::new(),
            parent: parent.clone(),
            children: Mutex::new(Vec::new()),
            child_death_notify: Notify::new(),
            termination_signal,
            pending_signals: Mutex::new(PendingSignals::new()),
            signals_notify: Notify::new(),
            threads: Mutex::new(Vec::new()),
            running: AtomicUsize::new(0),
            inos: ProcessInos::new(),
            exe: RwLock::new(exe),
            task_comm: Mutex::new(task_comm),
            alarm: Mutex::new(None),
            stop_state: StopState::default(),
            credentials: Mutex::new(credentials),
            cwd: Mutex::new(cwd),
            process_group: Mutex::new(process_group.clone()),
            limits: RwLock::new(limits),
            umask: Mutex::new(umask),
            self_usage: Mutex::default(),
            children_usage: Mutex::default(),
        };
        let arc = Arc::new(this);

        if let Some(parent) = parent.upgrade() {
            parent.children.lock().push(arc.clone());
        }
        process_group.processes.lock().push(Arc::downgrade(&arc));

        arc
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn ppid(&self) -> u32 {
        self.parent.upgrade().map_or(1, |parent| parent.pid())
    }

    pub fn pgrp(&self) -> u32 {
        self.process_group.lock().pgid
    }

    pub fn sid(&self) -> u32 {
        self.process_group.lock().session.lock().sid
    }

    pub fn exe(&self) -> Path {
        self.exe.read().clone()
    }

    pub fn task_comm(&self) -> ArrayVec<u8, TASK_COMM_CAPACITY> {
        self.task_comm.lock().clone()
    }

    pub fn cwd(&self) -> DynINode {
        self.cwd.lock().clone()
    }

    pub fn chdir(&self, cwd: DynINode) {
        *self.cwd.lock() = cwd;
    }

    pub fn add_thread(&self, thread: WeakThread) {
        let mut guard = self.threads.lock();
        guard.push(thread);
        self.running.fetch_add(1, Ordering::Relaxed);
    }

    pub fn restart_thread(&self) {
        self.running.fetch_add(1, Ordering::Relaxed);
    }

    pub fn exit(&self, exit_status: WStatus, rusage: Rusage) {
        let mut guard = self.self_usage.lock();
        *guard = guard.merge(rusage);
        drop(guard);

        let prev = self.running.fetch_sub(1, Ordering::Relaxed);
        if prev == 1 {
            self.exit_group(exit_status);
        }
    }

    pub fn execve(
        &self,
        virtual_memory: VirtualMemory,
        cpu_state: CpuState,
        fdtable: FileDescriptorTable,
        exe: Path,
    ) {
        *self.exe.write() = exe;
        let mut threads = self.threads.lock();

        // Restart the thread leader.
        let leader = threads[0].upgrade().unwrap();
        leader.execve(ExecveValues {
            virtual_memory,
            cpu_state,
            fdtable,
        });

        // Stop all threads except for the thread group leader.
        for thread in threads.drain(1..).filter_map(|t| t.upgrade()) {
            thread.terminate(WStatus::exit(0));
        }
    }

    /// Terminate all threads in the thread group.
    ///
    /// The returned exit status may not be the same as the requested
    /// if another thread terminated the thread group at the same time.
    pub fn exit_group(&self, exit_status: WStatus) {
        if self.pid == 1 {
            // Commit or fail the output depending on the exit status of the
            // init process.
            if exit_status == WStatus::exit(0) {
                supervisor::finish_output();
            } else {
                supervisor::fail();
            }
        }

        let set = self.exit_status.set(exit_status);
        if !set {
            return;
        }

        let mut threads = self.threads.lock();
        for thread in core::mem::take(&mut *threads)
            .into_iter()
            .filter_map(|t| t.upgrade())
        {
            thread.terminate(exit_status);
        }
        drop(threads);

        if let Some(termination_signal) = self.termination_signal {
            if let Some(parent) = self.parent.upgrade() {
                parent.queue_signal(SigInfo {
                    signal: termination_signal,
                    code: SigInfoCode::CLD_EXITED,
                    fields: SigFields::SigChld(SigChld {
                        pid: self.pid as i32,
                        uid: 0,
                        status: exit_status,
                        utime: 0,
                        stime: 0,
                    }),
                });
            }
        }

        if let Some(parent) = self.parent.upgrade() {
            parent.child_death_notify.notify();
        }
    }

    pub fn thread_group_leader(&self) -> Weak<Thread> {
        self.threads.lock().first().cloned().unwrap_or_default()
    }

    pub async fn exit_status(&self) -> WStatus {
        *self.exit_status.get().await
    }

    pub async fn wait_for_child_death(
        &self,
        filter: WaitFilter,
        no_hang: bool,
    ) -> Result<Option<(u32, WStatus)>> {
        self.child_death_notify
            .wait_until(|| {
                let mut guard = self.children.lock();
                if guard.is_empty() {
                    return Some(Err(err!(Child)));
                }

                let opt_idx = guard
                    .iter()
                    .enumerate()
                    .filter(|(_, child)| match filter {
                        WaitFilter::Any => true,
                        WaitFilter::ExactPid(pid) => child.pid() == pid,
                        WaitFilter::ExactPgid(pgid) => child.process_group.lock().pgid == pgid,
                    })
                    .filter(|(_, child)| child.exit_status.try_get().is_some())
                    .map(|(i, _)| i)
                    .next();

                let Some(idx) = opt_idx else {
                    if no_hang {
                        return Some(Ok(None));
                    } else {
                        return None;
                    }
                };
                let child = guard.swap_remove(idx);

                let usage = *child.self_usage.lock();
                let mut guard = self.children_usage.lock();
                *guard = guard.merge(usage);
                drop(guard);

                let status = *child.exit_status.try_get().unwrap();
                Some(Ok(Some((child.pid, status))))
            })
            .await
    }

    pub fn queue_signal(&self, sig_info: SigInfo) {
        match sig_info.signal {
            Signal::CONT | Signal::KILL => self.stop_state.cont(),
            Signal::STOP => self.stop_state.stop(),
            _ => {}
        }

        self.pending_signals.lock().add(sig_info);
        self.signals_notify.notify();
    }

    fn pop_signal(&self, mask: Sigset) -> Option<SigInfo> {
        self.pending_signals.lock().pop(mask)
    }

    pub fn can_send_signal(&self, target: &Process, signal: Signal) -> bool {
        // A process can always send a signal to itself.
        if core::ptr::eq(self, target) {
            return true;
        }

        if signal == Signal::CONT {
            // > In the case of SIGCONT, it suffices when the sending and
            // > receiving processes belong to the same session.

            let (self_process_group, target_process_group) =
                self.process_group.lock_two(&target.process_group);

            // If the processes are part of the same process group, they're also part of the same session.
            if self_process_group.pgid == target_process_group.pgid {
                return true;
            }

            let (self_session, target_session) = self_process_group
                .session
                .lock_two(&target_process_group.session);
            if self_session.sid == target_session.sid {
                return true;
            }
        }

        let (self_guard, target_guard) = self.credentials.lock_two(&target.credentials);
        if self_guard.is_super_user() {
            return true;
        }
        [self_guard.real_user_id, self_guard.effective_user_id]
            .into_iter()
            .any(|uid| [target_guard.real_user_id, target_guard.saved_set_user_id].contains(&uid))
    }

    pub fn find_by_pid(pid: u32) -> Option<Arc<Self>> {
        Self::all().find(|p| p.pid == pid)
    }

    pub fn find_by_pid_in(self: &Arc<Self>, pid: u32) -> Option<Arc<Self>> {
        self.iter().find(|p| p.pid == pid)
    }

    pub fn all() -> impl Iterator<Item = Arc<Self>> {
        INIT_THREAD.process().iter()
    }

    fn iter(self: &Arc<Self>) -> impl Iterator<Item = Arc<Self>> {
        let mut queue = VecDeque::new();
        queue.push_back(self.clone());
        from_fn(move || {
            let process = queue.pop_front()?;
            queue.extend(process.children.lock().iter().cloned());
            Some(process)
        })
    }

    pub fn schedule_alarm(self: &Arc<Self>, seconds: u32) -> u32 {
        let now = now(ClockId::Monotonic);
        let (cancel_tx, cancel_rx) = oneshot::new();
        let deadline = now.saturating_add(Timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        });
        let new_state = AlarmState {
            deadline,
            cancel_tx,
        };

        let prev_state = self.alarm.lock().replace(new_state);

        let this = self.clone();
        spawn(async move {
            select_biased! {
                _ = cancel_rx.recv().fuse() => {
                    // The alarm has been cancelled -> do nothing.
                }
                _ = sleep_until(deadline, ClockId::Monotonic).fuse() => {
                    // The alarm has fired -> queue a signal.
                    this.queue_signal(SigInfo {
                        signal: Signal::ALRM,
                        code: SigInfoCode::KERNEL,
                        fields: SigFields::None,
                    });
                }
            }
        });

        AlarmState::remaining_seconds(prev_state, now)
    }

    pub fn cancel_alarm(&self) -> u32 {
        let prev_state = self.alarm.lock().take();
        AlarmState::remaining_seconds(prev_state, now(ClockId::Monotonic))
    }

    pub async fn wait_until_not_stopped(&self) {
        self.stop_state.wait().await;
    }

    #[cfg(not(feature = "harden"))]
    pub fn dump(&self, indent: usize, write: &mut impl Write) -> fmt::Result {
        let process_group_guard = self.process_group.lock();
        let session_guard = process_group_guard.session.lock();
        let pgid = process_group_guard.pgid;
        let sid = session_guard.sid;
        drop(session_guard);
        drop(process_group_guard);
        writeln!(
            write,
            "{:indent$}process pid={} pgid={pgid} sid={sid} exit_status={:?}",
            "",
            self.pid,
            self.exit_status.try_get()
        )?;

        let indent = indent + 2;
        let threads_guard = self.threads.lock();
        for guard in threads_guard.iter().filter_map(Weak::upgrade) {
            guard.dump(indent, &mut *write)?;
        }

        let threads_guard = self.children.lock();
        for guard in threads_guard.iter() {
            guard.dump(indent, &mut *write)?;
        }

        Ok(())
    }
}

#[derive(Clone, Copy)]
pub enum WaitFilter {
    Any,
    ExactPid(u32),
    ExactPgid(u32),
}

#[cfg(not(feature = "harden"))]
pub fn dump() {
    let mut buf = String::new();
    INIT_THREAD.process().dump(0, &mut buf).unwrap();
    for line in buf.lines() {
        log::info!("{line}");
    }
}

struct AlarmState {
    deadline: Timespec,
    cancel_tx: oneshot::Sender<()>,
}

impl AlarmState {
    fn remaining_seconds(state: Option<Self>, now: Timespec) -> u32 {
        if let Some(state) = state {
            let _ = state.cancel_tx.send(());
            now.checked_sub(state.deadline).map_or(0, |tv| tv.tv_sec)
        } else {
            0
        }
    }
}

#[derive(Default)]
struct StopState {
    stopped: AtomicBool,
    notify: Notify,
}

impl StopState {
    async fn wait(&self) {
        self.notify
            .wait_until(|| self.stopped.load(Ordering::Relaxed).not().then_some(()))
            .await;
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }

    fn cont(&self) {
        self.stopped.store(false, Ordering::Relaxed);
        self.notify.notify();
    }
}

pub struct ProcessGroup {
    pgid: u32,
    session: Mutex<Arc<Session>>,
    processes: Mutex<Vec<Weak<Process>>>,
}

impl ProcessGroup {
    pub fn new(pgid: u32, session: Arc<Session>) -> Arc<Self> {
        let this = Self {
            pgid,
            session: Mutex::new(session.clone()),
            processes: Mutex::new(Vec::new()),
        };
        let arc = Arc::new(this);
        session.process_groups.lock().push(Arc::downgrade(&arc));
        arc
    }
}

pub struct Session {
    sid: u32,
    process_groups: Mutex<Vec<Weak<ProcessGroup>>>,
}

impl Session {
    pub fn new(sid: u32) -> Self {
        Self {
            sid,
            process_groups: Mutex::new(Vec::new()),
        }
    }
}

static INIT_THREAD: Lazy<Arc<Thread>> = Lazy::new(|| {
    let tid = new_tid();
    assert_eq!(tid, 1);
    let thread = Thread::empty(tid);

    let mut guard = thread.lock();
    let mut ctx = FileAccessContext::extract_from_thread(&guard);

    let file = TmpFsFile::new(
        TmpFs::new(),
        FileMode::all(),
        Uid::SUPER_USER,
        Gid::SUPER_USER,
    );
    StaticFile::init_file().copy_to(&file).unwrap();
    let path = Path::new(b"/bin/init".to_vec()).unwrap();
    let file = file.open(path.clone(), OpenFlags::empty()).unwrap();

    guard
        .start_executable(
            path,
            &file,
            &[c"/bin/init"],
            &[] as &[&CStr],
            &mut ctx,
            CurrentStackLimit::default(),
        )
        .unwrap();
    drop(guard);

    let thread = Arc::new(thread);
    thread.clone().spawn();

    thread
});

pub fn start_init_process() {
    INIT_THREAD.process();
}
