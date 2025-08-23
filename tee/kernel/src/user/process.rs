#[cfg(not(feature = "harden"))]
use alloc::string::String;
use alloc::{
    collections::{VecDeque, btree_map::BTreeMap},
    sync::{Arc, Weak},
    vec::Vec,
};
#[cfg(not(feature = "harden"))]
use core::fmt::{self, Write};
use core::{
    ffi::CStr,
    iter::from_fn,
    ops::Not,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use arrayvec::ArrayVec;
use crossbeam_utils::atomic::AtomicCell;
use futures::{FutureExt, select_biased};
use x86_64::VirtAddr;

use self::{
    limits::{CurrentStackLimit, Limits},
    memory::VirtualMemory,
    syscall::args::{ClockId, Rusage, Signal, Timespec, WStatus},
    thread::{
        Credentials, Gid, PendingSignals, SigChld, SigFields, SigInfo, SigInfoCode, Sigset, Thread,
        Uid, WeakThread, new_tid, running_state::ExecveValues,
    },
};
use crate::{
    char_dev::char::PtyData,
    error::{Result, bail, err},
    fs::{
        StaticFile,
        fd::FileDescriptorTable,
        node::{
            FileAccessContext, INode, Link, LinkLocation, ROOT_NODE,
            procfs::ProcessInos,
            tmpfs::{TmpFs, TmpFsFile},
        },
        path::{FileName, Path},
    },
    rt::{notify::Notify, once::OnceCell, oneshot, spawn},
    spin::{lazy::Lazy, mutex::Mutex, once::Once, rwlock::RwLock},
    supervisor,
    time::{CpuTimeBackend, Time, now, sleep_until},
    user::process::{
        exec::ExecResult,
        syscall::args::{
            ExtractableThreadState, FileMode, ITimerWhich, ITimerspec, ITimerval, OpenFlags,
            SigEvent, TimerId,
        },
        timer::Timer,
    },
};

mod exec;
pub mod futex;
pub mod limits;
pub mod memory;
pub mod syscall;
pub mod thread;
mod timer;
pub mod usage;

pub const TASK_COMM_CAPACITY: usize = 15;

pub struct Process {
    pid: u32,
    start_time: Timespec,
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
    exe: RwLock<Link>,
    task_comm: Mutex<ArrayVec<u8, TASK_COMM_CAPACITY>>,
    alarm: Mutex<Option<AlarmState>>,
    stop_state: StopState,
    pub credentials: Mutex<Credentials>,
    cwd: Mutex<Link>,
    process_group: Mutex<Arc<ProcessGroup>>,
    pub limits: RwLock<Limits>,
    pub umask: Mutex<FileMode>,
    /// The usage of all terminated threads.
    pub self_usage: Mutex<Rusage>,
    pub children_usage: Mutex<Rusage>,
    real_itimer: Timer,
    timers: Mutex<BTreeMap<TimerId, Timer>>,
    pub cpu_time: Time<CpuTimeBackend>,
    mm_arg_start: AtomicCell<VirtAddr>,
    mm_arg_end: AtomicCell<VirtAddr>,
    parent_death_signal: AtomicCell<Option<Signal>>,
}

impl Process {
    #[allow(clippy::too_many_arguments)]
    fn new(
        first_tid: u32,
        parent: Weak<Self>,
        termination_signal: Option<Signal>,
        exe: Link,
        credentials: Credentials,
        cwd: Link,
        process_group: Arc<ProcessGroup>,
        limits: Limits,
        umask: FileMode,
        mm_arg_start: VirtAddr,
        mm_arg_end: VirtAddr,
    ) -> Arc<Self> {
        let file_name = exe.location.file_name().unwrap();
        let task_comm = file_name
            .as_bytes()
            .iter()
            .copied()
            .take(TASK_COMM_CAPACITY)
            .collect();

        let arc = Arc::new_cyclic(|this| Self {
            pid: first_tid,
            start_time: now(ClockId::Monotonic),
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
            real_itimer: Timer::new(
                ClockId::Realtime,
                timer::Event::ITimer {
                    signal: Signal::ALRM,
                },
                this.clone(),
            ),
            timers: Mutex::new(BTreeMap::new()),
            cpu_time: Time::new_in_arc(CpuTimeBackend::default()),
            mm_arg_start: AtomicCell::new(mm_arg_start),
            mm_arg_end: AtomicCell::new(mm_arg_end),
            parent_death_signal: AtomicCell::new(None),
        });

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
        self.parent
            .upgrade()
            .map_or_else(|| if self.pid == 1 { 0 } else { 1 }, |parent| parent.pid())
    }

    pub fn pgrp(&self) -> u32 {
        self.process_group.lock().pgid
    }

    pub fn sid(&self) -> u32 {
        self.process_group.lock().session.lock().sid
    }

    pub fn process_group(&self) -> Arc<ProcessGroup> {
        self.process_group.lock().clone()
    }

    pub fn set_sid(&self) -> u32 {
        let mut process_group_guard = self.process_group.lock();

        // Don't do anything if the process is already the process group leader.
        if process_group_guard.pgid == self.pid {
            return process_group_guard.session().sid;
        }

        // Create a new session and process group.
        *process_group_guard = ProcessGroup::new(self.pid, Arc::new(Session::new(self.pid)));
        self.pid
    }

    pub fn exe(&self) -> Link {
        self.exe.read().clone()
    }

    pub fn task_comm(&self) -> ArrayVec<u8, TASK_COMM_CAPACITY> {
        self.task_comm.lock().clone()
    }

    pub fn cwd(&self) -> Link {
        self.cwd.lock().clone()
    }

    pub fn chdir(&self, cwd: Link) {
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
        fdtable: FileDescriptorTable,
        res: ExecResult,
    ) {
        *self.timers.lock() = BTreeMap::new();
        *self.exe.write() = res.exe;
        self.set_mm_arg_start(res.mm_arg_start);
        self.set_mm_arg_end(res.mm_arg_end);
        let mut threads = self.threads.lock();

        // Restart the thread leader.
        let leader = threads[0].upgrade().unwrap();
        leader.execve(ExecveValues {
            virtual_memory,
            cpu_state: res.cpu_state,
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

        if let Some(termination_signal) = self.termination_signal
            && let Some(parent) = self.parent.upgrade()
        {
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

        if let Some(parent) = self.parent.upgrade() {
            parent.child_death_notify.notify();
        }

        let mut children = core::mem::take(&mut *self.children.lock());
        for child in children.iter() {
            child.queue_parent_death_signal();
        }
        let init_process = INIT_THREAD.process();
        init_process.children.lock().append(&mut children);
        init_process.child_death_notify.notify();
    }

    pub fn thread_group_leader(&self) -> Weak<Thread> {
        self.threads.lock().first().cloned().unwrap_or_default()
    }

    pub async fn exit_status(&self) -> WStatus {
        *self.exit_status.get().await
    }

    pub fn poll_child_death(&self, filter: WaitFilter) -> WaitResult {
        let mut guard = self.children.lock();
        let mut children = guard
            .iter()
            .enumerate()
            .filter(|(_, child)| match filter {
                WaitFilter::Any => true,
                WaitFilter::ExactPid(pid) => child.pid() == pid,
                WaitFilter::ExactPgid(pgid) => child.process_group.lock().pgid == pgid,
            })
            .peekable();

        if children.peek().is_none() {
            return WaitResult::NoChild;
        }

        let opt_idx = children
            .filter(|(_, child)| child.exit_status.try_get().is_some())
            .map(|(i, _)| i)
            .next();

        let Some(idx) = opt_idx else {
            return WaitResult::NotReady;
        };
        let child = guard.swap_remove(idx);

        let rusage = *child.self_usage.lock();
        let mut guard = self.children_usage.lock();
        *guard = guard.merge(rusage);
        drop(guard);

        let wstatus = *child.exit_status.try_get().unwrap();
        WaitResult::Ready {
            pid: child.pid,
            wstatus,
            rusage,
        }
    }

    pub fn queue_signal(&self, sig_info: SigInfo) -> bool {
        match sig_info.signal {
            Signal::CONT | Signal::KILL => self.stop_state.cont(),
            Signal::STOP => self.stop_state.stop(),
            _ => {}
        }

        let added = self.pending_signals.lock().add(sig_info);
        if added {
            self.signals_notify.notify();
        }
        added
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
            tv_sec: i32::try_from(seconds).unwrap_or(i32::MAX),
            tv_nsec: 0,
        });
        let new_state = AlarmState {
            deadline,
            cancel_tx,
        };

        let prev_state = self.alarm.lock().replace(new_state);

        let this = Arc::downgrade(self);
        spawn(async move {
            select_biased! {
                _ = cancel_rx.recv().fuse() => {
                    // The alarm has been cancelled -> do nothing.
                    return;
                }
                _ = sleep_until(deadline, ClockId::Monotonic).fuse() => {}
            }

            // The alarm has fired -> queue a signal.
            let Some(this) = this.upgrade() else {
                return;
            };
            this.queue_signal(SigInfo {
                signal: Signal::ALRM,
                code: SigInfoCode::KERNEL,
                fields: SigFields::None,
            });
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

    pub fn threads(&self) -> Vec<Arc<Thread>> {
        self.threads
            .lock()
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }

    pub fn get_itimer(&self, which: ITimerWhich) -> Result<ITimerval> {
        let timer = match which {
            ITimerWhich::Real => &self.real_itimer,
            ITimerWhich::Virtual => bail!(Inval),
            ITimerWhich::Prof => bail!(Inval),
        };
        Ok(timer.get_time().into())
    }

    pub fn set_itimer(self: &Arc<Self>, which: ITimerWhich, value: ITimerval) -> ITimerval {
        let timer = match which {
            ITimerWhich::Real => &self.real_itimer,
            ITimerWhich::Virtual => todo!(),
            ITimerWhich::Prof => todo!(),
        };
        let old = timer.set_time(value.into(), false);
        old.into()
    }

    pub fn create_timer(self: &Arc<Self>, clock_id: ClockId, sig_event: SigEvent) -> TimerId {
        let mut guard = self.timers.lock();

        // Find a usable timer id.
        let id = (0..)
            .zip(guard.keys().copied())
            .find(|&(i, key)| key.0 != i)
            .map(|(i, _)| i)
            .unwrap_or(guard.len() as i64);
        let id = TimerId(id);

        let event = timer::Event::Timer {
            sig_event,
            timer: id,
        };
        guard.insert(id, Timer::new(clock_id, event, Arc::downgrade(self)));

        id
    }

    pub fn timer_set_time(
        &self,
        timer: TimerId,
        new: ITimerspec,
        absolute: bool,
    ) -> Result<ITimerspec> {
        let mut guard = self.timers.lock();
        let timer = guard.get_mut(&timer).ok_or(err!(Inval))?;
        let old = timer.set_time(new, absolute);
        drop(guard);
        Ok(old)
    }

    pub fn timer_get_time(&self, timer: TimerId) -> Result<ITimerspec> {
        let mut guard = self.timers.lock();
        let timer = guard.get_mut(&timer).ok_or(err!(Inval))?;
        let old = timer.get_time();
        drop(guard);
        Ok(old)
    }

    pub fn timer_delete(&self, timer: TimerId) -> Result<()> {
        // Remove the timer.
        let timer = self.timers.lock().remove(&timer).ok_or(err!(Inval))?;

        // Disarm the timer.
        timer.set_time(
            ITimerspec {
                interval: Timespec::ZERO,
                value: Timespec::ZERO,
            },
            true,
        );

        Ok(())
    }

    pub fn mm_arg_start(&self) -> VirtAddr {
        self.mm_arg_start.load()
    }

    pub fn set_mm_arg_start(&self, addr: VirtAddr) {
        self.mm_arg_start.store(addr);
    }

    pub fn mm_arg_end(&self) -> VirtAddr {
        self.mm_arg_end.load()
    }

    pub fn set_mm_arg_end(&self, addr: VirtAddr) {
        self.mm_arg_end.store(addr);
    }

    pub fn clear_parent_death_signal(&self) {
        self.parent_death_signal.store(None);
    }

    pub fn set_parent_death_signal(&self, signal: Signal) {
        self.parent_death_signal.store(Some(signal));
    }

    pub fn queue_parent_death_signal(&self) {
        let Some(signal) = self.parent_death_signal.load() else {
            return;
        };
        self.queue_signal(SigInfo {
            signal,
            code: SigInfoCode::KERNEL,
            fields: SigFields::None,
        });
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
            "{:indent$}process pid={} pgid={pgid} sid={sid} exit_status={:?} exe={:?}",
            "",
            self.pid,
            self.exit_status.try_get(),
            self.exe().location.path()
        )?;

        if let Some(thread) = self.thread_group_leader().upgrade() {
            writeln!(write, "{:indent$}memory:", "")?;
            if let Some(vm) = thread.try_lock().map(|t| t.virtual_memory().clone()) {
                let maps = vm.maps();
                let maps = String::from_utf8(maps).unwrap();
                for line in maps.lines() {
                    writeln!(write, "{:indent$}  {line}", "")?;
                }
            } else {
                writeln!(write, "{:indent$}  thread is locked", "")?;
            }
        }

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

#[derive(Debug, Clone, Copy)]
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
            now.checked_sub(state.deadline)
                .and_then(|time| u32::try_from(time.tv_sec).ok())
                .unwrap_or_default()
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

pub enum WaitResult {
    Ready {
        pid: u32,
        wstatus: WStatus,
        rusage: Rusage,
    },
    NoChild,
    NotReady,
}

impl WaitResult {
    pub fn or_else(self, f: impl FnOnce() -> Self) -> Self {
        match self {
            WaitResult::Ready { .. } => self,
            WaitResult::NoChild => f(),
            WaitResult::NotReady => match f() {
                other @ WaitResult::Ready { .. } => other,
                WaitResult::NoChild | WaitResult::NotReady => self,
            },
        }
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

    pub fn session(&self) -> Arc<Session> {
        self.session.lock().clone()
    }
}

pub struct Session {
    sid: u32,
    process_groups: Mutex<Vec<Weak<ProcessGroup>>>,
    controlling_terminal: Once<Arc<PtyData>>,
}

impl Session {
    pub fn new(sid: u32) -> Self {
        Self {
            sid,
            process_groups: Mutex::new(Vec::new()),
            controlling_terminal: Once::new(),
        }
    }

    pub fn sid(&self) -> u32 {
        self.sid
    }

    pub fn controlling_terminal(&self) -> Option<Arc<PtyData>> {
        self.controlling_terminal.get().cloned()
    }

    pub fn set_controlling_terminal(&self, tty: &Arc<PtyData>) -> bool {
        self.controlling_terminal.init(|| tty.clone()).is_ok()
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
        true,
    );
    StaticFile::init_file().copy_to(&file).unwrap();
    let location = LinkLocation::new(ROOT_NODE.clone(), FileName::new(b"init").unwrap());
    let link = Link {
        location: location.clone(),
        node: file.clone(),
    };
    let fd = file
        .open(location, OpenFlags::empty(), &FileAccessContext::root())
        .unwrap();

    guard
        .start_executable(
            Path::new(b"/init".to_vec()).unwrap(),
            link,
            &fd,
            &[c"/init"],
            &[] as &[&CStr],
            &mut ctx,
            CurrentStackLimit::default(),
        )
        .unwrap();
    drop(guard);

    thread.clone().spawn();

    thread
});

pub fn start_init_process() {
    INIT_THREAD.process();
}
