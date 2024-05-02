use core::{
    ffi::CStr,
    iter::from_fn,
    sync::atomic::{AtomicUsize, Ordering},
};

use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
    vec::Vec,
};

use crate::{
    error::{err, Result},
    fs::{
        fd::{file::File, FileDescriptorTable},
        node::{procfs::ProcessInos, tmpfs::TmpFsFile, FileAccessContext, INode},
        path::Path,
        INIT,
    },
    rt::{notify::Notify, once::OnceCell},
    spin::{lazy::Lazy, mutex::Mutex},
    supervisor,
    user::process::syscall::args::{ExtractableThreadState, FileMode, OpenFlags},
};

use self::{
    futex::Futexes,
    memory::VirtualMemory,
    syscall::{args::Signal, cpu_state::CpuState},
    thread::{
        new_tid, running_state::ExecveValues, PendingSignals, SigChld, SigFields, SigInfo,
        SigInfoCode, Sigset, Thread, WeakThread,
    },
};

mod exec;
mod futex;
pub mod memory;
pub mod syscall;
pub mod thread;

pub struct Process {
    pid: u32,
    futexes: Arc<Futexes>,
    exit_status: OnceCell<u8>,
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
}

impl Process {
    fn new(first_tid: u32, parent: Weak<Self>, termination_signal: Option<Signal>) -> Arc<Self> {
        let this = Self {
            pid: first_tid,
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
        };
        let arc = Arc::new(this);

        if let Some(parent) = parent.upgrade() {
            parent.children.lock().push(arc.clone());
        }

        arc
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn add_thread(&self, thread: WeakThread) {
        let mut guard = self.threads.lock();
        guard.push(thread);
        self.running.fetch_add(1, Ordering::Relaxed);
    }

    pub fn restart_thread(&self) {
        self.running.fetch_add(1, Ordering::Relaxed);
    }

    pub fn exit(&self, exit_status: u8) {
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
    ) {
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
            thread.terminate(0);
        }
    }

    /// Terminate all threads in the thread group.
    ///
    /// The returned exit status may not be the same as the requested
    /// if another thread terminated the thread group at the same time.
    pub fn exit_group(&self, exit_status: u8) {
        if self.pid == 1 {
            // Commit or fail the output depending on the exit status of the
            // init process.
            if exit_status == 0 {
                supervisor::commit_output();
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
                        status: i32::from(exit_status),
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
        self.threads.lock()[0].clone()
    }

    pub async fn exit_status(&self) -> u8 {
        *self.exit_status.get().await
    }

    pub async fn wait_for_child_death(
        &self,
        pid: Option<u32>,
        no_hang: bool,
    ) -> Result<Option<(u32, u8)>> {
        self.child_death_notify
            .wait_until(|| {
                let mut guard = self.children.lock();
                if guard.is_empty() {
                    return Some(Err(err!(Child)));
                }

                let opt_idx = guard.iter().position(|child| {
                    // If there's a pid, only consider the child with the given pid.
                    if let Some(pid) = pid {
                        if child.pid != pid {
                            return false;
                        }
                    }

                    child.exit_status.try_get().is_some()
                });

                let Some(idx) = opt_idx else {
                    if no_hang {
                        return Some(Ok(None));
                    } else {
                        return None;
                    }
                };
                let child = guard.swap_remove(idx);
                let status = *child.exit_status.try_get().unwrap();
                Some(Ok(Some((child.pid, status))))
            })
            .await
    }

    pub fn queue_signal(&self, sig_info: SigInfo) {
        self.pending_signals.lock().add(sig_info);
        self.signals_notify.notify();
    }

    fn pop_signal(&self, mask: Sigset) -> Option<SigInfo> {
        self.pending_signals.lock().pop(mask)
    }

    pub fn find_by_pid(pid: u32) -> Option<Arc<Self>> {
        Self::all().find(|p| p.pid == pid)
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
}

static INIT_THREAD: Lazy<Arc<Thread>> = Lazy::new(|| {
    let tid = new_tid();
    assert_eq!(tid, 1);
    let thread = Thread::empty(tid);

    let mut guard = thread.lock();
    let mut ctx = FileAccessContext::extract_from_thread(&guard);

    let file = TmpFsFile::new(FileMode::all());
    file.write(0, *INIT).unwrap();
    let path = Path::new(b"/bin/init".to_vec()).unwrap();
    let file = file.open(path.clone(), OpenFlags::empty()).unwrap();

    guard
        .start_executable(&path, &file, &[c"/bin/init"], &[] as &[&CStr], &mut ctx)
        .unwrap();
    drop(guard);

    let thread = Arc::new(thread);
    thread.clone().spawn();

    thread
});

pub fn start_init_process() {
    INIT_THREAD.process();
}
