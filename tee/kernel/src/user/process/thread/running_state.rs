use alloc::{boxed::Box, sync::Arc};
use core::ops::Not;

use futures::{FutureExt, select_biased};

use super::{Thread, ThreadGuard};
use crate::{
    fs::fd::FileDescriptorTable,
    rt::{notify::Notify, spawn},
    spin::mutex::Mutex,
    user::process::{
        memory::VirtualMemory,
        syscall::{args::WStatus, cpu_state::CpuState},
        thread::PtraceState,
    },
};

enum State {
    /// The thread is still active.
    Running,
    /// The thread is a thread group leader that exited.
    Paused,
    /// The thread has been terminated.
    Terminated,
    /// The thread is about to restart with the given parameters.
    Restart(Box<ExecveValues>),
}

pub struct ThreadRunningState {
    state: Mutex<State>,
    notify: Notify,
}

impl ThreadRunningState {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::Running),
            notify: Notify::new(),
        }
    }

    pub fn is_running(&self) -> bool {
        let guard = self.state.lock();
        matches!(*guard, State::Running)
    }
}

impl ThreadGuard<'_> {
    pub fn exit(&mut self, status: WStatus) {
        let running_state = &self.thread.running_state;
        let mut guard = running_state.state.lock();

        match *guard {
            State::Running => {
                if self.thread.is_thread_group_leader() {
                    *guard = State::Paused;
                } else {
                    *guard = State::Terminated;
                }
                running_state.notify.notify();
                drop(guard);

                self.do_exit();

                self.process().exit(status, self.get_rusage());
            }
            State::Paused => {}
            State::Terminated => {}
            State::Restart(_) => unreachable!(),
        }
    }
}

impl Thread {
    pub fn terminate(self: Arc<Self>, exit_status: WStatus) {
        let running_state = &self.running_state;
        let mut guard = running_state.state.lock();

        match *guard {
            State::Running => {
                *guard = State::Terminated;
                running_state.notify.notify();
                drop(guard);

                spawn(async move {
                    // If there's tracer, send a exit event.
                    let mut guard = self.lock();
                    if let Some(tracer) = guard.tracer.upgrade() {
                        guard.ptrace_state = PtraceState::Exit { reported: false };
                        drop(guard);
                        tracer.ptrace_tracer_notify.notify();
                        drop(tracer);

                        guard = self
                            .ptrace_tracee_notify
                            .wait_until(|| {
                                let guard = self.lock();
                                guard.ptrace_state.is_stopped().not().then_some(guard)
                            })
                            .await;
                    }
                    let rusage = guard.get_rusage();
                    drop(guard);

                    self.process.exit(exit_status, rusage);

                    let mut guard = self.lock();
                    guard.do_exit();
                });
            }
            State::Paused | State::Restart(_) => {
                *guard = State::Terminated;
            }
            State::Terminated => {}
        }
    }

    pub fn execve(&self, params: ExecveValues) {
        let running_state = &self.running_state;
        let mut guard = running_state.state.lock();
        match *guard {
            State::Running => {}
            State::Paused => self.process().restart_thread(),
            State::Terminated => return,
            State::Restart(_) => unreachable!(),
        }
        *guard = State::Restart(Box::new(params));
        running_state.notify.notify();
    }

    pub async fn watch(&self) -> ExitAction<'_> {
        let running_state = &self.running_state;

        let thread_exit = running_state.notify.wait_until(|| {
            let guard = running_state.state.lock();
            match &*guard {
                State::Running => None,
                State::Terminated => Some(ExitAction::Terminate),
                State::Paused | State::Restart(_) => {
                    Some(ExitAction::WaitForExecve(PendingRestartValues {
                        thread: self,
                    }))
                }
            }
        });
        let process_exit = self.process.exit_status();
        select_biased! {
            exit = thread_exit.fuse() => exit,
            _ = process_exit.fuse() => ExitAction::Terminate,
        }
    }
}

pub enum ExitAction<'a> {
    Terminate,
    WaitForExecve(PendingRestartValues<'a>),
}

pub struct PendingRestartValues<'a> {
    thread: &'a Thread,
}

impl PendingRestartValues<'_> {
    pub async fn get(self) -> Option<ExecveValues> {
        let running_state = &self.thread.running_state;

        let thread_exit = running_state.notify.wait_until(|| {
            let guard = self.thread.process.threads.lock();
            if guard[1..]
                .iter()
                .filter_map(|weak| weak.upgrade())
                .any(|thread| thread.running_state.is_running())
            {
                return None;
            }
            drop(guard);

            let mut guard = running_state.state.lock();
            match &*guard {
                State::Terminated => Some(None),
                State::Paused => None,
                State::Restart(_) => {
                    let State::Restart(params) = core::mem::replace(&mut *guard, State::Running)
                    else {
                        unreachable!();
                    };
                    Some(Some(*params))
                }
                State::Running => unreachable!(),
            }
        });
        let process_exit = self.thread.process.exit_status();
        select_biased! {
            exit = thread_exit.fuse() => exit,
            _ = process_exit.fuse() => None,
        }
    }
}

pub struct ExecveValues {
    pub virtual_memory: VirtualMemory,
    pub cpu_state: CpuState,
    pub fdtable: FileDescriptorTable,
}
