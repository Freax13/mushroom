use alloc::{boxed::Box, sync::Arc, task::Wake};
use core::{
    cell::Cell,
    fmt::{self, Debug},
    panic::Location,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use crossbeam_utils::atomic::AtomicCell;
use intrusive_collections::{XorLinkedList, XorLinkedListAtomicLink, intrusive_adapter};
use log::warn;

use crate::{
    exception::TimerInterruptGuard, per_cpu::PerCpu, spin::mutex::Mutex, time, user::schedule_vcpu,
};

pub mod futures_unordered;
pub mod mpmc;
pub mod mpsc;
pub mod notify;
pub mod once;
pub mod oneshot;

static SCHEDULED_THREADS: Mutex<XorLinkedList<TaskAdapter>, TimerInterruptGuard> =
    Mutex::new(XorLinkedList::new(TaskAdapter::NEW));

#[track_caller]
pub fn spawn(future: impl Future<Output = ()> + Send + 'static) {
    Task::new(future).wake()
}

pub fn poll() -> bool {
    let Some(thread) = SCHEDULED_THREADS.lock().pop_front() else {
        return false;
    };
    thread.poll();
    true
}

struct Task {
    link: XorLinkedListAtomicLink,
    state: AtomicCell<TaskState>,
    future: Mutex<Pin<Box<dyn Future<Output = ()> + Send>>>,
    spawn_location: &'static Location<'static>,
}

intrusive_adapter!(TaskAdapter = Arc<Task>: Task { link: XorLinkedListAtomicLink });

impl Task {
    #[track_caller]
    fn new(future: impl Future<Output = ()> + Send + 'static) -> Arc<Self> {
        Arc::new(Self {
            link: XorLinkedListAtomicLink::new(),
            state: AtomicCell::new(TaskState::Waiting),
            future: Mutex::new(Box::pin(future)),
            spawn_location: Location::caller(),
        })
    }

    fn poll(self: &Arc<Self>) {
        let waker = Waker::from(self.clone());
        let mut cx = Context::from_waker(&waker);

        // Scheduled -> Running
        self.state.store(TaskState::Running);

        loop {
            // Run the future.
            let mut guard = self.future.lock();
            let res = guard.as_mut().poll(&mut cx);
            drop(guard);

            // Mark the task as done if the future has finished.
            if res.is_ready() {
                self.state.store(TaskState::Done);
                return;
            }

            // If the thread yielded voluntarily, put it at the end of the queue.
            if PerCpu::get().scheduler_data.yielded.take() {
                self.state.store(TaskState::Scheduled);
                SCHEDULED_THREADS.lock().push_back(self.clone());
                return;
            }

            // Update the task state.
            let res = self.state.fetch_update(|state| match state {
                TaskState::Waiting => None,
                TaskState::Scheduled => None,
                TaskState::Running => Some(TaskState::Waiting),
                TaskState::Rescheduled => Some(TaskState::Running),
                TaskState::Done => None,
            });

            // Check if we should run again.
            let prev_state = match res {
                Ok(prev_state) => prev_state,
                Err(prev_state) => prev_state,
            };
            if prev_state != TaskState::Rescheduled {
                return;
            }
        }
    }
}

impl Wake for Task {
    fn wake(self: Arc<Self>) {
        // Update the state.
        let res = self.state.fetch_update(|state| match state {
            TaskState::Waiting => Some(TaskState::Scheduled),
            TaskState::Scheduled => None,
            TaskState::Running => Some(TaskState::Rescheduled),
            TaskState::Rescheduled => None,
            TaskState::Done => None,
        });
        let Ok(prev_state) = res else {
            // If the state wasn't updated, we also don't need to schedule the task.
            return;
        };

        // Schedule the task if necessary.
        if matches!(prev_state, TaskState::Waiting) {
            SCHEDULED_THREADS.lock().push_back(self);
            schedule_vcpu();
        }
    }
}

impl Debug for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "task spawned at {}", self.spawn_location)
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        let state = self.state.load();
        if state != TaskState::Done {
            warn!("{self:?} never completed")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskState {
    /// The task is waiting to be woken up.
    Waiting,
    /// The task has been woken up and is ready to run.
    Scheduled,
    /// The task is running.
    Running,
    /// The task is running and is already scheduled to be rerun.
    Rescheduled,
    /// The task has finished.
    Done,
}

pub struct SchedulerData {
    yielded: Cell<bool>,
}

impl SchedulerData {
    pub const fn new() -> Self {
        Self {
            yielded: Cell::new(false),
        }
    }
}

pub async fn r#yield() {
    struct Yield {
        polled: bool,
    }

    impl Future for Yield {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.polled {
                return Poll::Ready(());
            }

            // Tell the scheduler that the task wants to yield.
            PerCpu::get().scheduler_data.yielded.set(true);

            // Wake the waker and then yield. Note that this will only work
            // if the `Pending` bubbles all the way up to the scheduler.
            self.polled = true;
            cx.waker().wake_by_ref();

            Poll::Pending
        }
    }

    Yield { polled: false }.await
}

pub struct PreemptionState {
    last_resumed: u64,
}

impl PreemptionState {
    /// The duration after which threads should be preempted.
    const TIME_SLICE: u64 = 25_000_000;

    pub fn new() -> Self {
        Self {
            last_resumed: time::default_backend_offset(),
        }
    }

    pub async fn check(&mut self) {
        // Don't do anything if sufficient time hasn't passed.
        let now = time::default_backend_offset();
        if now - self.last_resumed < Self::TIME_SLICE {
            return;
        }

        // Yield to the scheduler.
        r#yield().await;

        // Record when the thread was resumed.
        self.last_resumed = time::default_backend_offset();
    }
}
