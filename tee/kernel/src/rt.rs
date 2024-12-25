use core::{
    fmt::{self, Debug},
    future::Future,
    panic::Location,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use crate::{spin::mutex::Mutex, user::schedule_vcpu};
use alloc::{boxed::Box, sync::Arc, task::Wake};
use crossbeam_queue::SegQueue;
use crossbeam_utils::atomic::AtomicCell;
use log::warn;

pub mod mpmc;
pub mod mpsc;
pub mod notify;
pub mod once;
pub mod oneshot;

static SCHEDULED_THREADS: SegQueue<Arc<Task>> = SegQueue::new();

#[track_caller]
pub fn spawn(future: impl Future<Output = ()> + Send + 'static) {
    Task::new(future).wake()
}

pub fn poll() -> bool {
    let Some(thread) = SCHEDULED_THREADS.pop() else {
        return false;
    };
    thread.poll();
    true
}

struct Task {
    state: AtomicCell<TaskState>,
    future: Mutex<Pin<Box<dyn Future<Output = ()> + Send>>>,
    spawn_location: &'static Location<'static>,
}

impl Task {
    #[track_caller]
    fn new(future: impl Future<Output = ()> + Send + 'static) -> Arc<Self> {
        Arc::new(Self {
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
            SCHEDULED_THREADS.push(self);
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

pub async fn r#yield() {
    struct Yield {
        polled: bool,
    }

    impl Future for Yield {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.polled {
                Poll::Ready(())
            } else {
                self.polled = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    Yield { polled: false }.await
}
