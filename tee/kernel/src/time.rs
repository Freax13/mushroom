//! We don't expose the real time to userspace, we simulate it.

use alloc::{collections::LinkedList, sync::Weak};
use log::debug;
use spin::Mutex;

use crate::user::process::{syscall::args::Timespec, Process};

static STATE: Mutex<State> = Mutex::new(State::new());
static EXPIRED_TIMEOUTS: Mutex<LinkedList<Timeout>> = Mutex::new(LinkedList::new());

/// Returns true if a timeout was fired.
pub fn fire_expired_timeout() -> bool {
    // Try to pop a expired timeout.
    let mut guard = EXPIRED_TIMEOUTS.lock();
    let Some(timeout) = guard.pop_front() else {
        return false;
    };
    drop(guard);

    // Fire the timeout.
    timeout.fire();

    true
}

pub fn advance_time() -> Result<(), NoTimeoutScheduledError> {
    debug!("advancing simulated time");

    let mut guard = STATE.lock();
    guard.advance_to_next_timeout()
}

#[derive(Debug, Clone, Copy)]
pub struct NoTimeoutScheduledError;

/// The global state of the simulated time.
struct State {
    clock: u64,
    timeouts: LinkedList<Timeout>,
}

impl State {
    pub const fn new() -> Self {
        Self {
            // Start at 1 second.
            clock: 1000,
            timeouts: LinkedList::new(),
        }
    }

    fn advance(&mut self, ms: u64) {
        self.advance_to(self.clock + ms);
    }

    fn advance_to(&mut self, clock: u64) {
        self.clock = clock;

        let mut cursor = self.timeouts.cursor_front_mut();
        // Go forward to the first timeout that has not expired.
        while let Some(current) = cursor.current() {
            if !current.has_expired(self.clock) {
                break;
            }
            cursor.move_next();
        }

        // Split off the chunk that contains timeouts that have expired.
        let mut before = cursor.split_before();
        if before.is_empty() {
            return;
        }

        let mut guard = EXPIRED_TIMEOUTS.lock();
        guard.append(&mut before);
    }

    pub fn now(&mut self) -> Timespec {
        self.advance(1);

        Timespec::from_ms(self.clock)
    }

    fn advance_to_next_timeout(&mut self) -> Result<(), NoTimeoutScheduledError> {
        let timeout = self.timeouts.front().ok_or(NoTimeoutScheduledError)?;
        self.advance_to(timeout.time);
        Ok(())
    }

    fn add_timeout(&mut self, timeout: Timeout) {
        // Immediatly queue expired timeouts.
        if timeout.has_expired(self.clock) {
            let mut guard = EXPIRED_TIMEOUTS.lock();
            guard.push_back(timeout);
            return;
        }

        // Go forward to the first timeout not before `timeout`.
        let mut cursor = self.timeouts.cursor_front_mut();
        while let Some(current) = cursor.current() {
            if current.time >= timeout.time {
                break;
            }
            cursor.move_next();
        }

        cursor.insert_before(timeout);
    }
}

pub fn now() -> Timespec {
    STATE.lock().now()
}

struct Timeout {
    time: u64,
    action: Action,
}

impl Timeout {
    fn has_expired(&self, clock: u64) -> bool {
        self.time <= clock
    }

    pub fn fire(self) {
        let time = Timespec::from_ms(self.time);

        match self.action {
            Action::WakeFutex { process } => {
                let Some(process) = process.upgrade() else {
                    return;
                };

                process.futexes().fire_timeouts(time);
            }
        }
    }
}

enum Action {
    WakeFutex { process: Weak<Process> },
}

impl Timespec {
    fn from_ms(ms: u64) -> Self {
        Timespec {
            tv_sec: ms / 1000,
            tv_nsec: (ms % 1000) * 1_000_000,
        }
    }

    fn into_ms(self) -> u64 {
        self.tv_sec * 1000 + self.tv_nsec / 1_000_000
    }
}

pub fn register_futex_timeout(time: Timespec, process: Weak<Process>) {
    let mut guard = STATE.lock();
    guard.add_timeout(Timeout {
        time: time.into_ms(),
        action: Action::WakeFutex { process },
    });
}
