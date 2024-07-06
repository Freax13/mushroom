//! We don't expose the real time to userspace, we simulate it.

use crate::spin::{lazy::Lazy, mutex::Mutex};
use alloc::collections::BinaryHeap;
use log::debug;

use crate::{rt::oneshot, user::process::syscall::args::Timespec};

static STATE: Lazy<Mutex<State>> = Lazy::new(|| Mutex::new(State::new()));

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
    timeouts: BinaryHeap<Timeout>,
}

impl State {
    pub fn new() -> Self {
        Self {
            // Start at 1 second.
            clock: 1_000_000_000,
            timeouts: BinaryHeap::new(),
        }
    }

    fn advance(&mut self, ns: u64) {
        self.advance_to(self.clock + ns);
    }

    fn advance_to(&mut self, clock: u64) {
        self.clock = clock;

        while let Some(first) = self.timeouts.peek() {
            if !first.has_expired(clock) {
                break;
            };
            let first = self.timeouts.pop().unwrap();
            first.fire();
        }
    }

    pub fn now(&mut self) -> Timespec {
        self.advance(5000);
        Timespec::from_ns(self.clock)
    }

    fn advance_to_next_timeout(&mut self) -> Result<(), NoTimeoutScheduledError> {
        let timeout = self
            .timeouts
            .iter()
            .find(|t| t.valid())
            .ok_or(NoTimeoutScheduledError)?;
        self.advance_to(timeout.time);
        Ok(())
    }

    fn add_timeout(&mut self, timeout: Timeout) {
        // Immediatly queue expired timeouts.
        if timeout.has_expired(self.clock) {
            timeout.fire();
            return;
        }

        self.timeouts.push(timeout);
    }
}

pub fn now() -> Timespec {
    STATE.lock().now()
}

struct Timeout {
    time: u64,
    sender: oneshot::Sender<()>,
}

impl Timeout {
    fn has_expired(&self, clock: u64) -> bool {
        self.time <= clock
    }

    /// Returns whether firing the timeout will have any effect.
    fn valid(&self) -> bool {
        self.sender.can_send()
    }

    pub fn fire(self) {
        let _ = self.sender.send(());
    }
}

impl PartialEq for Timeout {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
    }
}
impl Eq for Timeout {}

impl PartialOrd for Timeout {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timeout {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.time.cmp(&other.time).reverse()
    }
}

impl Timespec {
    pub fn from_ms(ms: u64) -> Self {
        Self::from_ns(ms * 1_000_000)
    }

    pub fn from_ns(ns: u64) -> Self {
        Timespec {
            tv_sec: u32::try_from(ns / 1_000_000_000).unwrap(),
            tv_nsec: u32::try_from(ns % 1_000_000_000).unwrap(),
        }
    }

    fn into_ns(self) -> u64 {
        u64::from(self.tv_sec) * 1_000_000_000 + u64::from(self.tv_nsec)
    }
}

pub async fn sleep_until(deadline: Timespec) {
    let (sender, receiver) = oneshot::new();

    let mut guard = STATE.lock();
    guard.add_timeout(Timeout {
        time: deadline.into_ns(),
        sender,
    });
    drop(guard);

    receiver.recv().await.unwrap();
}
