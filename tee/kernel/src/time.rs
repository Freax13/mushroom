use core::cmp;

use crate::spin::{lazy::Lazy, mutex::Mutex};
use alloc::collections::BinaryHeap;
use log::debug;

use crate::{rt::oneshot, user::process::syscall::args::Timespec};

#[cfg(all(feature = "fake-time", feature = "real-time"))]
compile_error!("the fake-time and real-time features are both enabled");
#[cfg(not(any(feature = "fake-time", feature = "real-time")))]
compile_error!("neither the fake-time nor real-time features are enabled");

#[cfg(feature = "fake-time")]
mod fake;
#[cfg(feature = "fake-time")]
use fake as backend;
#[cfg(feature = "real-time")]
mod real;
#[cfg(feature = "real-time")]
use real as backend;

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
    backend_offset: u64,
    skip_offset: u64,
    timeouts: BinaryHeap<Timeout>,
}

impl State {
    pub fn new() -> Self {
        Self {
            // Start at 1 second.
            backend_offset: 0,
            skip_offset: 1_000_000_000,
            timeouts: BinaryHeap::new(),
        }
    }

    fn fire_clocks(&mut self) {
        let now = self.combine();
        while let Some(first) = self.timeouts.peek() {
            if !first.has_expired(now) {
                break;
            };
            let first = self.timeouts.pop().unwrap();
            first.fire();
        }
    }

    pub fn refresh(&mut self) -> Timespec {
        let new_backend_offset = backend::current_offset();
        self.backend_offset = cmp::max(self.backend_offset, new_backend_offset);
        self.fire_clocks();

        Timespec::from_ns(self.combine())
    }

    fn advance_to_next_timeout(&mut self) -> Result<(), NoTimeoutScheduledError> {
        let timeout = self
            .timeouts
            .iter()
            .find(|t| t.valid())
            .ok_or(NoTimeoutScheduledError)?;
        let current = self.combine();
        self.skip_offset += timeout.time.saturating_sub(current);
        self.fire_clocks();
        Ok(())
    }

    fn add_timeout(&mut self, timeout: Timeout) {
        // Immediatly queue expired timeouts.
        if timeout.has_expired(self.combine()) {
            timeout.fire();
            return;
        }

        self.timeouts.push(timeout);
    }

    fn combine(&self) -> u64 {
        self.backend_offset + self.skip_offset
    }
}

pub fn now() -> Timespec {
    STATE.lock().refresh()
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
