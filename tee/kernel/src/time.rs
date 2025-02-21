use core::cmp;

use crate::{
    error::{Result, bail, err},
    spin::{lazy::Lazy, mutex::Mutex},
    user::process::syscall::args::ClockId,
};
use alloc::collections::{BinaryHeap, binary_heap::PeekMut};
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
    realtime_offset: Timespec,
    monotonic_timeouts: BinaryHeap<Timeout>,
    realtime_timeouts: BinaryHeap<Timeout>,
}

impl State {
    pub fn new() -> Self {
        Self {
            // Start at 1 second.
            backend_offset: 0,
            skip_offset: 1_000_000_000,
            realtime_offset: Timespec::ZERO,
            monotonic_timeouts: BinaryHeap::new(),
            realtime_timeouts: BinaryHeap::new(),
        }
    }

    fn fire_clocks(&mut self) {
        self.fire_monotonic_clocks();
        self.fire_realtime_clocks();
    }

    fn fire_monotonic_clocks(&mut self) {
        let now = self.combine();
        while let Some(first) = self.monotonic_timeouts.peek() {
            if !first.has_expired(now) {
                break;
            };
            let first = self.monotonic_timeouts.pop().unwrap();
            first.fire();
        }
    }

    fn fire_realtime_clocks(&mut self) {
        let now = self.combine();
        let now = self.realtime_offset.into_ns() + now;
        while let Some(first) = self.realtime_timeouts.peek() {
            if !first.has_expired(now) {
                break;
            };
            let first = self.realtime_timeouts.pop().unwrap();
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
        // Calculate the duration to the next timeout relative to the monotonic
        // clock.
        let current = self.combine();
        let next_monotonic_offset = loop {
            let Some(first) = self.monotonic_timeouts.peek_mut() else {
                break None;
            };
            if !first.valid() {
                PeekMut::pop(first);
                continue;
            }
            break Some(first.time.saturating_sub(current));
        };

        // Calculate the duration to the next timeout relative to the realtime
        // clock.
        let current = self.realtime_offset.into_ns() + current;
        let next_realtime_offset = loop {
            let Some(first) = self.realtime_timeouts.peek_mut() else {
                break None;
            };
            if !first.valid() {
                PeekMut::pop(first);
                continue;
            }
            break Some(first.time.saturating_sub(current));
        };

        // Skip to the next timeout.
        let next_offset = [next_monotonic_offset, next_realtime_offset]
            .into_iter()
            .flatten()
            .min()
            .ok_or(NoTimeoutScheduledError)?;
        self.skip_offset += next_offset;

        self.fire_clocks();
        Ok(())
    }

    fn add_timeout(&mut self, timeout: Timeout) {
        // Immediately queue expired timeouts.
        if timeout.has_expired(self.combine()) {
            timeout.fire();
            return;
        }

        self.monotonic_timeouts.push(timeout);
    }

    fn add_realtime_timeout(&mut self, timeout: Timeout) {
        // Immediately queue expired timeouts.
        if timeout.has_expired(self.realtime_offset.into_ns() + self.combine()) {
            timeout.fire();
            return;
        }

        self.realtime_timeouts.push(timeout);
    }

    fn combine(&self) -> u64 {
        self.backend_offset + self.skip_offset
    }

    fn read_clock(&mut self, clock: ClockId) -> Timespec {
        let monotonic = self.refresh();
        match clock {
            ClockId::Realtime => self.realtime_offset + monotonic,
            ClockId::Monotonic => monotonic,
        }
    }

    fn set_real_time(&mut self, time: Timespec) -> Result<()> {
        let now = self.read_clock(ClockId::Monotonic);
        self.realtime_offset = time.checked_sub(now).ok_or(err!(Inval))?;
        self.fire_realtime_clocks();
        Ok(())
    }
}

pub fn now(clock: ClockId) -> Timespec {
    STATE.lock().read_clock(clock)
}

pub fn try_fire_clocks() {
    let Some(mut guard) = STATE.try_lock() else {
        // Some other thread is already using the state. Don't do anything
        // now.
        return;
    };
    guard.fire_clocks();
}

pub fn set(clock: ClockId, time: Timespec) -> Result<()> {
    match clock {
        ClockId::Realtime => STATE.lock().set_real_time(time),
        ClockId::Monotonic => bail!(OpNotSupp),
    }
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

pub async fn sleep_until(deadline: Timespec, clock_id: ClockId) {
    let (sender, receiver) = oneshot::new();
    let timeout = Timeout {
        time: deadline.into_ns(),
        sender,
    };

    let mut guard = STATE.lock();
    match clock_id {
        ClockId::Realtime => guard.add_realtime_timeout(timeout),
        ClockId::Monotonic => guard.add_timeout(timeout),
    }
    drop(guard);

    receiver.recv().await.unwrap();
}

pub fn refresh_backend_offset() -> u64 {
    backend::current_offset()
}
