//! When this backend is used, we don't expose the real time to userspace, we simulate it.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::time::TimeBackend;

pub struct FakeBackend {
    counter_ns: AtomicU64,
}

impl FakeBackend {
    pub const fn new() -> Self {
        Self {
            counter_ns: AtomicU64::new(0),
        }
    }

    pub fn skip(&self, offset: u64) {
        self.counter_ns.fetch_add(offset, Ordering::Relaxed);
    }
}

impl TimeBackend for FakeBackend {
    fn current_offset(&self) -> u64 {
        self.counter_ns.fetch_add(5000, Ordering::Relaxed)
    }
}
