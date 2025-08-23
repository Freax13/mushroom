use core::sync::atomic::{AtomicU64, Ordering};

use usize_conversions::FromUsize;

use super::syscall::args::{Rusage, Timespec, Timeval};
use crate::time::default_backend_offset;

#[derive(Default)]
pub struct MemoryUsage {
    maxrss: AtomicU64,
    minflt: AtomicU64,
    majflt: AtomicU64,
    rss: AtomicU64,
}

impl MemoryUsage {
    pub fn fork(&self) -> Self {
        let rss = self.rss.load(Ordering::Relaxed);
        Self {
            maxrss: AtomicU64::new(rss),
            minflt: AtomicU64::new(0),
            majflt: AtomicU64::new(0),
            rss: AtomicU64::new(rss),
        }
    }

    pub fn record_minor_page_fault(&self) {
        self.minflt.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_major_page_fault(&self) {
        self.majflt.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increase_rss(&self) {
        let prev = self.rss.fetch_add(1, Ordering::Relaxed);
        self.maxrss.fetch_max(prev + 1, Ordering::Relaxed);
    }

    pub fn decrease_rss(&self, delta: usize) {
        self.rss
            .fetch_sub(u64::from_usize(delta), Ordering::Relaxed);
    }

    pub fn rss(&self) -> u64 {
        self.rss.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
pub struct ThreadUsage {
    /// The last time a task started executing or 0 if the thread is not
    /// currently running. Any time from then until now should be added on top
    /// of total.
    last_start: AtomicU64,
    total_ns: AtomicU64,
    user_ns: AtomicU64,
    voluntary_context_switches: AtomicU64,
}

const UPDATING: u64 = 1 << 63;

impl ThreadUsage {
    pub fn start(&self, start: u64) {
        self.last_start.store(start, Ordering::Relaxed);
    }

    pub fn stop(&self, end: u64) {
        let start = self.last_start.load(Ordering::SeqCst);
        self.total_ns
            .fetch_add(UPDATING | (end - start), Ordering::SeqCst);
        self.last_start.store(0, Ordering::SeqCst);
        self.total_ns.fetch_and(!UPDATING, Ordering::SeqCst);
    }

    pub fn record_user_execution_time(&self, delta_t: u64) {
        self.user_ns.fetch_add(delta_t, Ordering::Relaxed);
    }

    pub fn record_voluntary_context_switch(&self) {
        self.voluntary_context_switches
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn cpu_time(&self) -> u64 {
        self.user_ns.load(Ordering::Relaxed)
    }
}

pub fn collect(memory: &MemoryUsage, thread: &ThreadUsage) -> Rusage {
    let user_ns = thread.user_ns.load(Ordering::Relaxed);
    let mut total_ns = thread.total_ns.load(Ordering::Relaxed);

    let last_start = thread.last_start.load(Ordering::Relaxed);
    if total_ns & UPDATING != 0 {
        total_ns &= !UPDATING;
    } else if last_start != 0 {
        total_ns += default_backend_offset().saturating_sub(last_start);
    }

    let sys_time = total_ns - user_ns;
    let utime = Timeval::from(Timespec::from_ns(user_ns as i64));
    let stime = Timeval::from(Timespec::from_ns(sys_time as i64));
    let maxrss = memory.maxrss.load(Ordering::Relaxed) * 0x1000;
    let majflt = memory.majflt.load(Ordering::Relaxed);
    let minflt = memory.minflt.load(Ordering::Relaxed) - majflt;
    let nvcsw = thread.voluntary_context_switches.load(Ordering::Relaxed);
    Rusage {
        utime,
        stime,
        maxrss,
        minflt,
        majflt,
        nvcsw,
        ..Rusage::default()
    }
}
