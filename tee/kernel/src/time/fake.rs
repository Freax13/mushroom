//! When this backend is used, we don't expose the real time to userspace, we simulate it.

use core::sync::atomic::AtomicU64;

/// Returns the time current offset in ns.
pub fn current_offset() -> u64 {
    static COUNTER_NS: AtomicU64 = AtomicU64::new(0);
    COUNTER_NS.fetch_add(5000, core::sync::atomic::Ordering::Relaxed)
}
