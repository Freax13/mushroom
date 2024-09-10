use core::{
    cell::UnsafeCell,
    num::Wrapping,
    ops::{Deref, DerefMut},
    panic::Location,
    sync::atomic::{AtomicI64, Ordering},
};

use log::warn;

const RELOAD_LIMIT: i64 = i64::MIN / 2;

/// A spin locked based read-write mutex to create unique references to shared values.
pub struct RwLock<T> {
    cell: UnsafeCell<T>,
    ///  0 -> Unlocked
    /// \>0 -> Read-locked
    /// <0 -> Write-locked
    state: AtomicI64,
}

impl<T> RwLock<T> {
    /// Wrap a value.
    pub const fn new(value: T) -> Self {
        Self {
            cell: UnsafeCell::new(value),
            state: AtomicI64::new(0),
        }
    }

    /// Try to acquire the lock for a read guard without spinnning.
    #[inline]
    pub fn try_read(&self) -> Option<ReadRwLockGuard<T>> {
        // fetch_add is faster than compare_exchange, so we optimistically add
        // 1 to the state to registers a read guard. This will obviously behave
        // correctly if the lock is not taken or taken by other read guards.
        // When the lock is taken by a write-guard, it sets `state` to a really
        // large negative value so that even if we repeatedly add 1, it will
        // remain negative. Even though it's very unlikely that the lock will
        // be taken for so long that `state` eventually becomes positive, we
        // still try to prevent that by "reloading" `state` once it's no longer
        // sufficiently large. We "reload" `state` by reinitializing `state` to
        // a large negative number with a compare-exchange loop. That way we
        // can avoid a compare-exchange loop for the fast majority of attempts,
        // but still avoid bugs.
        let value = self.state.fetch_add(1, Ordering::Relaxed);
        match value {
            0.. => Some(ReadRwLockGuard { lock: self }),
            ..=RELOAD_LIMIT => {
                self.reload();
                None
            }
            _ => None,
        }
    }

    #[inline(never)]
    #[cold]
    fn reload(&self) {
        let mut value = self.state.load(Ordering::Relaxed);
        loop {
            core::hint::spin_loop();

            match value {
                0.. => break,
                ..=RELOAD_LIMIT => {
                    let res = self.state.compare_exchange(
                        value,
                        i64::MIN,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                    match res {
                        Ok(_) => break,
                        Err(new_value) => value = new_value,
                    }
                }
                _ => break,
            }
        }
    }

    /// Acquire the lock for a read guard.
    #[inline]
    #[track_caller]
    pub fn read(&self) -> ReadRwLockGuard<T> {
        if let Some(guard) = self.try_read() {
            return guard;
        }
        self.read_slow_path()
    }

    #[inline(never)]
    #[cold]
    #[track_caller]
    fn read_slow_path(&self) -> ReadRwLockGuard<'_, T> {
        let mut counter = Wrapping(0u32);
        loop {
            core::hint::spin_loop();

            if let Some(guard) = self.try_read() {
                return guard;
            }
            counter += 1;
            if counter.0 == 0 {
                warn!("lock stalling at {}", Location::caller());
            }
        }
    }

    /// Try to acquire the lock for a write guard without spinnning.
    #[inline]
    pub fn try_write(&self) -> Option<WriteRwLockGuard<T>> {
        self.state
            .compare_exchange(0, i64::MIN, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| WriteRwLockGuard { lock: self })
    }

    /// Acquire the lock for a write guard.
    #[inline]
    #[track_caller]
    pub fn write(&self) -> WriteRwLockGuard<T> {
        if let Some(guard) = self.try_write() {
            return guard;
        }
        self.write_slow_path()
    }

    #[inline(never)]
    #[cold]
    #[track_caller]
    fn write_slow_path(&self) -> WriteRwLockGuard<'_, T> {
        let mut counter = Wrapping(0u32);
        loop {
            core::hint::spin_loop();

            if let Some(guard) = self.try_write() {
                return guard;
            }
            counter += 1;
            if counter.0 == 0 {
                warn!("lock stalling at {}", Location::caller());
            }
        }
    }

    /// Get a mutable reference to the contained value.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.cell.get_mut()
    }
}

unsafe impl<T> Send for RwLock<T> where T: Send {}
unsafe impl<T> Sync for RwLock<T> where T: Send + Sync {}

pub struct ReadRwLockGuard<'a, T> {
    lock: &'a RwLock<T>,
}

impl<T> Deref for ReadRwLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.cell.get() }
    }
}

impl<T> Drop for ReadRwLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.state.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct WriteRwLockGuard<'a, T> {
    lock: &'a RwLock<T>,
}

impl<T> Deref for WriteRwLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.cell.get() }
    }
}

impl<T> DerefMut for WriteRwLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.cell.get() }
    }
}

impl<T> Drop for WriteRwLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.state.store(0, Ordering::Release);
    }
}
