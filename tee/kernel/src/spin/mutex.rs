use core::{
    cell::UnsafeCell,
    num::Wrapping,
    ops::{Deref, DerefMut},
    panic::Location,
    sync::atomic::{AtomicBool, Ordering},
};

use log::warn;

/// A spin locked based mutex to create unique references to shared values.
pub struct Mutex<T> {
    locked: AtomicBool,
    cell: UnsafeCell<T>,
}

impl<T> Mutex<T> {
    #[inline]
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            cell: UnsafeCell::new(value),
        }
    }

    /// Try to acquire the mutex.
    #[inline]
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| MutexGuard { mutex: self })
    }

    /// Acquire the mutex.
    #[inline]
    #[track_caller]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        if let Some(guard) = self.try_lock() {
            return guard;
        }
        self.lock_slow_path()
    }

    #[inline(never)]
    #[cold]
    #[track_caller]
    fn lock_slow_path(&self) -> MutexGuard<'_, T> {
        let mut counter = Wrapping(0u32);
        loop {
            core::hint::spin_loop();

            if let Some(guard) = self.try_lock() {
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

unsafe impl<T> Send for Mutex<T> where T: Send {}
unsafe impl<T> Sync for Mutex<T> where T: Send {}

impl<T> Clone for Mutex<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self::new(self.lock().clone())
    }
}

pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe {
            // SAFETY: The existance of this guard implies that the mutex has
            // been acquired.
            &*self.mutex.cell.get()
        }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            // SAFETY: The existance of this guard implies that the mutex has
            // been acquired.
            &mut *self.mutex.cell.get()
        }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.mutex.locked.store(false, Ordering::Release);
    }
}
