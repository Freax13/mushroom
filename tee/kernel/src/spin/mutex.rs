use core::{
    cell::UnsafeCell,
    cmp,
    marker::PhantomData,
    num::Wrapping,
    ops::{Deref, DerefMut},
    panic::Location,
    sync::atomic::{AtomicBool, Ordering},
};

use log::warn;

use crate::exception::{InterruptGuard, NoInterruptGuard};

/// A spin locked based mutex to create unique references to shared values.
pub struct Mutex<T, I = NoInterruptGuard> {
    locked: AtomicBool,
    cell: UnsafeCell<T>,
    _marker: PhantomData<I>,
}

impl<T, I> Mutex<T, I> {
    #[inline]
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            cell: UnsafeCell::new(value),
            _marker: PhantomData,
        }
    }

    /// Try to acquire the mutex.
    #[inline]
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T, I>>
    where
        I: InterruptGuard,
    {
        let interrupt_guard = I::new();

        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| MutexGuard {
                mutex: self,
                _interrupt_guard: interrupt_guard,
            })
    }

    /// Acquire the mutex.
    #[inline]
    #[track_caller]
    pub fn lock(&self) -> MutexGuard<'_, T, I>
    where
        I: InterruptGuard,
    {
        if let Some(guard) = self.try_lock() {
            return guard;
        }
        self.lock_slow_path()
    }

    #[inline(never)]
    #[cold]
    #[track_caller]
    fn lock_slow_path(&self) -> MutexGuard<'_, T, I>
    where
        I: InterruptGuard,
    {
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

    /// Lock two mutexes. This method avoids deadlocks with other threads
    /// trying to acquire the same Mutexes.
    #[track_caller]
    pub fn lock_two<'a>(&'a self, other: &'a Self) -> (MutexGuard<'a, T, I>, MutexGuard<'a, T, I>)
    where
        I: InterruptGuard,
    {
        // Compare the pointers of the mutexes to get a determinstic ordering.
        let self_ptr = self as *const Self;
        let other_ptr = other as *const Self;
        let cmp = self_ptr.cmp(&other_ptr);

        // Lock the mutex with the lower address first.
        match cmp {
            cmp::Ordering::Less => loop {
                let self_guard = self.lock();
                let Some(other_guard) = other.try_lock() else {
                    continue;
                };
                return (self_guard, other_guard);
            },
            cmp::Ordering::Equal => panic!("can't lock the same Mutex twice"),
            cmp::Ordering::Greater => loop {
                let other_guard = other.lock();
                let Some(self_guard) = self.try_lock() else {
                    continue;
                };
                return (self_guard, other_guard);
            },
        }
    }

    pub fn into_inner(self) -> T {
        self.cell.into_inner()
    }
}

unsafe impl<T, I> Send for Mutex<T, I> where T: Send {}
unsafe impl<T, I> Sync for Mutex<T, I> where T: Send {}

impl<T, I> Clone for Mutex<T, I>
where
    T: Clone,
    I: InterruptGuard,
{
    fn clone(&self) -> Self {
        Self::new(self.lock().clone())
    }
}

impl<T, I> Default for Mutex<T, I>
where
    T: Default,
{
    fn default() -> Self {
        Self::new(T::default())
    }
}

pub struct MutexGuard<'a, T, I = NoInterruptGuard> {
    mutex: &'a Mutex<T, I>,
    _interrupt_guard: I,
}

impl<T, I> Deref for MutexGuard<'_, T, I> {
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

impl<T, I> DerefMut for MutexGuard<'_, T, I> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            // SAFETY: The existance of this guard implies that the mutex has
            // been acquired.
            &mut *self.mutex.cell.get()
        }
    }
}

impl<T, I> Drop for MutexGuard<'_, T, I> {
    #[inline]
    fn drop(&mut self) {
        self.mutex.locked.store(false, Ordering::Release);
    }
}
