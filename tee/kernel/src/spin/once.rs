use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    num::Wrapping,
    panic::Location,
    sync::atomic::{AtomicU8, Ordering},
};

use log::warn;

const STATE_UNINITIALIZED: u8 = 0;
const STATE_INITIALIZING: u8 = 1;
const STATE_INITIALIZED: u8 = 2;

/// A value that can be initialized once.
pub struct Once<T> {
    state: AtomicU8,
    cell: UnsafeCell<MaybeUninit<T>>,
}

impl<T> Once<T> {
    #[inline]
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(STATE_UNINITIALIZED),
            cell: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Try to initialize the value.
    ///
    /// `init` will only be called once per `Once<T>` instance.
    #[track_caller]
    pub fn call_once(&self, init: impl FnOnce() -> T) -> &T {
        let mut state = self.state.load(Ordering::Acquire);

        // Check if the value can be initialized.
        if state == STATE_UNINITIALIZED {
            // Start initialization.
            let res = self.state.compare_exchange(
                STATE_UNINITIALIZED,
                STATE_INITIALIZING,
                Ordering::Relaxed,
                Ordering::Acquire,
            );
            match res {
                Ok(_) => {
                    // Initialize the value.
                    let value = init();
                    unsafe {
                        // SAFETY: We just changed the state to
                        // `STATE_INITIALIZING`. This guarantees unique access to
                        // the value.
                        (*self.cell.get()).write(value);
                    }

                    // Finish initialization
                    self.state.store(STATE_INITIALIZED, Ordering::Release);
                    state = STATE_INITIALIZED;
                }
                Err(new_state) => state = new_state,
            }
        }

        // Wait until the value is initalized.
        let mut counter = Wrapping(0u32);
        while state != STATE_INITIALIZED {
            counter += 1;
            if counter.0 == 0 {
                warn!("once stalling at {}", Location::caller());
            }
            core::hint::spin_loop();
            state = self.state.load(Ordering::Acquire);
        }

        unsafe {
            // SAFETY: The value was initialized and no one is allowed unique
            // access.
            (*self.cell.get()).assume_init_ref()
        }
    }

    /// Try to get the value if it was initialized already.
    #[inline]
    pub fn get(&self) -> Option<&T> {
        let state = self.state.load(Ordering::Acquire);
        (state == STATE_INITIALIZED).then(|| unsafe {
            // SAFETY: The value was initialized and no one is allowed unique
            // access.
            (*self.cell.get()).assume_init_ref()
        })
    }

    /// Get the value without initializing it.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that the value was already initialized.
    #[inline]
    pub unsafe fn get_unchecked(&self) -> &T {
        unsafe { (*self.cell.get()).assume_init_ref() }
    }
}

unsafe impl<T> Send for Once<T> where T: Send {}
unsafe impl<T> Sync for Once<T> where T: Send + Sync {}
