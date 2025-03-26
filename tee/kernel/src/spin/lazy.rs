use core::ops::Deref;

use super::once::Once;

/// A value that's lazily initialized.
pub struct Lazy<T> {
    init: fn() -> T,
    cell: Once<T>,
}

impl<T> Lazy<T> {
    #[inline]
    pub const fn new(f: fn() -> T) -> Self {
        Self {
            init: f,
            cell: Once::new(),
        }
    }

    /// Force initialization.
    #[inline]
    pub fn force(this: &Self) -> &T {
        this
    }

    /// Get the value without initializing it.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that the value was already initialized.
    #[inline]
    pub unsafe fn get_unchecked(&self) -> &T {
        unsafe { self.cell.get_unchecked() }
    }

    /// Get the value if it's already been initialized.
    #[inline]
    pub fn try_get(&self) -> Option<&T> {
        self.cell.get()
    }
}

impl<T> Deref for Lazy<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.cell.call_once(self.init)
    }
}
