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
}

impl<T> Deref for Lazy<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.cell.call_once(self.init)
    }
}
