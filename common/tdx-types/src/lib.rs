#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt;

use bytemuck::{CheckedBitPattern, NoUninit, Zeroable};

pub mod ghci;
pub mod report;
#[cfg(feature = "quote")]
pub mod td_quote;
pub mod tdcall;
pub mod vmexit;

/// A type that transparently wraps another type, but replaces the Debug
/// representation with an emtpy one. The Debug representation for reserved
/// values is not of interest.
#[derive(Clone, Copy, Zeroable)]
#[repr(transparent)]
pub struct Reserved<const SIZE: usize, const MBZ: bool = true>([u8; SIZE]);

impl<const SIZE: usize, const MBZ: bool> Reserved<SIZE, MBZ> {
    pub const ZERO: Self = Self([0; SIZE]);
}

unsafe impl<const SIZE: usize, const MBZ: bool> NoUninit for Reserved<SIZE, MBZ> {}

unsafe impl<const SIZE: usize, const MBZ: bool> CheckedBitPattern for Reserved<SIZE, MBZ> {
    type Bits = [u8; SIZE];

    fn is_valid_bit_pattern(bits: &Self::Bits) -> bool {
        !MBZ || *bits == [0; SIZE]
    }
}

impl<const SIZE: usize, const MBZ: bool> fmt::Debug for Reserved<SIZE, MBZ> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reserved").finish_non_exhaustive()
    }
}

impl<const SIZE: usize, const MBZ: bool> PartialEq for Reserved<SIZE, MBZ> {
    fn eq(&self, other: &Self) -> bool {
        // If we're enforcing that all bytes are `0`, then all instances are
        // always equal.
        if MBZ {
            return true;
        }

        // Otherwise compare the bytes.
        self.0 == other.0
    }
}

impl<const SIZE: usize, const MBZ: bool> Eq for Reserved<SIZE, MBZ> {}

impl<const SIZE: usize, const MBZ: bool> Default for Reserved<SIZE, MBZ> {
    fn default() -> Self {
        Self([0; SIZE])
    }
}
