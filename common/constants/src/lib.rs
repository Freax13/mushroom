//! This crate contains constants and related types shared between the kernel,
//! loader and host executable.
#![cfg_attr(not(test), no_std)]

use core::{
    fmt::{self, Debug, Display},
    marker::PhantomData,
    ops::{BitAnd, BitAndAssign, BitOrAssign, Index, Not, RangeInclusive},
    sync::atomic::{AtomicU32, Ordering},
};

use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{
        Page, PhysFrame, frame::PhysFrameRangeInclusive, page::PageRangeInclusive,
    },
};

pub const MAX_APS_COUNT: u8 = 32;

/// `ApIndex` represents the index of one vCPU thread running the workload
/// kernel. It's maximum value is capped at compile time.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct ApIndex(u8);

impl ApIndex {
    /// Create a new `ApIndex` from an integer.
    ///
    /// # Panics
    ///
    /// This function panics if `idx` exceeds [`MAX_APS_COUNT`].
    #[must_use]
    pub const fn new(idx: u8) -> Self {
        assert!(idx < MAX_APS_COUNT);
        Self(idx)
    }

    /// Create a new `ApIndex` from an integer or return `None` if `idx`
    /// exceeds [`MAX_APS_COUNT`].
    #[must_use]
    pub const fn try_new(idx: u8) -> Option<Self> {
        if idx < MAX_APS_COUNT {
            Some(Self::new(idx))
        } else {
            None
        }
    }

    /// Returns `true` for the first AP that starts running.
    #[must_use]
    pub const fn is_first(&self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

impl Display for ApIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Debug for ApIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl<T> Index<ApIndex> for [T; MAX_APS_COUNT as usize] {
    type Output = T;

    fn index(&self, index: ApIndex) -> &Self::Output {
        unsafe { self.get_unchecked(usize::from(index.as_u8())) }
    }
}

type BitmapType = u32;
type AtomicBitmapType = AtomicU32;

// Make sure that both types are of the same size.
const _: () = assert!(size_of::<BitmapType>() == size_of::<AtomicBitmapType>());

// Make sure that the bitmap type can fit all bits.
const _: () = assert!((MAX_APS_COUNT as usize).div_ceil(8) <= size_of::<BitmapType>());

/// A bitmap containing one bit for every vCPU thread running the workload.
/// Its size is capped by [`MAX_APS_COUNT`] at compile-time.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct ApBitmap(BitmapType);

impl ApBitmap {
    /// Create a new bitmap with all bits set to `false`.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create a new bitmap with all bits set to `true`.
    #[must_use]
    pub const fn all() -> Self {
        let mut bits = 0;
        let mut i = 0;
        while i < MAX_APS_COUNT {
            bits |= 1 << i;
            i += 1;
        }
        Self(bits)
    }

    /// Returns the bit for the given AP.
    #[must_use]
    pub const fn get(&self, idx: ApIndex) -> bool {
        self.0 & (1 << idx.0) != 0
    }

    /// Sets the bit for the given AP.
    #[cfg(feature = "nightly")] // TODO: Remove this when Rust 1.83 is released.
    pub const fn set(&mut self, idx: ApIndex, value: bool) {
        if value {
            self.0 |= 1 << idx.0;
        } else {
            self.0 &= !(1 << idx.0);
        }
    }

    /// Sets the bit for the given AP.
    #[cfg(not(feature = "nightly"))] // TODO: Remove this when Rust 1.83 is released.
    pub fn set(&mut self, idx: ApIndex, value: bool) {
        if value {
            self.0 |= 1 << idx.0;
        } else {
            self.0 &= !(1 << idx.0);
        }
    }

    /// Returns whether all bits are `false`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Returns the index of the first AP whose bit is not set.
    #[must_use]
    pub fn first_unset(&self) -> Option<ApIndex> {
        let idx = self.0.trailing_ones() as u8;
        ApIndex::try_new(idx)
    }
}

impl BitOrAssign for ApBitmap {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for ApBitmap {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for ApBitmap {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl Not for ApBitmap {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(!self.0) & Self::all()
    }
}

impl IntoIterator for ApBitmap {
    type Item = ApIndex;
    type IntoIter = ApBitmapIter;

    /// Returns the indicies of all APs whose bit is `true`.
    fn into_iter(self) -> Self::IntoIter {
        ApBitmapIter(self)
    }
}

/// Returns the indicies of all APs whose bit is `true`.
pub struct ApBitmapIter(ApBitmap);

impl Iterator for ApBitmapIter {
    type Item = ApIndex;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.0.0.trailing_zeros();
        let idx = ApIndex::try_new(idx as u8)?;
        self.0.set(idx, false);
        Some(idx)
    }
}

impl Debug for ApBitmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(*self).finish()
    }
}

/// The atomic equivalent of [`ApBitmap`].
#[repr(transparent)]
pub struct AtomicApBitmap(AtomicBitmapType);

impl AtomicApBitmap {
    /// Create a new bitmap with all bits set to `false`.
    pub const fn empty() -> Self {
        Self::new(ApBitmap::empty())
    }

    pub const fn new(value: ApBitmap) -> Self {
        Self(AtomicBitmapType::new(value.0))
    }

    /// Returns the bit for the given AP.
    pub fn get(&self, idx: ApIndex) -> bool {
        self.0.load(Ordering::SeqCst) & (1 << idx.0) != 0
    }

    /// Returns a copy of all bits.
    pub fn get_all(&self) -> ApBitmap {
        ApBitmap(self.0.load(Ordering::SeqCst))
    }

    /// Sets the bit for the given AP to `true`.
    pub fn set(&self, idx: ApIndex) -> bool {
        let mask = 1 << idx.0;
        self.0.fetch_or(mask, Ordering::SeqCst) & mask != 0
    }

    /// Sets the bits for the given APs to `true`.
    pub fn set_all(&self, aps: ApBitmap) {
        self.0.fetch_or(aps.0, Ordering::SeqCst);
    }

    pub fn set_exact(&self, aps: ApBitmap) {
        self.0.store(aps.0, Ordering::SeqCst);
    }

    /// Atomically clear the bit for the given AP and return its value.
    pub fn take(&self, idx: ApIndex) -> bool {
        let mask = 1 << idx.0;
        self.0.fetch_and(!mask, Ordering::SeqCst) & mask != 0
    }

    /// Atomically clears the bits for all APs and return their values.
    pub fn take_all(&self) -> ApBitmap {
        ApBitmap(self.0.swap(0, Ordering::SeqCst))
    }
}

pub const FIRST_AP: u8 = 0x80;

pub const EXIT_PORT: u16 = 0xf4;
pub const MEMORY_PORT: u16 = 0x1337;
pub const KICK_AP_PORT: u16 = 0x7331;
pub const SCHEDULE_PORT: u16 = 0x1373;
pub const HALT_PORT: u16 = 0x7313;
pub const INSECURE_SUPERVISOR_CALL_PORT: u16 = 0x17;
pub const MEMORY_MSR: u32 = 0x7000_0000;
pub const UPDATE_OUTPUT_MSR: u32 = 0x7000_0001;
pub const FINISH_OUTPUT_MSR: u32 = 0x7000_0002;

pub mod physical_address;

#[derive(Clone)]
pub struct PageRange<T> {
    start_addr: u64,
    end_inclusive_addr: u64,
    _marker: PhantomData<T>,
}

impl<T> PageRange<T> {
    pub const fn new(a: RangeInclusive<u64>) -> Self {
        let start_addr = *a.start();
        let end_inclusive_addr = *a.end();
        assert!(
            start_addr & 0xfff == 0,
            "start address is not at the start of a page"
        );
        assert!(
            end_inclusive_addr & 0xfff == 0xfff,
            "end address is not at the end of a page"
        );
        assert!(
            start_addr <= end_inclusive_addr,
            "end address must be behind start address"
        );
        Self {
            start_addr,
            end_inclusive_addr,
            _marker: PhantomData,
        }
    }

    pub const fn start(&self) -> u64 {
        self.start_addr
    }

    pub const fn end_inclusive(&self) -> u64 {
        self.end_inclusive_addr
    }

    pub fn contains(&self, addr: u64) -> bool {
        (self.start()..=self.end_inclusive()).contains(&addr)
    }

    pub const fn size(&self) -> u64 {
        match self.end_inclusive_addr.checked_sub(self.start_addr) {
            Some(diff) => diff + 1,
            None => 0,
        }
    }
}

impl IntoIterator for PageRange<Page> {
    type Item = Page;
    type IntoIter = PageRangeInclusive;

    fn into_iter(self) -> Self::IntoIter {
        let start = Page::containing_address(VirtAddr::new(self.start_addr));
        let end = Page::containing_address(VirtAddr::new(self.end_inclusive_addr));
        Page::range_inclusive(start, end)
    }
}

impl IntoIterator for PageRange<PhysFrame> {
    type Item = PhysFrame;
    type IntoIter = PhysFrameRangeInclusive;

    fn into_iter(self) -> Self::IntoIter {
        let start = PhysFrame::containing_address(PhysAddr::new(self.start_addr));
        let end = PhysFrame::containing_address(PhysAddr::new(self.end_inclusive_addr));
        PhysFrame::range_inclusive(start, end)
    }
}

// Irq vectors used in the kernel.
pub const TIMER_VECTOR: u8 = 0x20;
pub const TLB_VECTOR: u8 = 0x30;

#[cfg(test)]
fn check_ranges<T>(ranges: &[PageRange<T>])
where
    T: PartialEq,
{
    for (i, range_a) in ranges.iter().enumerate() {
        for range_b in ranges[..i].iter() {
            let r_a = range_a.start_addr..=range_a.end_inclusive_addr;
            assert!(!r_a.contains(&range_b.start_addr));
            assert!(!r_a.contains(&range_b.end_inclusive_addr));

            let r_b = range_b.start_addr..=range_b.end_inclusive_addr;
            assert!(!r_b.contains(&range_a.start_addr));
            assert!(!r_b.contains(&range_a.end_inclusive_addr));
        }
    }
}

#[cfg(test)]
mod tests {
    use x86_64::{VirtAddr, structures::paging::Page};

    use crate::{ApBitmap, MAX_APS_COUNT, PageRange, check_ranges};

    #[test]
    fn test_address_range() {
        let mut range = PageRange::<Page>::new(0x1000..=0x3fff).into_iter();
        assert_eq!(
            range.next(),
            Some(Page::containing_address(VirtAddr::new(0x1000)))
        );
        assert_eq!(
            range.next(),
            Some(Page::containing_address(VirtAddr::new(0x2000)))
        );
        assert_eq!(
            range.next(),
            Some(Page::containing_address(VirtAddr::new(0x3000)))
        );
        assert_eq!(range.next(), None);
    }

    #[test]
    fn test_valid_range() {
        PageRange::<Page>::new(0x1000..=0x1fff);
    }

    #[test]
    #[should_panic]
    fn test_bad_range_start() {
        check_ranges(&[PageRange::<Page>::new(0x1001..=0x1fff)])
    }

    #[test]
    #[should_panic]
    fn test_bad_range_end() {
        check_ranges(&[PageRange::<Page>::new(0x1000..=0x1ffe)])
    }

    #[test]
    #[should_panic]
    fn test_bad_range() {
        check_ranges(&[PageRange::<Page>::new(0x1000..=0xfff)])
    }

    #[test]
    #[should_panic]
    fn test_invalid_ranges() {
        check_ranges(&[
            PageRange::<Page>::new(0x1000..=0x3fff),
            PageRange::<Page>::new(0x2000..=0x2fff),
        ])
    }

    #[test]
    fn test_bitmap_range() {
        let bitmap = ApBitmap::all();
        let iter = bitmap.into_iter();
        for (i, idx) in iter.enumerate() {
            assert_eq!(i, usize::from(idx.as_u8()));
        }
        assert_eq!(bitmap.into_iter().count(), usize::from(MAX_APS_COUNT));
    }
}
