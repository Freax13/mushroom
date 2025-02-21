use core::{
    iter::Step,
    ops::{Index, IndexMut, RangeInclusive},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LimitedIndex<const N: usize>(u16);

impl<const N: usize> LimitedIndex<N> {
    pub const MIN: Self = Self::new(0);
    pub const MAX: Self = Self::new(N - 1);
    pub const ALL: RangeInclusive<Self> = Self::MIN..=Self::MAX;

    #[inline(always)]
    pub const fn new(idx: usize) -> Self {
        assert!(N <= u16::MAX as usize);

        assert!(idx < N);
        Self(idx as u16)
    }

    #[inline(always)]
    pub const fn try_new(idx: usize) -> Option<Self> {
        if idx < N {
            Some(Self(idx as u16))
        } else {
            None
        }
    }

    #[inline(always)]
    pub const fn get(&self) -> usize {
        self.0 as usize
    }
}

impl<const N: usize> Step for LimitedIndex<N> {
    #[inline(always)]
    fn steps_between(start: &Self, end: &Self) -> (usize, Option<usize>) {
        Step::steps_between(&start.0, &end.0)
    }

    #[inline(always)]
    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        let idx = start.get().checked_add(count)?;
        if idx < N { Some(Self::new(idx)) } else { None }
    }

    #[inline(always)]
    unsafe fn forward_unchecked(start: Self, count: usize) -> Self {
        Self(start.0.wrapping_add(count as u16))
    }

    #[inline(always)]
    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        let idx = start.get().checked_sub(count)?;
        Some(Self::new(idx))
    }

    #[inline(always)]
    unsafe fn backward_unchecked(start: Self, count: usize) -> Self {
        Self(start.0.wrapping_sub(count as u16))
    }
}

impl<T, const N: usize> Index<LimitedIndex<N>> for [T; N] {
    type Output = T;

    fn index(&self, index: LimitedIndex<N>) -> &Self::Output {
        unsafe {
            // SAFETY: `index.get()` is always less than `N`.
            self.get_unchecked(index.get())
        }
    }
}

impl<T, const N: usize> IndexMut<LimitedIndex<N>> for [T; N] {
    fn index_mut(&mut self, index: LimitedIndex<N>) -> &mut Self::Output {
        unsafe {
            // SAFETY: `index.get()` is always less than `N`.
            self.get_unchecked_mut(index.get())
        }
    }
}
