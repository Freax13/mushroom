//! This crate contains constants shared between the kernel, loader and host executable.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::{marker::PhantomData, ops::RangeInclusive};

use x86_64::{
    structures::paging::{
        frame::PhysFrameRangeInclusive, page::PageRangeInclusive, Page, PhysFrame,
    },
    PhysAddr, VirtAddr,
};

pub const MAX_APS_COUNT: u8 = 32;

pub const FIRST_AP: u8 = 0x80;

pub const EXIT_PORT: u16 = 0xf4;
pub const MEMORY_PORT: u16 = 0x1337;
pub const KICK_AP_PORT: u16 = 0x7331;
pub const SCHEDULE_PORT: u16 = 0x1373;
pub const HALT_PORT: u16 = 0x7313;
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
    use x86_64::{structures::paging::Page, VirtAddr};

    use crate::{check_ranges, PageRange};

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
}
