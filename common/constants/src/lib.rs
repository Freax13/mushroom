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

/// The alignment of the TLS segment.
pub const TLS_ALIGN: usize = 8;

pub const MAX_APS_COUNT: u8 = 128;

pub const PAGE_TABLE_WITH_RESET_VECTOR: u64 = 0;
pub const PAGE_TABLE_WITHOUT_RESET_VECTOR: u64 = 0x1000;

pub const FIRST_AP: u8 = 0x80;

pub const EXIT_PORT: u16 = 0xf4;
pub const LOG_PORT: u16 = 0x3f8;
pub const MEMORY_PORT: u16 = 0x1337;
pub const KICK_AP_PORT: u16 = 0x7331;
pub const SCHEDULE_PORT: u16 = 0x1373;
pub const HALT_PORT: u16 = 0x7313;
pub const MEMORY_MSR: u32 = 0x4000_0000;

macro_rules! address {
    ($(#[$meta:meta])* const $ident:ident = $start:literal;) => {
        $(#[$meta])*
        pub const $ident: PageRange = PageRange::new($start..=$start + 0xfff);
    };
    ($(#[$meta:meta])* const $ident:ident = $start:literal ..=$end:literal;) => {
        $(#[$meta])*
        pub const $ident: PageRange = PageRange::new($start..=$end);
    };
    ($(#[$meta:meta])* const $ident:ident = $start:literal @ $size:expr;) => {
        $(#[$meta])*
        pub const $ident: PageRange = PageRange::new($start..=$start + ($size - 1));
    };
    ($(#[$meta:meta])* const $ident:ident = $start:literal $(..=$end:literal)? $(@$size:expr)?;) => {
        compiler_error!("Must not specify end and size");
    };
}

macro_rules! addresses {
    ($($(#[$meta:meta])* const $ident:ident = $start:literal $(..=$end:literal)? $(@$size:expr)?;)*) => {
        $(
            address!{ $(#[$meta])* const $ident = $start $(..=$end)? $(@$size)?; }
        )*

        #[cfg(test)]
        #[test]
        fn test_ranges() {
            crate::check_ranges(&[
                $(
                    $(#[$meta])* $ident,
                )*
            ]);
        }
    };
}

pub mod virtual_address {
    use x86_64::structures::paging::Page;

    type PageRange = crate::PageRange<Page>;

    addresses! {
        const KERNEL = 0xffff_8000_0000_0000..=0xffff_8000_ffff_ffff;
        const HEAP = 0xffff_c000_0000_0000..=0xffff_cfff_ffff_ffff;
        const TEMPORARY = 0xffff_d000_0000_0000..=0xffff_dfff_ffff_ffff;
        const INIT = 0xffff_e000_0000_0000..=0xffff_e0ff_ffff_ffff;
        const INPUT = 0xffff_f000_0000_0000..=0xffff_f0ff_ffff_ffff;
    }
}

pub mod physical_address {
    use x86_64::structures::paging::PhysFrame;

    type PageRange = crate::PageRange<PhysFrame>;

    addresses! {
        // 64 gibibytes of dynamic physical memory that can be grown and shrunk.
        const DYNAMIC = 0x0000_0200_0000_0000..=0x0000_02ff_ffff_ffff;
        const INIT = 0x0000_0300_0000_0000..=0x0000_03ff_ffff_ffff;
        const INPUT = 0x0000_0400_0000_0000..=0x0000_04ff_ffff_ffff;
    }
}

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
fn check_ranges(ranges: &[PageRange]) {
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
    use crate::{check_ranges, PageRange};

    #[test]
    fn test_address_range() {
        let mut range = PageRange::new(0x1000..=0x3fff).into_iter();
        assert_eq!(range.next(), Some(0x1000));
        assert_eq!(range.next(), Some(0x2000));
        assert_eq!(range.next(), Some(0x3000));
        assert_eq!(range.next(), None);
    }

    #[test]
    fn test_valid_range() {
        PageRange::new(0x1000..=0x1fff);
    }

    #[test]
    #[should_panic]
    fn test_bad_range_start() {
        check_ranges(&[PageRange::new(0x1001..=0x1fff)])
    }

    #[test]
    #[should_panic]
    fn test_bad_range_end() {
        check_ranges(&[PageRange::new(0x1000..=0x1ffe)])
    }

    #[test]
    #[should_panic]
    fn test_bad_range() {
        check_ranges(&[PageRange::new(0x1000..=0xfff)])
    }

    #[test]
    #[should_panic]
    fn test_invalid_ranges() {
        check_ranges(&[
            PageRange::new(0x1000..=0x3fff),
            PageRange::new(0x2000..=0x2fff),
        ])
    }
}
