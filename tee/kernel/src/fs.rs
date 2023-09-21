use crate::spin::lazy::Lazy;
use constants::{physical_address, virtual_address};
use x86_64::structures::paging::{frame::PhysFrameRangeInclusive, page::PageRangeInclusive};

use crate::memory::{
    frame::FRAME_ALLOCATOR,
    pagetable::{map_page, PageTableFlags, PresentPageTableEntry},
};

pub mod fd;
pub mod node;
pub mod path;

pub static INIT: Lazy<&'static [u8]> = Lazy::new(|| {
    let pages = virtual_address::INIT.into_iter();
    let frames = physical_address::INIT.into_iter();
    load_static_file(pages, frames)
});

pub static INPUT: Lazy<&'static [u8]> = Lazy::new(|| {
    let pages = virtual_address::INPUT.into_iter();
    let frames = physical_address::INPUT.into_iter();
    load_static_file(pages, frames)
});

fn load_static_file(
    mut pages: PageRangeInclusive,
    mut frames: PhysFrameRangeInclusive,
) -> &'static [u8] {
    let header_page = pages.next().unwrap();
    let header_frame = frames.next().unwrap();

    let header_entry = PresentPageTableEntry::new(header_frame, PageTableFlags::GLOBAL);
    unsafe {
        map_page(header_page, header_entry, &mut &FRAME_ALLOCATOR).expect("failed to map header");
    }

    #[cfg(sanitize = "address")]
    crate::sanitize::map_shadow(
        header_page.start_address().as_ptr(),
        crate::sanitize::MIN_ALLOCATION_SIZE,
        &mut &FRAME_ALLOCATOR,
    );

    let len = unsafe {
        header_page
            .start_address()
            .as_ptr::<usize>()
            .read_volatile()
    };

    let num_pages = len.div_ceil(0x1000);
    for _ in 0..num_pages {
        let input_page = pages.next().unwrap();
        let input_frame = frames.next().unwrap();

        let input_entry = PresentPageTableEntry::new(input_frame, PageTableFlags::GLOBAL);
        unsafe {
            map_page(input_page, input_entry, &mut &FRAME_ALLOCATOR)
                .expect("failed to map content");
        }
    }

    #[cfg(sanitize = "address")]
    crate::sanitize::map_shadow(
        header_page
            .start_address()
            .as_ptr::<u8>()
            .wrapping_add(crate::sanitize::MIN_ALLOCATION_SIZE)
            .cast(),
        ((0x1000 + len).saturating_sub(crate::sanitize::MIN_ALLOCATION_SIZE))
            .next_multiple_of(crate::sanitize::MIN_ALLOCATION_SIZE),
        &mut &FRAME_ALLOCATOR,
    );

    let first_input_page = header_page + 1;
    let ptr = first_input_page.start_address().as_ptr();
    unsafe { core::slice::from_raw_parts(ptr, len) }
}
