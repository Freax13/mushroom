use core::any::Any;

use constants::{physical_address, virtual_address};
use spin::Lazy;
use x86_64::structures::paging::{frame::PhysFrameRangeInclusive, page::PageRangeInclusive};

use crate::{
    error::Result,
    memory::{
        frame::DUMB_FRAME_ALLOCATOR,
        pagetable::{map_page, PageTableFlags, PresentPageTableEntry},
    },
    user::process::syscall::args::FileMode,
};

use self::node::{
    special::{NullFile, OutputFile},
    Directory, TmpFsDirectory, TmpFsFile, ROOT_NODE,
};

pub mod node;
pub mod path;

pub use path::{FileName, Path, PathSegment};

pub fn init() -> Result<()> {
    let bin = ROOT_NODE.create_dir(FileName::new(b"bin").unwrap(), false)?;
    let bin =
        <dyn Any>::downcast_ref::<TmpFsDirectory>(&*bin as &dyn Any).expect("/bin/ is not a tmpfs");
    bin.mount(
        FileName::new(b"init").unwrap(),
        TmpFsFile::new(FileMode::from_bits_truncate(0o755), &INIT),
    );

    let dev = ROOT_NODE.create_dir(FileName::new(b"dev").unwrap(), false)?;
    let dev =
        <dyn Any>::downcast_ref::<TmpFsDirectory>(&*dev as &dyn Any).expect("/dev/ is not a tmpfs");
    dev.mount(
        FileName::new(b"input").unwrap(),
        TmpFsFile::new(FileMode::from_bits_truncate(0o444), &INPUT),
    );
    dev.mount(FileName::new(b"output").unwrap(), OutputFile::new());
    dev.mount(FileName::new(b"null").unwrap(), NullFile::new());

    Ok(())
}

static INIT: Lazy<&'static [u8]> = Lazy::new(|| {
    let pages = virtual_address::INIT.into_iter();
    let frames = physical_address::INIT.into_iter();
    load_static_file(pages, frames)
});

static INPUT: Lazy<&'static [u8]> = Lazy::new(|| {
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
        map_page(header_page, header_entry, &mut &DUMB_FRAME_ALLOCATOR)
            .expect("failed to map header");
    }

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
            map_page(input_page, input_entry, &mut &DUMB_FRAME_ALLOCATOR)
                .expect("failed to map content");
        }
    }

    let first_input_page = header_page + 1;
    let ptr = first_input_page.start_address().as_ptr();
    unsafe { core::slice::from_raw_parts(ptr, len) }
}
