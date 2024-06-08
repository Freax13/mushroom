use core::ffi::c_void;

use bit_field::BitField;
use x86_64::{
    registers::control::Cr2,
    structures::{idt::InterruptStackFrame, paging::Page},
    VirtAddr,
};

use crate::memory::{
    frame::{allocate_frame, deallocate_frame},
    pagetable::{map_page, unmap_page, PageTableFlags, PresentPageTableEntry},
};

mod interface;

const ASAN_MAPPING_OFFSET: u64 = 0xdfff_c000_0000_0000;
const ASAN_MAPPING_SCALE: u64 = 3;
const ASAN_MAPPING_MULTIPLIER: usize = 1 << ASAN_MAPPING_SCALE;

/// Map a real address to the shadow address.
#[inline]
fn map_to_shadow(addr: u64) -> u64 {
    ASAN_MAPPING_OFFSET + (addr >> ASAN_MAPPING_SCALE)
}

/// Map a shadow address to the real address.
fn map_from_shadow(addr: u64) -> u64 {
    (addr - ASAN_MAPPING_OFFSET) << ASAN_MAPPING_SCALE
}

/// The smallest unit of memory that we can map shadow memory for.
pub const MIN_ALLOCATION_SIZE: usize = 0x1000 << ASAN_MAPPING_SCALE;

/// Add `ptr` to the shadow mapping.
pub fn map_shadow(ptr: *const c_void, size: usize) {
    let addr = ptr as u64;
    assert!(
        addr.get_bit(63),
        "can only map shadow for addresses in the upper half"
    );
    assert!(
        ptr.is_aligned_to(MIN_ALLOCATION_SIZE),
        "pointer is not aligned"
    );
    assert!(size % MIN_ALLOCATION_SIZE == 0, "size is not aligned");

    let shadow_address = map_to_shadow(addr);
    let shadow_addr = VirtAddr::new(shadow_address);
    let shadow_page = Page::containing_address(shadow_addr);

    let pages = size / 0x1000;
    let shadow_pages = pages >> ASAN_MAPPING_SCALE;

    for shadow_page in (shadow_page..).take(shadow_pages) {
        // debug!("mapping shadow page: {shadow_page:?}");

        let frame = allocate_frame();
        let entry =
            PresentPageTableEntry::new(frame, PageTableFlags::WRITABLE | PageTableFlags::GLOBAL);
        let res = unsafe { map_page(shadow_page, entry) };
        res.unwrap();

        let ptr = shadow_page.start_address().as_mut_ptr();
        unsafe {
            interface::set_shadow_n(ptr, 0x1000, 0);
        }
    }
}

/// Remove `ptr` from the shadow mapping.
pub fn unmap_shadow(ptr: *const c_void, size: usize) {
    let addr = ptr as u64;
    assert!(
        addr.get_bit(63),
        "can only map shadow for addresses in the upper half"
    );
    assert!(
        ptr.is_aligned_to(MIN_ALLOCATION_SIZE),
        "pointer is not aligned"
    );
    assert!(size % MIN_ALLOCATION_SIZE == 0, "size is not aligned");

    let shadow_address = map_to_shadow(addr);
    let shadow_addr = VirtAddr::new(shadow_address);
    let shadow_page = Page::containing_address(shadow_addr);

    let pages = size / 0x1000;
    let shadow_pages = pages >> ASAN_MAPPING_SCALE;

    for shadow_page in (shadow_page..).take(shadow_pages) {
        let entry = unsafe { unmap_page(shadow_page) };
        unsafe {
            deallocate_frame(entry.frame());
        }
    }
}

/// Check if Cr2 points somewhere to the shadow mapping.
pub fn page_fault_handler(frame: &InterruptStackFrame) {
    let cr2 = Cr2::read_raw();

    let kernel_start = map_to_shadow(0xffff_8000_0000_0000);
    let kernel_end = map_to_shadow(0xffff_ffff_ffff_ffff);
    if !(kernel_start..=kernel_end).contains(&cr2) {
        return;
    }

    let real_address = map_from_shadow(cr2);
    panic!(
        "page fault while accessing shadow address for {real_address:#018x} at {:?}",
        frame.instruction_pointer
    );
}

/// Mark shadow memory as usable or unusable.
pub unsafe fn mark(ptr: *const c_void, len: usize, usable: bool) {
    assert!(ptr.is_aligned_to(ASAN_MAPPING_MULTIPLIER));
    assert_eq!(len % ASAN_MAPPING_MULTIPLIER, 0);

    let ptr = map_to_shadow(ptr as u64);

    let n = if usable { 0 } else { 0xfd };
    unsafe {
        interface::set_shadow_n(ptr as *mut u8, len >> ASAN_MAPPING_SCALE, n);
    }
}
