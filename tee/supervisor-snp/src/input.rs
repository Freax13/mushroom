use core::{
    mem::size_of,
    sync::atomic::{AtomicU64, Ordering},
};

use bytemuck::checked::pod_read_unaligned;
use constants::physical_address::INPUT_FILE;
use io::input::{Hasher, Header};
use log::info;
use snp_types::{
    VmplPermissions,
    ghcb::{PageOperation, msr_protocol},
};
use spin::Once;
use x86_64::{
    VirtAddr,
    structures::paging::{Page, PhysFrame, Size4KiB},
};

use crate::{
    ghcb::{self, get_host_data},
    rmp::{pvalidate, rmpadjust},
};

static PAGE_INDEX: AtomicU64 = AtomicU64::new(0);

fn next_page_index() -> u64 {
    PAGE_INDEX.fetch_add(1, Ordering::Relaxed)
}

/// Verify the input and make it accessible to VMPL 1.
pub fn verify_and_load() {
    let mut next_hash = get_host_data();
    loop {
        // Read the input header.
        let header_page_bytes = convert_to_private_in_place(next_page_index());
        let header_bytes = &header_page_bytes[..size_of::<Header>()];
        let header = pod_read_unaligned::<Header>(header_bytes);

        // Verify the input header.
        assert!(header.verify(next_hash), "header doesn't match");

        if header == Header::end() {
            break;
        }

        // Hash the input.

        let mut hasher = Hasher::new(header.hash_type);

        // Copy pages one at a time.
        let mut remaining_len = usize::try_from(header.input_len).unwrap();
        while remaining_len >= 0x1000 {
            let input_bytes = convert_to_private_in_place(next_page_index());
            hasher.update(&input_bytes);
            remaining_len -= 0x1000;
        }

        // The last page may not be a full page.
        if remaining_len > 0 {
            let input_bytes = convert_to_private_in_place(next_page_index());
            let (input_bytes, rest) = input_bytes.split_at(remaining_len);
            hasher.update(input_bytes);

            // The page must be zero past the end of the input.
            assert_eq!(rest, &[0; 4096][remaining_len..]);
        }

        // Verify the input.
        hasher.verify(header.hash);

        next_hash = header.next_hash;
    }

    info!("verified input");
}

/// This converts a page of the input file to private memory. Returns the
/// content of the page.
fn convert_to_private_in_place(index: u64) -> [u8; 0x1000] {
    let shared_mapping =
        Page::<Size4KiB>::from_start_address(VirtAddr::new(0x1000000000)).unwrap() + index;
    let private_mapping =
        Page::<Size4KiB>::from_start_address(VirtAddr::new(0x2000000000)).unwrap() + index;
    let frame = PhysFrame::<Size4KiB>::from_start_address(INPUT_FILE.start.start_address())
        .unwrap()
        + index;

    // Copy to content out of the shared mapping.
    let mut content = [0u8; 0x1000];
    unsafe {
        core::intrinsics::volatile_copy_nonoverlapping_memory(
            &mut content,
            shared_mapping.start_address().as_ptr(),
            1,
        );
    }

    // Tell the Hypervisor that we want to change the page to private.
    ghcb::page_state_change(frame, msr_protocol::PageOperation::PageAssignmentPrivate);

    // Validate the page.
    unsafe {
        pvalidate(private_mapping, true).unwrap();
    }

    // Copy the content back in.
    unsafe {
        core::intrinsics::volatile_copy_nonoverlapping_memory(
            private_mapping.start_address().as_mut_ptr(),
            &content,
            1,
        );
    }

    // Adjust the permissions for VMPL 1.
    unsafe {
        rmpadjust(private_mapping, 1, VmplPermissions::READ, false).unwrap();
    }

    content
}

pub fn release() {
    static RELEASE: Once = Once::new();
    RELEASE.call_once(|| {
        let private_mapping_start =
            Page::<Size4KiB>::from_start_address(VirtAddr::new(0x2000000000)).unwrap();
        let num_pages = PAGE_INDEX.load(Ordering::SeqCst);
        for i in 0..num_pages {
            let private_mapping = private_mapping_start + i;
            // Invalidate the page.
            unsafe {
                pvalidate(private_mapping, false).unwrap();
            }
        }

        // Tell the Hypervisor that we want to change the pages to shared.
        let input_file_start =
            PhysFrame::<Size4KiB>::from_start_address(INPUT_FILE.start.start_address()).unwrap();
        ghcb::page_state_change_multiple(
            PhysFrame::range(input_file_start, input_file_start + num_pages),
            PageOperation::PageAssignmentShared,
        );
    });
}
