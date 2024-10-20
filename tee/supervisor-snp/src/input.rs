use core::mem::size_of;

use bytemuck::checked::pod_read_unaligned;
use constants::physical_address::INPUT_FILE;
use io::input::{Hasher, Header};
use log::info;
use snp_types::{ghcb::msr_protocol::PageOperation, VmplPermissions};
use x86_64::{
    structures::paging::{Page, PhysFrame, Size4KiB},
    VirtAddr,
};

use crate::{
    ghcb::{self, get_host_data},
    rmp::{pvalidate, rmpadjust},
};

/// Verify the input and make it accessible to VMPL 1.
pub fn verify_and_load() {
    let mut page_index = 0;

    let mut next_hash = get_host_data();
    loop {
        // Read the input header.
        let header_page_bytes = convert_to_private_in_place(page_index);
        let header_bytes = &header_page_bytes[..size_of::<Header>()];
        let header = pod_read_unaligned::<Header>(header_bytes);
        page_index += 1;

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
            let input_bytes = convert_to_private_in_place(page_index);
            page_index += 1;
            hasher.update(&input_bytes);
            remaining_len -= 0x1000;
        }

        // The last page may not be a full page.
        if remaining_len > 0 {
            let input_bytes = convert_to_private_in_place(page_index);
            page_index += 1;
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
    ghcb::page_state_change(frame, PageOperation::PageAssignmentPrivate);

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
