use core::mem::size_of;

use bytemuck::pod_read_unaligned;
use constants::physical_address::INPUT;
use io::input::Header;
use log::info;
use sha2::{Digest, Sha256};

use crate::{ghcb::get_host_data, pagetable::TEMPORARY_MAPPER};

/// Verify the input and make it accessible to VMPL 1.
pub fn verify_and_load() {
    let mut frames = INPUT.into_iter();
    let header_frame = frames.next().unwrap();

    // Read the input header.
    let mut mapper = TEMPORARY_MAPPER.borrow_mut();
    let mut mapping = mapper.create_temporary_mapping_4kib(header_frame, false, false);
    let header_page_bytes = unsafe { mapping.convert_to_private_in_place() };
    let header_bytes = &header_page_bytes[..size_of::<Header>()];
    let header = pod_read_unaligned::<Header>(header_bytes);

    // Verify the input header.
    let host_data = get_host_data();
    assert!(header.verify(host_data), "header doesn't match host data");

    // Hash the input.

    let mut hasher = Sha256::new();

    // Copy pages one at a time.
    let mut remaining_len = header.input_len;
    while remaining_len >= 0x1000 {
        let frame = frames.next().unwrap();

        let mut mapping = mapper.create_temporary_mapping_4kib(frame, false, false);
        let input_bytes = unsafe { mapping.convert_to_private_in_place() };
        hasher.update(input_bytes);

        remaining_len -= 0x1000;
    }

    // The last page may not be a full page.
    if remaining_len > 0 {
        let frame = frames.next().unwrap();

        let mut mapping = mapper.create_temporary_mapping_4kib(frame, false, false);
        let input_bytes = unsafe { mapping.convert_to_private_in_place() };
        let (input_bytes, rest) = input_bytes.split_at(remaining_len);
        hasher.update(input_bytes);

        // The page must be zero past the end of the input.
        assert_eq!(rest, &[0; 4096][remaining_len..]);
    }

    // Verify the input.
    let hash: [u8; 32] = hasher.finalize().into();
    assert_eq!(header.hash, hash, "input hash doesn't match hash in header");

    info!("verified input");
}
