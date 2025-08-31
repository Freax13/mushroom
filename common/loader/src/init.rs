use std::iter::once;

use bytemuck::bytes_of;
use constants::physical_address::INIT_FILE;
use io::input::Header;
use snp_types::VmplPermissions;
use x86_64::structures::paging::PhysFrame;

use crate::{LoadCommand, LoadCommandPayload};

pub fn load_init(init: &[u8]) -> impl Iterator<Item = LoadCommand> + Clone + '_ {
    let start_frame = PhysFrame::from_start_address(INIT_FILE.start.start_address()).unwrap();
    let end_frame = PhysFrame::from_start_address(INIT_FILE.end.start_address()).unwrap();
    let frames = PhysFrame::range(start_frame, end_frame);

    let start_header = Header::without_hash(init);
    let mut bytes = [0; 0x1000];
    bytes[..size_of::<Header>()].copy_from_slice(bytes_of(&start_header));
    let start_header_payload = LoadCommandPayload::Normal(bytes);

    let end_header = Header::end();
    let mut bytes = [0; 0x1000];
    bytes[..size_of::<Header>()].copy_from_slice(bytes_of(&end_header));
    let end_header_payload = LoadCommandPayload::Normal(bytes);

    let payloads = once((VmplPermissions::READ, start_header_payload))
        .chain(init.chunks(0x1000).map(|chunk| {
            let mut bytes = [0; 0x1000];
            bytes[..chunk.len()].copy_from_slice(chunk);
            (
                VmplPermissions::READ | VmplPermissions::EXECUTE_USER,
                LoadCommandPayload::Normal(bytes),
            )
        }))
        .chain(once((VmplPermissions::READ, end_header_payload)));

    payloads
        .zip(frames)
        .map(|((vmpl1_perms, payload), physical_address)| LoadCommand {
            physical_address,
            vcpu_id: 0,
            vmpl1_perms,
            payload,
            shared: false,
            private: true,
        })
}
