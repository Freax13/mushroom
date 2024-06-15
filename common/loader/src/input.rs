use std::{iter::once, mem::size_of};

use bytemuck::bytes_of;
use constants::physical_address::INPUT_FILE;
use io::input::Header;
use snp_types::VmplPermissions;
use x86_64::structures::paging::PhysFrame;

use crate::{LoadCommand, LoadCommandPayload};

pub fn load_input(input: &[u8]) -> (impl Iterator<Item = LoadCommand> + '_, [u8; 32]) {
    let header = Header::new(input);

    let payloads = once(LoadCommandPayload::Shared({
        let mut bytes = [0; 0x1000];
        bytes[..size_of::<Header>()].copy_from_slice(bytes_of(&header));
        bytes
    }))
    .chain(input.chunks(0x1000).map(|chunk| {
        let mut bytes = [0; 0x1000];
        bytes[..chunk.len()].copy_from_slice(chunk);
        LoadCommandPayload::Shared(bytes)
    }));

    let start_frame = PhysFrame::from_start_address(INPUT_FILE.start.start_address()).unwrap();
    let end_frame = PhysFrame::from_start_address(INPUT_FILE.end.start_address()).unwrap();
    let frames = PhysFrame::range(start_frame, end_frame);

    (
        frames
            .into_iter()
            .zip(payloads)
            .map(|(physical_address, payload)| LoadCommand {
                physical_address,
                vmpl1_perms: VmplPermissions::empty(),
                payload,
            }),
        header.hash(),
    )
}
