use std::{iter::once, mem::size_of};

use bytemuck::bytes_of;
use constants::physical_address::INPUT_FILE;
use io::input::{HashType, Header};
use snp_types::VmplPermissions;
use x86_64::structures::paging::PhysFrame;

use crate::{LoadCommand, LoadCommandPayload};

#[derive(Clone)]
pub struct Input<T> {
    pub bytes: T,
    pub hash_type: HashType,
}

pub fn load_input(
    inputs: &[Input<impl AsRef<[u8]>>],
) -> (impl Iterator<Item = LoadCommand> + '_, [u8; 32]) {
    let mut header = Header::end();
    let mut headers = inputs
        .iter()
        .rev()
        .map(|input| {
            header = Header::new(input.bytes.as_ref(), input.hash_type, &header);
            header
        })
        .collect::<Vec<_>>();
    headers.reverse();

    let payloads = headers
        .into_iter()
        .zip(inputs)
        .flat_map(|(header, input)| {
            once(LoadCommandPayload::Shared({
                let mut bytes = [0; 0x1000];
                bytes[..size_of::<Header>()].copy_from_slice(bytes_of(&header));
                bytes
            }))
            .chain(input.bytes.as_ref().chunks(0x1000).map(|chunk| {
                let mut bytes = [0; 0x1000];
                bytes[..chunk.len()].copy_from_slice(chunk);
                LoadCommandPayload::Shared(bytes)
            }))
        })
        .chain(once(LoadCommandPayload::Shared({
            let header = Header::end();
            let mut bytes = [0; 0x1000];
            bytes[..size_of::<Header>()].copy_from_slice(bytes_of(&header));
            bytes
        })));

    let start_frame = PhysFrame::from_start_address(INPUT_FILE.start.start_address()).unwrap();
    let end_frame = PhysFrame::from_start_address(INPUT_FILE.end.start_address()).unwrap();
    let frames = PhysFrame::range(start_frame, end_frame);

    (
        frames
            .into_iter()
            .zip(payloads)
            .map(|(physical_address, payload)| LoadCommand {
                physical_address,
                vcpu_id: 0,
                vmpl1_perms: VmplPermissions::empty(),
                payload,
            }),
        header.hash(),
    )
}
