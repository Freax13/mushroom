use std::{iter::once, mem::size_of};

use bytemuck::bytes_of;
use constants::physical_address::INPUT;
use io::input::Header;
use snp_types::VmplPermissions;

use crate::{LoadCommand, LoadCommandPayload};

pub fn load_input<'a>(input: &'a [u8]) -> (impl Iterator<Item = LoadCommand> + 'a, [u8; 32]) {
    let header = Header::new(input);

    let payloads = once(LoadCommandPayload::Normal({
        let mut bytes = [0; 0x1000];
        bytes[..size_of::<Header>()].copy_from_slice(bytes_of(&header));
        bytes
    }))
    .chain(input.chunks(0x1000).map(|chunk| {
        let mut bytes = [0; 0x1000];
        bytes[..chunk.len()].copy_from_slice(chunk);
        LoadCommandPayload::Normal(bytes)
    }));

    (
        INPUT
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
