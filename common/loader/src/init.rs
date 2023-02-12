use std::iter::once;

use constants::physical_address::INIT;
use snp_types::VmplPermissions;

use crate::{LoadCommand, LoadCommandPayload};

pub fn load_init<'a>(init: &'a [u8]) -> impl Iterator<Item = LoadCommand> + 'a {
    let mut frames = INIT.into_iter();

    let mut bytes = [0; 0x1000];
    bytes[..8].copy_from_slice(&init.len().to_ne_bytes());

    let physical_address = frames.next().unwrap();
    let header_load = LoadCommand {
        physical_address,
        vmpl1_perms: VmplPermissions::READ,
        payload: LoadCommandPayload::Normal(bytes),
    };

    once(header_load).chain(init.chunks(0x1000).map(move |chunk| {
        let mut bytes = [0; 0x1000];
        bytes[..chunk.len()].copy_from_slice(chunk);

        let physical_address = frames.next().unwrap();
        LoadCommand {
            physical_address,
            vmpl1_perms: VmplPermissions::READ | VmplPermissions::EXECUTE_USER,
            payload: LoadCommandPayload::Normal(bytes),
        }
    }))
}
