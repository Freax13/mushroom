use std::iter::once;

use constants::physical_address::INIT_FILE;
use snp_types::VmplPermissions;
use x86_64::structures::paging::PhysFrame;

use crate::{LoadCommand, LoadCommandPayload};

pub fn load_init(init: &[u8]) -> impl Iterator<Item = LoadCommand> + '_ {
    let start_frame = PhysFrame::from_start_address(INIT_FILE.start.start_address()).unwrap();
    let end_frame = PhysFrame::from_start_address(INIT_FILE.end.start_address()).unwrap();
    let mut frames = PhysFrame::range(start_frame, end_frame);

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
