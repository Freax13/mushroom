use snp_types::VmplPermissions;

use crate::{elf::load, LoadCommand};

const SUPERVISOR_BYTES: &[u8] = include_bytes!(env!("CARGO_BIN_FILE_SUPERVISOR"));

pub fn load_supervisor() -> impl Iterator<Item = LoadCommand> {
    load(SUPERVISOR_BYTES, VmplPermissions::empty())
}
