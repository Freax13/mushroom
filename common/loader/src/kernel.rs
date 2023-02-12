use snp_types::VmplPermissions;

use crate::{elf::load, LoadCommand};

const KERNEL_BYTES: &[u8] = include_bytes!(env!("CARGO_BIN_FILE_KERNEL"));

pub fn load_kernel() -> impl Iterator<Item = LoadCommand> {
    load(
        KERNEL_BYTES,
        VmplPermissions::READ | VmplPermissions::WRITE | VmplPermissions::EXECUTE_SUPERVISOR,
    )
}
