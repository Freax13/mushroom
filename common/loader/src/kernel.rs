use snp_types::VmplPermissions;

use crate::{elf::load, LoadCommand};

pub fn load_kernel(kernel: &[u8]) -> impl Iterator<Item = LoadCommand> + '_ {
    load(
        kernel,
        VmplPermissions::READ | VmplPermissions::WRITE | VmplPermissions::EXECUTE_SUPERVISOR,
    )
}
