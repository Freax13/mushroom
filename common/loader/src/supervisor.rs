use snp_types::VmplPermissions;

use crate::{LoadCommand, elf::load};

pub fn load_supervisor(supervisor: &[u8]) -> impl Iterator<Item = LoadCommand> + '_ {
    load(supervisor, VmplPermissions::empty())
}
