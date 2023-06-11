use snp_types::VmplPermissions;

use crate::{elf::load, LoadCommand};

pub fn load_supervisor(supervisor: &[u8]) -> impl Iterator<Item = LoadCommand> + '_ {
    load(supervisor, VmplPermissions::empty())
}
