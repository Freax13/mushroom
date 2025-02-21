use snp_types::VmplPermissions;

use crate::{
    LoadCommand,
    elf::{load, load_shadow_mapping},
};

pub fn load_kernel(
    kernel: &[u8],
    load_kasan_shadow_mappings: bool,
) -> impl Iterator<Item = LoadCommand> + '_ {
    load(
        kernel,
        VmplPermissions::READ | VmplPermissions::WRITE | VmplPermissions::EXECUTE_SUPERVISOR,
    )
    .chain(
        load_shadow_mapping(kernel, VmplPermissions::READ | VmplPermissions::WRITE)
            .filter(move |_| load_kasan_shadow_mappings),
    )
}
