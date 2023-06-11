#![forbid(unsafe_code)]

use bytemuck::cast;
use snp_types::{cpuid::CpuidPage, PageType, VmplPermissions};
use x86_64::structures::paging::PhysFrame;

mod elf;
mod init;
mod input;
mod kernel;
mod supervisor;

#[derive(Debug)]
pub struct LoadCommand {
    pub physical_address: PhysFrame,
    pub vmpl1_perms: VmplPermissions,
    pub payload: LoadCommandPayload,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy)]
pub enum LoadCommandPayload {
    Normal([u8; 0x1000]),
    Zero,
    Secrets,
    Cpuid(CpuidPage),
    Shared([u8; 0x1000]),
}

impl LoadCommandPayload {
    pub fn page_type(&self) -> Option<PageType> {
        match self {
            LoadCommandPayload::Normal(_) => Some(PageType::Normal),
            LoadCommandPayload::Zero => Some(PageType::Zero),
            LoadCommandPayload::Secrets => Some(PageType::Secrets),
            LoadCommandPayload::Cpuid(_) => Some(PageType::Cpuid),
            LoadCommandPayload::Shared(_) => None,
        }
    }

    pub fn bytes(&self) -> [u8; 0x1000] {
        match self {
            LoadCommandPayload::Normal(bytes) => *bytes,
            LoadCommandPayload::Zero => [0; 0x1000],
            LoadCommandPayload::Secrets => [0; 0x1000],
            LoadCommandPayload::Cpuid(cpuid) => cast(*cpuid),
            LoadCommandPayload::Shared(bytes) => *bytes,
        }
    }
}

pub fn generate_base_load_commands<'a>(
    supervisor: &'a [u8],
    kernel: &'a [u8],
    init: &'a [u8],
) -> impl Iterator<Item = LoadCommand> + 'a {
    let load_supervisor = supervisor::load_supervisor(supervisor);
    let load_kernel = kernel::load_kernel(kernel);
    let load_init = init::load_init(init);
    load_supervisor.chain(load_kernel).chain(load_init)
}

pub fn generate_load_commands<'a>(
    supervisor: &'a [u8],
    kernel: &'a [u8],
    init: &'a [u8],
    input: &'a [u8],
) -> (impl Iterator<Item = LoadCommand> + 'a, [u8; 32]) {
    let base_load_commands = generate_base_load_commands(supervisor, kernel, init);
    let (load_input, host_data) = input::load_input(input);
    (base_load_commands.chain(load_input), host_data)
}
