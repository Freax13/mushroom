use bytemuck::{Pod, Zeroable};

use crate::user::process::syscall::traits::Abi;

use super::{ElfHeader, ElfIdent, ElfLoaderParams, ProgramHeaderEntry};

pub enum ElfLoaderParams64 {}

impl ElfLoaderParams for ElfLoaderParams64 {
    type Header = ElfHeader64;
    type ProgramHeaderEntry = ProgramHeaderEntry64;

    const ABI: Abi = Abi::Amd64;
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct ElfHeader64 {
    e_ident: ElfIdent,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

impl ElfHeader for ElfHeader64 {
    const CLASS: u8 = 2;
    const MACHINE: u16 = 62;

    fn e_ident(&self) -> &ElfIdent {
        &self.e_ident
    }

    fn e_type(&self) -> u16 {
        self.e_type
    }

    fn e_machine(&self) -> u16 {
        self.e_machine
    }

    fn e_version(&self) -> u32 {
        self.e_version
    }
    fn e_entry(&self) -> u64 {
        self.e_entry
    }

    fn e_phoff(&self) -> u64 {
        self.e_phoff
    }

    fn e_phentsize(&self) -> u16 {
        self.e_phentsize
    }

    fn e_phnum(&self) -> u16 {
        self.e_phnum
    }
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct ProgramHeaderEntry64 {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

impl ProgramHeaderEntry for ProgramHeaderEntry64 {
    fn p_type(&self) -> u32 {
        self.p_type
    }

    fn p_offset(&self) -> u64 {
        self.p_offset
    }

    fn p_vaddr(&self) -> u64 {
        self.p_vaddr
    }

    fn p_filesz(&self) -> u64 {
        self.p_filesz
    }

    fn p_memsz(&self) -> u64 {
        self.p_memsz
    }

    fn p_flags(&self) -> u32 {
        self.p_flags
    }
}
