use bytemuck::{Pod, Zeroable};

use super::{ElfHeader, ElfIdent, ElfLoaderParams, ProgramHeaderEntry};
use crate::user::process::syscall::traits::Abi;

pub enum ElfLoaderParams32 {}

impl ElfLoaderParams for ElfLoaderParams32 {
    type Header = ElfHeader32;
    type ProgramHeaderEntry = ProgramHeaderEntry32;

    const ABI: Abi = Abi::I386;
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct ElfHeader32 {
    e_ident: ElfIdent,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u32,
    e_phoff: u32,
    e_shoff: u32,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

impl ElfHeader for ElfHeader32 {
    const CLASS: u8 = 1;
    const MACHINE: u16 = 3;

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
        u64::from(self.e_entry)
    }

    fn e_phoff(&self) -> u64 {
        u64::from(self.e_phoff)
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
pub struct ProgramHeaderEntry32 {
    p_type: u32,
    p_offset: u32,
    p_vaddr: u32,
    p_paddr: u32,
    p_filesz: u32,
    p_memsz: u32,
    p_flags: u32,
    p_align: u32,
}

impl ProgramHeaderEntry for ProgramHeaderEntry32 {
    fn p_type(&self) -> u32 {
        self.p_type
    }

    fn p_offset(&self) -> u64 {
        u64::from(self.p_offset)
    }

    fn p_vaddr(&self) -> u64 {
        u64::from(self.p_vaddr)
    }

    fn p_filesz(&self) -> u64 {
        u64::from(self.p_filesz)
    }

    fn p_memsz(&self) -> u64 {
        u64::from(self.p_memsz)
    }

    fn p_flags(&self) -> u32 {
        self.p_flags
    }
}
