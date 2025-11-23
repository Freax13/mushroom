use alloc::vec;
use core::{cmp, mem::size_of};

use bit_field::BitField;
use bytemuck::{Pod, Zeroable, bytes_of_mut};
use usize_conversions::usize_from;
use x86_64::{VirtAddr, align_up};

use crate::{
    error::{Result, bail, ensure},
    fs::{
        fd::{FileDescriptor, KernelReadBuf},
        node::FileAccessContext,
        path::Path,
    },
    user::{
        memory::{Bias, MemoryPermissions, VirtualMemoryWriteGuard},
        syscall::traits::Abi,
    },
};

mod elf32;
mod elf64;

pub use elf32::ElfLoaderParams32;
pub use elf64::ElfLoaderParams64;

pub const MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PF_X_BIT: usize = 0;
const PF_W_BIT: usize = 1;
const PF_R_BIT: usize = 2;

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct ElfIdent {
    pub e_ident: [u8; 16],
}

impl ElfIdent {
    pub fn verify(&self) -> Result<Abi> {
        ensure!(self.e_ident[0..4] == MAGIC, NoExec);

        let abi = match self.e_ident[4] {
            1 => Abi::I386,
            2 => Abi::Amd64,
            _ => bail!(NoExec),
        };

        // Check endianess == little.
        ensure!(self.e_ident[5] == 1, NoExec);

        // Check version == 1.
        ensure!(self.e_ident[6] == 1, NoExec);

        // Check OS ABI == 0 (System V) or 3 (Linux).
        ensure!(matches!(self.e_ident[7], 0 | 3), NoExec);

        // Ignore extended ABI version.
        let _ = self.e_ident[8];

        // Ignore reserved bytes.
        let _ = self.e_ident[9..];

        Ok(abi)
    }
}

pub trait ElfLoaderParams {
    type Header: ElfHeader;
    type ProgramHeaderEntry: ProgramHeaderEntry;

    const ABI: Abi;
}

pub trait ElfHeader: Pod {
    const CLASS: u8;
    const MACHINE: u16;

    fn e_ident(&self) -> &ElfIdent;
    fn e_type(&self) -> u16;
    fn e_machine(&self) -> u16;
    fn e_version(&self) -> u32;
    fn e_entry(&self) -> u64;
    fn e_phoff(&self) -> u64;
    fn e_phentsize(&self) -> u16;
    fn e_phnum(&self) -> u16;
}

pub trait ProgramHeaderEntry: Pod {
    fn p_type(&self) -> u32;
    fn p_offset(&self) -> u64;
    fn p_vaddr(&self) -> u64;
    fn p_filesz(&self) -> u64;
    fn p_memsz(&self) -> u64;
    fn p_flags(&self) -> u32;
}

pub fn load_elf<E>(
    file: &FileDescriptor,
    ctx: &FileAccessContext,
    mut vm: VirtualMemoryWriteGuard<'_>,
    load_bias: u64,
) -> Result<LoaderInfo>
where
    E: ElfLoaderParams,
{
    let mut header = <E::Header>::zeroed();
    file.pread(0, &mut KernelReadBuf::new(bytes_of_mut(&mut header)), ctx)?;

    header.e_ident().verify()?;

    ensure!(header.e_ident().e_ident[4] == <E::Header>::CLASS, NoExec);
    ensure!(header.e_machine() == <E::Header>::MACHINE, NoExec);
    ensure!(header.e_version() == 1, NoExec);

    let base = match header.e_type() {
        ET_EXEC => 0,
        ET_DYN => load_bias,
        _ => bail!(NoExec),
    };

    let mut phdr = None;
    let mut interpreter_path = None;

    let e_phoff = header.e_phoff();
    let e_phentsize = header.e_phentsize();
    let e_phnum = header.e_phnum();

    ensure!(
        usize::from(e_phentsize) == size_of::<E::ProgramHeaderEntry>(),
        NoExec
    );

    let mut end = VirtAddr::zero();

    for i in 0..e_phnum {
        let offset = usize_from(e_phoff) + usize::from(i) * usize::from(e_phentsize);
        let mut program_header_entry = <E::ProgramHeaderEntry>::zeroed();
        file.pread(
            offset,
            &mut KernelReadBuf::new(bytes_of_mut(&mut program_header_entry)),
            ctx,
        )?;

        let p_type = program_header_entry.p_type();
        let p_offset = program_header_entry.p_offset();
        let p_vaddr = program_header_entry.p_vaddr();
        let mut p_filesz = program_header_entry.p_filesz();
        let mut p_memsz = program_header_entry.p_memsz();
        let p_flags = program_header_entry.p_flags();

        match p_type {
            PT_LOAD => {
                // Sanity check sizes.
                ensure!(p_memsz >= p_filesz, NoExec);
                ensure!(p_memsz != 0, NoExec);

                let mut permissions = MemoryPermissions::empty();
                permissions.set(MemoryPermissions::EXECUTE, p_flags.get_bit(PF_X_BIT));
                permissions.set(MemoryPermissions::WRITE, p_flags.get_bit(PF_W_BIT));
                permissions.set(MemoryPermissions::READ, p_flags.get_bit(PF_R_BIT));

                // Oddly enough, if p_filesz is equal to p_memsz, Linux doesn't
                // zero the memory *after* mem_sz. Instead the page will just
                // containg the normal file contents. Some ELF binaries (e.g.
                // GHC) depend on this behavior. It's not clear whether this is
                // a bug in the GHC binary or intended behavior.
                if p_filesz == p_memsz {
                    p_filesz = align_up(p_filesz, 0x1000);
                    p_memsz = p_filesz;
                }

                vm.mmap_file_with_zeros(
                    Bias::Fixed(VirtAddr::try_new(base + p_vaddr)?),
                    p_filesz,
                    p_memsz,
                    file.clone(),
                    p_offset,
                    permissions,
                    false,
                    true,
                )?;

                if (p_offset..p_offset + p_filesz).contains(&e_phoff) {
                    phdr = Some(base + p_vaddr + (e_phoff - p_offset));
                }

                end = cmp::max(end, VirtAddr::new(base + p_vaddr + p_memsz));
            }
            PT_INTERP => {
                let mut raw_interpreter_path = vec![0; usize_from(p_memsz.saturating_sub(1))];
                file.pread(
                    usize_from(p_offset),
                    &mut KernelReadBuf::new(&mut raw_interpreter_path),
                    ctx,
                )?;
                interpreter_path = Some(Path::new(raw_interpreter_path)?);
            }
            _ => {}
        }
    }

    let info = LoaderInfo {
        entry: base + header.e_entry(),
        phdr,
        phentsize: e_phentsize,
        phnum: e_phnum,
        base,
        end,
        interpreter_path,
    };

    Ok(info)
}

pub struct LoaderInfo {
    pub entry: u64,
    pub phdr: Option<u64>,
    pub phentsize: u16,
    pub phnum: u16,
    pub base: u64,
    pub end: VirtAddr,
    pub interpreter_path: Option<Path>,
}
