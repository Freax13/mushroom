use alloc::sync::Arc;
use bytemuck::{bytes_of_mut, Pod, Zeroable};
use goblin::{
    elf::Elf,
    elf64::{header::ET_DYN, program_header::PT_LOAD},
};
use log::debug;
use x86_64::VirtAddr;

use super::{memory::MemoryPermissions, Process};
use crate::{error::Result, fs::node::FileSnapshot, user::process::thread::Thread};

impl Process {
    pub fn load_elf(self: &Arc<Self>, elf_bytes: FileSnapshot) -> Result<()> {
        let elf = Elf::parse(&elf_bytes).unwrap();

        assert!(elf.is_64);
        assert_eq!(elf.header.e_type, ET_DYN);

        // let base = 0x5555_5555_5000;
        let base = 0x4000_0000_0000;

        for ph in elf.program_headers.iter().filter(|ph| ph.p_type == PT_LOAD) {
            let addr = VirtAddr::new(base + ph.p_vaddr);
            let len = ph.p_filesz;
            let offset = ph.p_offset;

            let mut permissions = MemoryPermissions::empty();
            if ph.is_executable() {
                permissions |= MemoryPermissions::EXECUTE;
            }
            if ph.is_write() {
                permissions |= MemoryPermissions::WRITE;
            }
            if ph.is_read() {
                permissions |= MemoryPermissions::READ;
            }

            self.mmap_into(addr, len, offset, elf_bytes.clone(), permissions)?;

            let zero_len = ph.p_memsz - ph.p_filesz;
            if zero_len != 0 {
                self.mmap_zero(addr + ph.p_filesz, zero_len, permissions)?;
            }
        }

        let entry = base + elf.entry;

        let addr = VirtAddr::new(0x7fff_fff0_0000);
        let len = 0x1_0000;
        let stack = self.allocate_stack(addr, len)?;
        self.mmap_zero(
            stack,
            0x1000,
            MemoryPermissions::READ | MemoryPermissions::WRITE,
        );

        let mut addr = stack;
        let mut write = |value: u64| {
            self.write(addr, &value.to_ne_bytes()).unwrap();
            addr += 8u64;
        };

        write(1); // argc
        write((stack + 0x800u64).as_u64()); // argv[0]
        write(0); // argv[1]

        write((stack + 0xc00u64).as_u64()); // argv[0]
        write(0); // envp[1]

        write(3); // AT_PHDR
        write(base + elf.header.e_phoff);
        write(4); // AT_PHENT
        write(u64::from(elf.header.e_phentsize));
        write(5); // AT_PHNUM
        write(u64::from(elf.header.e_phnum));
        write(7); // AT_BASE
        write(base);
        write(9); // AT_ENTRY
        write(0x5555_ABAA_5000);
        write(0); // AT_NULL

        self.write(stack + 0x800u64, b"/bin/init\0").unwrap();
        self.write(stack + 0xc00u64, b"RUST_BACKTRACE=0\0").unwrap();

        let thread = Thread::new(self.clone(), entry, stack);
        thread.spawn();

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct Rela {
    offset: u64,
    info: u64,
    addend: u64,
}
