use core::{ffi::CStr, iter::from_fn};

use alloc::{borrow::ToOwned, ffi::CString, sync::Arc, vec};
use goblin::{
    elf::Elf,
    elf64::{
        header::{ET_DYN, ET_EXEC},
        program_header::PT_LOAD,
    },
};
use x86_64::VirtAddr;

use super::{
    memory::{ActiveVirtualMemory, MemoryPermissions},
    syscall::args::FileMode,
};
use crate::{
    error::{Error, Result},
    fs::{
        node::{lookup_and_resolve_node, File, FileSnapshot, ROOT_NODE},
        path::Path,
    },
};

impl ActiveVirtualMemory<'_, '_> {
    fn load_elf(&mut self, mut base: u64, elf_bytes: FileSnapshot) -> Result<LoadInfo> {
        let elf = Elf::parse(&elf_bytes).unwrap();
        assert!(elf.is_64);
        match elf.header.e_type {
            ET_DYN => {}
            ET_EXEC => base = 0,
            ty => unimplemented!("unimplemented type: {ty:#x}"),
        }

        let mut phdr = None;

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

            self.mmap_into(Some(addr), len, offset, elf_bytes.clone(), permissions)?;

            let zero_len = ph.p_memsz - ph.p_filesz;
            if zero_len != 0 {
                self.mmap_zero(Some(addr + ph.p_filesz), zero_len, permissions)?;
            }

            if (ph.p_offset..ph.p_offset + ph.p_filesz).contains(&elf.header.e_phoff) {
                phdr = Some(base + ph.p_vaddr + (elf.header.e_phoff - ph.p_offset));
            }
        }

        Ok(LoadInfo {
            phdr,
            phentsize: elf.header.e_phentsize,
            phnum: elf.header.e_phnum,
            base,
            entry: base + elf.entry,
        })
    }

    pub fn start_executable(
        &mut self,
        bytes: FileSnapshot,
        stack: VirtAddr,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
    ) -> Result<u64> {
        match &**bytes {
            [0x7f, b'E', b'L', b'F', ..] => self.start_elf(bytes, stack, argv, envp),
            [b'#', b'!', ..] => self.start_shebang(bytes, stack, argv, envp),
            _ => Err(Error::no_exec(())),
        }
    }

    fn start_elf(
        &mut self,
        elf_bytes: FileSnapshot,
        stack: VirtAddr,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
    ) -> Result<u64> {
        let elf = Elf::parse(&elf_bytes).map_err(|_| Error::inval(()))?;
        let interpreter = elf.interpreter.map(ToOwned::to_owned);

        let info = self.load_elf(0x4000_0000_0000, elf_bytes)?;
        let mut entrypoint = info.entry;

        let mut at_base = None;

        if let Some(interpreter) = interpreter {
            let path = Path::new(interpreter.into_bytes())?;
            let node = lookup_and_resolve_node(ROOT_NODE.clone(), &path)?;
            let file: Arc<dyn File> = node.try_into()?;
            if !file.mode().contains(FileMode::EXECUTE) {
                return Err(Error::acces(()));
            }
            let interpreter = file.read_snapshot()?;
            let info = self.load_elf(0x5000_0000_0000, interpreter)?;
            entrypoint = info.entry;
            at_base = Some(info.base);
        }

        self.mmap_zero(
            Some(stack),
            0x2000,
            MemoryPermissions::READ | MemoryPermissions::WRITE,
        )?;

        let mut addr = stack;
        let mut write = |value: u64| {
            self.write(addr, &value.to_ne_bytes()).unwrap();
            addr += 8u64;
        };

        let mut str_addr = stack + 0x800u64;
        let mut write_str = |value: &CStr| {
            let addr = str_addr;
            self.write(str_addr, value.to_bytes_with_nul())?;
            str_addr += value.to_bytes_with_nul().len();
            Result::<_>::Ok(addr)
        };

        write(u64::try_from(argv.len()).unwrap()); // argc
        for arg in argv {
            let arg = write_str(arg.as_ref())?;
            write(arg.as_u64());
        }
        write(0);

        for env in envp {
            let env = write_str(env.as_ref())?;
            write(env.as_u64());
        }
        write(0);

        if let Some(phdr) = info.phdr {
            write(3); // AT_PHDR
            write(phdr);
        }
        write(4); // AT_PHENT
        write(u64::from(info.phentsize));
        write(5); // AT_PHNUM
        write(u64::from(info.phnum));
        write(6); // AT_PAGESZ
        write(4096);
        if let Some(at_base) = at_base {
            write(7); // AT_BASE
            write(at_base);
        }
        write(9); // AT_ENTRY
        write(info.entry);
        write(0); // AT_NULL

        Ok(entrypoint)
    }

    fn start_shebang(
        &mut self,
        bytes: FileSnapshot,
        stack: VirtAddr,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
    ) -> Result<u64> {
        // Strip shebang.
        let bytes = bytes.strip_prefix(b"#!").ok_or_else(|| Error::inval(()))?;

        // Strip leading whitespaces.
        let mut bytes = bytes;
        while let Some(bs) = bytes.strip_prefix(b" ") {
            bytes = bs;
        }

        let mut bytes = Some(bytes);
        let mut args = from_fn(|| {
            let bs = bytes.as_mut()?;

            let position_res = bs.iter().position(|&b| matches!(b, b' ' | b'\n'));
            let Some(position) = position_res else { return Some(Err(Error::inval(()))); };
            let delimiter = bs[position];

            let arg = &bs[..position];
            let arg = CString::new(arg.to_vec()).unwrap();

            *bs = &bs[position..];
            if delimiter == b'\n' {
                bytes = None;
            }

            Some(Ok(arg))
        });

        let interpreter_path = args.next().ok_or_else(|| Error::inval(()))??;
        let path = Path::new(interpreter_path.as_bytes().to_vec())?;
        let node = lookup_and_resolve_node(ROOT_NODE.clone(), &path)?;
        let file: Arc<dyn File> = node.try_into()?;
        if !file.mode().contains(FileMode::EXECUTE) {
            return Err(Error::acces(()));
        }
        let interpreter = file.read_snapshot()?;

        let mut new_argv = vec![interpreter_path];
        for arg in args {
            new_argv.push(arg?);
        }
        new_argv.extend(argv.iter().map(AsRef::as_ref).map(CStr::to_owned));

        self.start_executable(interpreter, stack, &new_argv, envp)
    }
}

#[derive(Debug)]
struct LoadInfo {
    pub phdr: Option<u64>,
    pub phentsize: u16,
    pub phnum: u16,
    pub base: u64,
    pub entry: u64,
}
