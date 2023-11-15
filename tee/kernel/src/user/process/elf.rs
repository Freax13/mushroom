use core::{ffi::CStr, iter::from_fn};

use crate::{
    fs::node::{DynINode, FileAccessContext},
    spin::lazy::Lazy,
};
use alloc::{borrow::ToOwned, ffi::CString, vec};
use goblin::{
    elf::Elf,
    elf64::{
        header::{ET_DYN, ET_EXEC},
        program_header::PT_LOAD,
    },
};
use x86_64::{instructions::random::RdRand, VirtAddr};

use super::{
    memory::{ActiveVirtualMemory, MemoryPermissions, VmSize},
    syscall::{
        args::FileMode,
        cpu_state::{amd64::Amd64, i386::I386, CpuState},
    },
};
use crate::{
    error::{Error, Result},
    fs::{
        node::{lookup_and_resolve_node, FileSnapshot},
        path::Path,
    },
};

impl ActiveVirtualMemory<'_, '_> {
    fn load_elf(&mut self, mut base: u64, elf_bytes: FileSnapshot) -> Result<LoadInfo> {
        let elf = Elf::parse(&elf_bytes).unwrap();
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
            bits: if elf.is_64 {
                Bits::SixtyFour
            } else {
                Bits::ThirtyTwo
            },
        })
    }

    pub fn start_executable(
        &mut self,
        bytes: FileSnapshot,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        ctx: &mut FileAccessContext,
        cwd: DynINode,
    ) -> Result<CpuState> {
        match &**bytes {
            [0x7f, b'E', b'L', b'F', ..] => self.start_elf(bytes, argv, envp, ctx, cwd),
            [b'#', b'!', ..] => self.start_shebang(bytes, argv, envp, ctx, cwd),
            _ => Err(Error::no_exec(())),
        }
    }

    fn start_elf(
        &mut self,
        elf_bytes: FileSnapshot,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        ctx: &mut FileAccessContext,
        cwd: DynINode,
    ) -> Result<CpuState> {
        let elf = Elf::parse(&elf_bytes).map_err(|_| Error::inval(()))?;
        let interpreter = elf.interpreter.map(ToOwned::to_owned);

        let vm_size = if elf.is_64 {
            VmSize::FourtySeven
        } else {
            VmSize::ThirtyTwo
        };
        self.init(vm_size);

        let info = self.load_elf(0x4000_0000_0000, elf_bytes)?;
        let mut entrypoint = info.entry;

        let mut at_base = None;

        if let Some(interpreter) = interpreter {
            let path = Path::new(interpreter.into_bytes())?;
            let node = lookup_and_resolve_node(cwd.clone(), &path, ctx)?;
            if !node.mode().contains(FileMode::EXECUTE) {
                return Err(Error::acces(()));
            }
            let interpreter = node.read_snapshot()?;
            let loader_info = self.load_elf(0x5000_0000_0000, interpreter)?;
            assert_eq!(loader_info.bits, info.bits);
            entrypoint = loader_info.entry;
            at_base = Some(loader_info.base);
        }

        // Create stack.
        let len = 0x10_0000;
        let stack = self.allocate_stack(None, len)? + len;

        self.mmap_zero(
            Some(stack),
            0x4000,
            MemoryPermissions::READ | MemoryPermissions::WRITE,
        )?;

        let mut addr = stack;
        let mut write = |value: u64| match vm_size {
            VmSize::ThirtyTwo => {
                let value = u32::try_from(value).unwrap();
                self.write_bytes(addr, &value.to_ne_bytes()).unwrap();
                addr += 4u64;
            }
            VmSize::FourtySeven => {
                self.write_bytes(addr, &value.to_ne_bytes()).unwrap();
                addr += 8u64;
            }
        };

        let mut str_addr = stack + 0x800u64;
        let mut write_bytes = |value: &[u8]| {
            let addr = str_addr;
            self.write_bytes(str_addr, value)?;
            str_addr += value.len();
            Result::<_>::Ok(addr)
        };
        let mut write_str = |value: &CStr| write_bytes(value.to_bytes_with_nul());

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
        write(25); // AT_RANDOM
        write(write_bytes(&random_bytes())?.as_u64());
        write(0); // AT_NULL

        let cpu_state = match vm_size {
            VmSize::ThirtyTwo => CpuState::I386(I386::new(
                entrypoint.try_into().unwrap(),
                stack.as_u64().try_into().unwrap(),
            )),
            VmSize::FourtySeven => CpuState::Amd64(Amd64::new(entrypoint, stack.as_u64())),
        };
        Ok(cpu_state)
    }

    fn start_shebang(
        &mut self,
        bytes: FileSnapshot,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        ctx: &mut FileAccessContext,
        cwd: DynINode,
    ) -> Result<CpuState> {
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
            let Some(position) = position_res else {
                return Some(Err(Error::inval(())));
            };
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
        let node = lookup_and_resolve_node(cwd.clone(), &path, ctx)?;
        if !node.mode().contains(FileMode::EXECUTE) {
            return Err(Error::acces(()));
        }
        let interpreter = node.read_snapshot()?;

        let mut new_argv = vec![interpreter_path];
        for arg in args {
            new_argv.push(arg?);
        }
        new_argv.extend(argv.iter().map(AsRef::as_ref).map(CStr::to_owned));

        self.start_executable(interpreter, &new_argv, envp, ctx, cwd)
    }
}

#[derive(Debug)]
struct LoadInfo {
    pub phdr: Option<u64>,
    pub phentsize: u16,
    pub phnum: u16,
    pub base: u64,
    pub entry: u64,
    pub bits: Bits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bits {
    ThirtyTwo,
    SixtyFour,
}

fn random_bytes() -> [u8; 16] {
    // Generate random bytes.
    static RD_RAND: Lazy<RdRand> = Lazy::new(|| RdRand::new().unwrap());
    let mut random_iter = from_fn(|| Some(RD_RAND.get_u64()))
        .flatten()
        .flat_map(u64::to_ne_bytes);

    // Fill 16 values.
    let mut buffer = [0; 16];
    buffer.fill_with(|| random_iter.next().unwrap());
    buffer
}
