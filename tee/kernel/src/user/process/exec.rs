use core::{cmp, ffi::CStr, iter::from_fn};

use crate::{
    error::{bail, ensure, err},
    fs::{
        fd::{FileDescriptor, OpenFileDescription},
        node::{DynINode, FileAccessContext},
    },
    spin::lazy::Lazy,
};
use alloc::{borrow::ToOwned, ffi::CString, vec};
use bytemuck::{bytes_of_mut, Zeroable};
use usize_conversions::FromUsize;
use x86_64::{
    instructions::random::RdRand,
    structures::paging::{PageSize, Size4KiB},
};

use self::elf::{ElfIdent, ElfLoaderParams};

use super::{
    memory::{Bias, MemoryPermissions, VirtualMemory},
    syscall::{
        args::{FileMode, OpenFlags},
        cpu_state::CpuState,
        traits::Abi,
    },
};
use crate::{
    error::Result,
    fs::{node::lookup_and_resolve_node, path::Path},
};

mod elf;

impl VirtualMemory {
    pub fn start_executable(
        &self,
        path: &Path,
        file: &FileDescriptor,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        ctx: &mut FileAccessContext,
        cwd: DynINode,
    ) -> Result<CpuState> {
        self.modify().map_sigreturn_trampoline();

        let mut header = [0; 4];
        file.pread(0, &mut header)?;

        match header {
            elf::MAGIC => {
                let mut header = ElfIdent::zeroed();
                file.pread(0, bytes_of_mut(&mut header))?;

                match header.verify()? {
                    Abi::I386 => {
                        self.start_elf::<elf::ElfLoaderParams32>(file, argv, envp, ctx, cwd)
                    }
                    Abi::Amd64 => {
                        self.start_elf::<elf::ElfLoaderParams64>(file, argv, envp, ctx, cwd)
                    }
                }
            }
            [b'#', b'!', ..] => self.start_shebang(path, &**file, argv, envp, ctx, cwd),
            _ => bail!(NoExec),
        }
    }

    fn start_elf<E>(
        &self,
        file: &FileDescriptor,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        ctx: &mut FileAccessContext,
        cwd: DynINode,
    ) -> Result<CpuState>
    where
        E: ElfLoaderParams,
    {
        let info = elf::load_elf::<E>(file, self.modify(), 0x2000_0000)?;

        let mut entrypoint = info.entry;
        let mut brk_start = info.end;

        let mut at_base = None;

        if let Some(interpreter_path) = info.interpreter_path {
            let node = lookup_and_resolve_node(cwd.clone(), &interpreter_path, ctx)?;
            ensure!(node.mode().contains(FileMode::EXECUTE), Acces);

            let file = node.open(OpenFlags::empty())?;
            let info = elf::load_elf::<E>(&file, self.modify(), info.base + 0x2000_0000)?;

            entrypoint = info.entry;
            brk_start = cmp::max(brk_start, info.end);
            at_base = Some(info.base);
        }

        let brk_start = brk_start.align_up(Size4KiB::SIZE);
        self.modify().init_brk(brk_start);

        // Create stack.
        let len = 0x10_0000;
        let stack = self.modify().allocate_stack(Bias::Dynamic(E::ABI), len) + len;

        self.modify().mmap_zero(
            Bias::Fixed(stack),
            0x4000,
            MemoryPermissions::READ | MemoryPermissions::WRITE,
        );

        let mut addr = stack;
        let mut write = |value: u64| match E::ABI {
            Abi::I386 => {
                let value = u32::try_from(value).unwrap();
                self.write_bytes(addr, &value.to_ne_bytes()).unwrap();
                addr += 4u64;
            }
            Abi::Amd64 => {
                self.write_bytes(addr, &value.to_ne_bytes()).unwrap();
                addr += 8u64;
            }
        };

        let mut str_addr = stack + 0x800u64;
        let mut write_bytes = |value: &[u8]| {
            let addr = str_addr;
            self.write_bytes(str_addr, value)?;
            str_addr += u64::from_usize(value.len());
            Result::<_>::Ok(addr)
        };
        let mut write_str = |value: &CStr| write_bytes(value.to_bytes_with_nul());

        write(u64::from_usize(argv.len())); // argc
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
        } else {
            write(7); // AT_BASE
            write(0);
        }
        write(9); // AT_ENTRY
        write(info.entry);
        write(25); // AT_RANDOM
        write(write_bytes(&random_bytes())?.as_u64());
        write(0); // AT_NULL

        let cs = match E::ABI {
            Abi::I386 => 0x1b,
            Abi::Amd64 => 0x2b,
        };
        let cpu_state = CpuState::new(cs, entrypoint, stack.as_u64());
        Ok(cpu_state)
    }

    fn start_shebang(
        &self,
        path: &Path,
        file: &dyn OpenFileDescription,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        ctx: &mut FileAccessContext,
        cwd: DynINode,
    ) -> Result<CpuState> {
        let mut bytes = [0; 128];
        let len = file.pread(0, &mut bytes)?;
        let bytes = &bytes[..len];

        log::debug!("{bytes:02x?}");

        // Strip shebang.
        let bytes = bytes.strip_prefix(b"#!").ok_or(err!(Inval))?;

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
                return Some(Err(err!(Inval)));
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

        let interpreter_path_str = args.next().ok_or(err!(Inval))??;
        let interpreter_path = Path::new(interpreter_path_str.as_bytes().to_vec())?;
        let node = lookup_and_resolve_node(cwd.clone(), &interpreter_path, ctx)?;
        ensure!(node.mode().contains(FileMode::EXECUTE), Acces);
        let interpreter = node.open(OpenFlags::empty())?;

        let mut new_argv = vec![interpreter_path_str];
        for arg in args {
            new_argv.push(arg?);
        }
        new_argv.push(CString::new(path.as_bytes()).map_err(|_| err!(Inval))?);
        new_argv.extend(argv.iter().skip(1).map(AsRef::as_ref).map(CStr::to_owned));

        self.start_executable(&interpreter_path, &interpreter, &new_argv, envp, ctx, cwd)
    }
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
