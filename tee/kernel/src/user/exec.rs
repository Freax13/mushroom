use alloc::{borrow::ToOwned, ffi::CString, vec};
use core::{ffi::CStr, iter::from_fn};

use bytemuck::{Zeroable, bytes_of_mut};
use usize_conversions::FromUsize;
use x86_64::{
    VirtAddr, align_up,
    instructions::random::RdRand,
    structures::paging::{PageSize, Size4KiB},
};

use self::elf::{ElfIdent, ElfLoaderParams};
use crate::{
    error::{Result, bail, ensure, err},
    fs::{
        fd::{FileDescriptor, KernelReadBuf, OpenFileDescription},
        node::{FileAccessContext, Link, lookup_and_resolve_link},
        path::Path,
    },
    spin::lazy::Lazy,
    user::{
        memory::{Bias, MemoryPermissions, VirtualMemory},
        process::limits::{CurrentAsLimit, CurrentStackLimit},
        syscall::{
            args::{FileMode, OpenFlags},
            cpu_state::CpuState,
            traits::Abi,
        },
    },
};

mod elf;

impl VirtualMemory {
    #[allow(clippy::too_many_arguments)]
    pub fn start_executable(
        &self,
        path: Path,
        link: Link,
        fd: &FileDescriptor,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        ctx: &mut FileAccessContext,
        cwd: Link,
        stack_limit: CurrentStackLimit,
    ) -> Result<ExecResult> {
        self.modify().map_sigreturn_trampoline();

        let mut header = [0; 4];
        fd.pread(0, &mut KernelReadBuf::new(&mut header), ctx)?;

        match header {
            elf::MAGIC => {
                let mut header = ElfIdent::zeroed();
                fd.pread(0, &mut KernelReadBuf::new(bytes_of_mut(&mut header)), ctx)?;

                match header.verify()? {
                    Abi::I386 => self.start_elf::<elf::ElfLoaderParams32>(
                        link,
                        fd,
                        argv,
                        envp,
                        ctx,
                        cwd,
                        stack_limit,
                    ),
                    Abi::Amd64 => self.start_elf::<elf::ElfLoaderParams64>(
                        link,
                        fd,
                        argv,
                        envp,
                        ctx,
                        cwd,
                        stack_limit,
                    ),
                }
            }
            [b'#', b'!', ..] => {
                self.start_shebang(path, &****fd, argv, envp, ctx, cwd, stack_limit)
            }
            _ => bail!(NoExec),
        }
    }

    #[expect(clippy::too_many_arguments)]
    fn start_elf<E>(
        &self,
        link: Link,
        file: &FileDescriptor,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        ctx: &mut FileAccessContext,
        cwd: Link,
        stack_limit: CurrentStackLimit,
    ) -> Result<ExecResult>
    where
        E: ElfLoaderParams,
    {
        let load_bias = match E::ABI {
            Abi::I386 => 0x5655_5000,
            Abi::Amd64 => 0x5555_5555_4000,
        };
        let info = elf::load_elf::<E>(file, ctx, self.modify(), load_bias)?;

        let mut entrypoint = info.entry;
        let mut at_base = None;

        if let Some(interpreter_path) = info.interpreter_path {
            let interpreter_link = lookup_and_resolve_link(cwd.clone(), &interpreter_path, ctx)?;
            ensure!(
                interpreter_link
                    .node
                    .mode()?
                    .contains(FileMode::OTHER_EXECUTE),
                Acces
            );

            let file =
                interpreter_link
                    .node
                    .open(interpreter_link.location, OpenFlags::empty(), ctx)?;
            let load_bias = match E::ABI {
                Abi::I386 => 0xf800_0000,
                Abi::Amd64 => 0x7fff_8000_0000,
            };
            let info = elf::load_elf::<E>(&file, ctx, self.modify(), load_bias)?;

            entrypoint = info.entry;
            at_base = Some(info.base);
        }

        let brk_start = info.end.align_up(Size4KiB::SIZE);
        self.modify().init_brk(brk_start);

        // Create stack.
        let len = stack_limit.get();
        let bias = Bias::Dynamic {
            abi: E::ABI,
            map_32bit: false,
        };
        let stack = self
            .modify()
            .allocate_stack(bias, len, CurrentAsLimit::INFINITE)?
            + len;

        // Sum up the number of pointer-sized values that need to be placed in
        // a contigous chunk of memory.
        let mut num_values = 0;
        num_values += 1; // argc
        num_values += argv.len(); // argv
        num_values += 1; // argv null-terminator
        num_values += envp.len(); // envp
        num_values += 1; // envp null-terminator
        num_values += MAX_NUM_AUX_VECTORS * 2; // auxv

        let pointer_size = match E::ABI {
            Abi::I386 => 4,
            Abi::Amd64 => 8,
        };
        // Calculate the first address where we can place other values (mostly
        // strings) that don't need to be in a contigous chunk.
        let start_str_addr = stack;

        let stack_base = stack - align_up(u64::from_usize(num_values) * pointer_size, 0x10);
        let mut addr = stack_base;
        let mut write = |value: u64| {
            // Double-check that the contigous values don't overlap with the string values.
            debug_assert!(addr < start_str_addr);

            match E::ABI {
                Abi::I386 => {
                    let value = u32::try_from(value).unwrap();
                    self.write_bytes(addr, &value.to_ne_bytes()).unwrap();
                }
                Abi::Amd64 => self.write_bytes(addr, &value.to_ne_bytes()).unwrap(),
            }
            addr += pointer_size;
        };

        let mut str_addr = start_str_addr;
        let write_bytes = |value: &[u8], str_addr: &mut VirtAddr| {
            // Map more memory for each new page we write to.
            for addr in (*str_addr..)
                .take(value.len())
                .filter(|addr| addr.is_aligned(0x1000u64))
            {
                self.modify().mmap_private_zero_special(
                    Bias::Fixed(addr),
                    0x1000,
                    MemoryPermissions::WRITE | MemoryPermissions::READ,
                    "stack",
                    false,
                    CurrentAsLimit::INFINITE,
                )?;
            }

            let addr = *str_addr;
            self.write_bytes(*str_addr, value)?;
            *str_addr += u64::from_usize(value.len());
            Result::<_>::Ok(addr)
        };
        let write_str = |value: &CStr, str_addr: &mut VirtAddr| {
            write_bytes(value.to_bytes_with_nul(), str_addr)
        };

        // write argc + argv.
        write(u64::from_usize(argv.len())); // argc
        for arg in argv {
            let arg = write_str(arg.as_ref(), &mut str_addr)?;
            write(arg.as_u64());
        }
        write(0);

        let mm_arg_start = start_str_addr;
        let mm_arg_end = str_addr;

        // write enpv.
        for env in envp {
            let env = write_str(env.as_ref(), &mut str_addr)?;
            write(env.as_u64());
        }
        write(0);

        let platform = match E::ABI {
            Abi::I386 => c"i686",
            Abi::Amd64 => c"x86_64",
        };
        let platform = write_str(platform, &mut str_addr)?;
        let random_bytes = write_bytes(&random_bytes(), &mut str_addr)?;

        // write auxv.
        const MAX_NUM_AUX_VECTORS: usize = 11;
        #[derive(Clone, Copy)]
        enum AuxVector {
            End = 0,
            Phdr = 3,
            Phent = 4,
            Phnum = 5,
            Pagesz = 6,
            Base = 7,
            Entry = 9,
            Platform = 15,
            ClkTck = 17,
            Secure = 23,
            Random = 25,
        }
        let aux_vectors = info
            .phdr
            .into_iter()
            .map(|phdr| (AuxVector::Phdr, phdr))
            .chain([
                (AuxVector::Phent, u64::from(info.phentsize)),
                (AuxVector::Phnum, u64::from(info.phnum)),
                (AuxVector::Pagesz, 0x1000),
                (AuxVector::Base, at_base.unwrap_or_default()),
                (AuxVector::Entry, info.entry),
                (AuxVector::Platform, platform.as_u64()),
                (AuxVector::ClkTck, 100),
                (AuxVector::Secure, 0),
                (AuxVector::Random, random_bytes.as_u64()),
                (AuxVector::End, 0),
            ]);
        assert!(aux_vectors.clone().count() <= MAX_NUM_AUX_VECTORS);
        for (vector, value) in aux_vectors {
            write(vector as u64);
            write(value);
        }

        let cs = match E::ABI {
            Abi::I386 => 0x1b,
            Abi::Amd64 => 0x2b,
        };
        let cpu_state = CpuState::new(cs, entrypoint, stack_base.as_u64());
        Ok(ExecResult {
            cpu_state,
            exe: link,
            mm_arg_start,
            mm_arg_end,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn start_shebang(
        &self,
        path: Path,
        file: &dyn OpenFileDescription,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        ctx: &mut FileAccessContext,
        cwd: Link,
        stack_limit: CurrentStackLimit,
    ) -> Result<ExecResult> {
        let mut bytes = [0; 256];
        let len = file.pread(0, &mut KernelReadBuf::new(&mut bytes), ctx)?;
        let bytes = &bytes[..len];

        // Truncate at the first newline or nul byte.
        let len = bytes
            .iter()
            .position(|&b| matches!(b, b'\n' | b'\0'))
            .unwrap_or(len);
        let bytes = &bytes[..len];

        // Strip shebang.
        let bytes = bytes.strip_prefix(b"#!").ok_or(err!(Inval))?;

        // Strip whitespaces.
        let bytes = bytes.trim_prefix(b" ").trim_suffix(b" ");

        // Split into interpreter and argv[1] (if present).
        let (interpreter, argv1) = bytes
            .split_once(|&b| b == b' ')
            .map_or((bytes, None), |(first, second)| {
                (first, Some(second.trim_prefix(b" ")))
            });

        ensure!(!interpreter.is_empty(), NoExec);

        let interpreter_path_str = CString::new(interpreter.to_vec()).unwrap();
        let interpreter_path = Path::new(interpreter_path_str.as_bytes().to_vec())?;
        let interpreter_link = lookup_and_resolve_link(cwd.clone(), &interpreter_path, ctx)?;
        ensure!(
            interpreter_link
                .node
                .mode()?
                .contains(FileMode::OTHER_EXECUTE),
            Acces
        );
        let interpreter = interpreter_link.node.open(
            interpreter_link.location.clone(),
            OpenFlags::empty(),
            ctx,
        )?;

        let mut new_argv = vec![interpreter_path_str];
        if let Some(argv1) = argv1 {
            new_argv.push(CString::new(argv1.to_vec()).unwrap());
        }
        new_argv.push(CString::new(path.as_bytes()).map_err(|_| err!(Inval))?);
        new_argv.extend(argv.iter().skip(1).map(AsRef::as_ref).map(CStr::to_owned));

        self.start_executable(
            interpreter_path,
            interpreter_link,
            &interpreter,
            &new_argv,
            envp,
            ctx,
            cwd,
            stack_limit,
        )
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

pub struct ExecResult {
    pub cpu_state: CpuState,
    pub exe: Link,
    pub mm_arg_start: VirtAddr,
    pub mm_arg_end: VirtAddr,
}
