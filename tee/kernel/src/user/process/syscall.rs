use core::{
    cmp,
    fmt::{self, Display},
};

use bytemuck::{bytes_of, bytes_of_mut, Pod, Zeroable};
use log::warn;
use x86_64::VirtAddr;

use crate::{
    error::{Error, Result},
    fs::{
        node::{lookup_node, Node, ROOT_NODE},
        Path,
    },
    user::process::memory::MemoryPermissions,
};

use self::traits::{
    Pointer, Syscall1, Syscall2, Syscall3, Syscall4, Syscall6, SyscallArg, SyscallHandlers,
};

use super::{
    fd::file::ReadonlyFile,
    thread::{Sigset, Stack, StackFlags, Thread, UserspaceRegisters},
};

mod traits;

macro_rules! bitflags {
    (pub struct $strukt:ident {
        $(
            const $constant:ident = $expr:expr;
        )*
    }) => {
        bitflags::bitflags! {
            pub struct $strukt: u64 {
                $(
                    const $constant = $expr;
                )*
            }
        }

        impl Display for $strukt {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{self:?}")
            }
        }

        impl SyscallArg for $strukt {
            fn parse(value: u64) -> Result<Self> {
                Self::from_bits(value).ok_or(Error::Inval)
            }

            fn display(f: &mut dyn fmt::Write, value: u64) -> fmt::Result {
                let valid_bits = Self::from_bits_truncate(value);
                let invalid_bits = value & !Self::all().bits();

                write!(f, "{valid_bits}")?;
                if invalid_bits != 0 {
                    write!(f, " | {invalid_bits}")?;
                }
                Ok(())
            }
        }
    };
}

macro_rules! enum_arg {
    (pub enum $enuhm:ident {
        $(
            $variant:ident = $expr:expr,
        )*
    }) => {
        #[derive(Debug, Clone, Copy)]
        pub enum $enuhm {
            $(
                $variant = $expr,
            )*
        }

        impl Display for $enuhm {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{self:?}")
            }
        }


        impl SyscallArg for $enuhm {
            fn parse(value: u64) -> Result<Self> {
                match value {
                    $(
                        value if value == Self::$variant as u64 => Ok(Self::$variant),
                    )*
                    _ => Err(Error::Inval),
                }
            }

            fn display(f: &mut dyn fmt::Write, value: u64) -> fmt::Result {
                match Self::parse(value) {
                    Ok(value) => write!(f, "{value}"),
                    Err(_) => write!(f, "{value}"),
                }
            }
        }
    };
}

impl Thread {
    pub fn execute_syscall(&mut self) {
        let UserspaceRegisters {
            rax: syscall_no,
            rdi: arg0,
            rsi: arg1,
            rdx: arg2,
            r10: arg3,
            r8: arg4,
            r9: arg5,
            ..
        } = self.registers;

        let result = SYSCALL_HANDLERS.execute(self, syscall_no, arg0, arg1, arg2, arg3, arg4, arg5);

        let rax = match result {
            Ok(result) => {
                let is_error = (-4095..=-1).contains(&(result as i64));
                assert!(!is_error);
                result
            }
            Err(err) => (-(err as i64)) as u64,
        };
        self.registers.rax = rax;
    }
}

const SYSCALL_HANDLERS: SyscallHandlers = {
    let mut handlers = SyscallHandlers::new();

    handlers.register(SysWrite);
    handlers.register(SysOpen);
    handlers.register(SysClose);
    handlers.register(SysPoll);
    handlers.register(SysMmap);
    handlers.register(SysMprotect);
    handlers.register(SysBrk);
    handlers.register(SysRtSigaction);
    handlers.register(SysRtSigprocmask);
    handlers.register(SysFcntl);
    handlers.register(SysSigaltstack);
    handlers.register(SysArchPrctl);
    handlers.register(SysSetTidAddress);
    handlers.register(SysExitGroup);

    handlers
};

struct SysWrite;

impl Syscall3 for SysWrite {
    const NO: usize = 1;
    const NAME: &'static str = "write";

    type Arg0 = Fd;
    type Arg1 = Pointer;
    type Arg2 = u64;

    fn execute(thread: &mut Thread, fd: Fd, buf: Pointer, count: u64) -> Result<u64> {
        let fd = thread.process().fdtable().get(fd)?;

        let buf = buf.get();
        let count = usize::try_from(count).unwrap();

        let mut chunk = [0u8; 128];
        let max_chunk_len = chunk.len();
        let len = cmp::min(max_chunk_len, count);
        let chunk = &mut chunk[..len];
        thread.process().read(buf, chunk)?;

        fd.write(chunk)
    }
}

struct SysOpen;

impl Syscall3 for SysOpen {
    const NO: usize = 2;
    const NAME: &'static str = "open";

    type Arg0 = Pointer;
    type Arg1 = OpenFlags;
    type Arg2 = u64;

    fn execute(thread: &mut Thread, filename: Pointer, flags: OpenFlags, mode: u64) -> Result<u64> {
        if mode != 0 {
            todo!();
        }

        let filename = thread.process().read_cstring(filename.get(), 4096)?;
        let filename = Path::new(&filename);

        let node = lookup_node(Node::Directory(ROOT_NODE.clone()), &filename)?;

        let file = match node {
            Node::File(file) => file,
            Node::Directory(_) => return Err(Error::IsDir),
        };

        if flags.contains(OpenFlags::WRONLY) {
            todo!()
        } else if flags.contains(OpenFlags::RDWR) {
            todo!()
        } else {
            let snapshot = file.read_snapshot()?;
            let fd = thread
                .process()
                .fdtable()
                .insert(ReadonlyFile::new(snapshot));
            Ok(fd.get() as u64)
        }
    }
}

struct SysClose;

impl Syscall1 for SysClose {
    const NO: usize = 3;
    const NAME: &'static str = "close";

    type Arg0 = Fd;

    fn execute(thread: &mut Thread, fd: Fd) -> Result<u64> {
        thread.process().fdtable().close(fd)?;
        Ok(0)
    }
}

struct SysPoll;

impl Syscall3 for SysPoll {
    const NO: usize = 7;
    const NAME: &'static str = "poll";

    type Arg0 = Pointer;
    type Arg1 = u64;
    type Arg2 = u64;

    fn execute(thread: &mut Thread, fds: Pointer, nfds: u64, timeout: u64) -> Result<u64> {
        let process = thread.process();
        for i in 0..nfds {
            let mut pollfd = Pollfd::zeroed();
            process.read(fds.get() + i * 8, bytes_of_mut(&mut pollfd))?;
        }

        if timeout != 0 {
            todo!()
        }

        Ok(0)
    }
}

struct SysMmap;

impl Syscall6 for SysMmap {
    const NO: usize = 9;
    const NAME: &'static str = "mmap";

    type Arg0 = Pointer;
    type Arg1 = u64;
    type Arg2 = ProtFlags;
    type Arg3 = MmapFlags;
    type Arg4 = u64;
    type Arg5 = u64;

    fn execute(
        thread: &mut Thread,
        addr: Pointer,
        len: u64,
        prot: ProtFlags,
        flags: MmapFlags,
        fd: u64,
        off: u64,
    ) -> Result<u64> {
        if flags.contains(MmapFlags::SHARED_VALIDATE) {
            todo!("{addr} {len} {prot:?} {flags:?} {fd} {off}");
        } else if flags.contains(MmapFlags::SHARED) {
            todo!("{addr} {len} {prot:?} {flags:?} {fd} {off}");
        } else if flags.contains(MmapFlags::PRIVATE) {
            if flags.contains(MmapFlags::STACK) {
                assert!(flags.contains(MmapFlags::ANONYMOUS));
                assert_eq!(prot, ProtFlags::READ | ProtFlags::WRITE);

                warn!("FIXME: generate stack address dynamically");
                assert_eq!(addr.get().as_u64(), 0);
                let addr = VirtAddr::new(0x7fff_ffd0_0000);
                thread.process().allocate_stack(addr, len);
                let stack = addr + len;

                Ok(stack.as_u64())
            } else if flags.contains(MmapFlags::ANONYMOUS) {
                warn!("FIXME: generate anonymous mapping address dynamically");
                assert_eq!(addr.get().as_u64(), 0);
                let addr = VirtAddr::new(0x7fff_ffe0_0000);

                let mut permissions = MemoryPermissions::empty();
                permissions.set(MemoryPermissions::READ, prot.contains(ProtFlags::READ));
                permissions.set(MemoryPermissions::WRITE, prot.contains(ProtFlags::WRITE));
                permissions.set(MemoryPermissions::EXECUTE, prot.contains(ProtFlags::EXEC));

                thread.process().mmap_zero(addr, len, permissions);

                Ok(addr.as_u64())
            } else {
                todo!("{addr} {len} {prot:?} {flags:?} {fd} {off}");
            }
        } else {
            return Err(Error::Inval);
        }
    }
}

struct SysMprotect;

impl Syscall3 for SysMprotect {
    const NO: usize = 10;
    const NAME: &'static str = "mprotect";

    type Arg0 = Pointer;
    type Arg1 = u64;
    type Arg2 = ProtFlags;

    fn execute(_thread: &mut Thread, start: Pointer, len: u64, prot: ProtFlags) -> Result<u64> {
        warn!("FIXME: implement mprotect({start}, {len:#x}, {prot})");
        Ok(0)
    }
}

struct SysBrk;

impl Syscall1 for SysBrk {
    const NO: usize = 12;
    const NAME: &'static str = "brk";

    type Arg0 = u64;

    fn execute(_thread: &mut Thread, brk: u64) -> Result<u64> {
        if brk == 0 || brk == 0x1000 {
            return Ok(0);
        }

        return Err(Error::NoMem);
    }
}

struct SysRtSigaction;

impl Syscall4 for SysRtSigaction {
    const NO: usize = 13;
    const NAME: &'static str = "rt_sigaction";

    type Arg0 = u64;
    type Arg1 = Pointer;
    type Arg2 = Pointer;
    type Arg3 = u64;

    fn execute(
        thread: &mut Thread,
        signum: u64,
        act: Pointer,
        oldact: Pointer,
        _sigsetsize: u64,
    ) -> Result<u64> {
        let signum = usize::try_from(signum).unwrap();

        // FIXME: SIGKILL and SIGSTOP are special
        // FIXME: sigsetsize

        let process = thread.process().clone();

        if !oldact.is_null() {
            let sigaction = thread.sigaction.get(signum).ok_or(Error::Inval)?;
            process.write(oldact.get(), bytes_of(sigaction))?;
        }
        if !act.is_null() {
            let sigaction = thread.sigaction.get_mut(signum).ok_or(Error::Inval)?;
            process.read(act.get(), bytes_of_mut(sigaction))?;
        }

        Ok(0)
    }
}

struct SysRtSigprocmask;

impl Syscall3 for SysRtSigprocmask {
    const NO: usize = 14;
    const NAME: &'static str = "rt_sigprocmask";

    type Arg0 = u64;
    type Arg1 = Pointer;
    type Arg2 = Pointer;

    fn execute(thread: &mut Thread, how: u64, set: Pointer, oldset: Pointer) -> Result<u64> {
        let process = thread.process().clone();

        if !oldset.is_null() {
            process.write(oldset.get(), bytes_of(&thread.sigmask))?;
        }

        if !set.is_null() {
            let mut set_value = Sigset::zeroed();
            process.read(set.get(), bytes_of_mut(&mut set_value))?;

            let how = RtSigprocmaskHow::parse(how)?;
            match how {
                RtSigprocmaskHow::Block => thread.sigmask |= set_value,
                RtSigprocmaskHow::Unblock => thread.sigmask &= !set_value,
                RtSigprocmaskHow::SetMask => thread.sigmask = set_value,
            }
        }

        Ok(0)
    }

    fn display(f: &mut dyn fmt::Write, how: u64, set: u64, oldset: u64) -> fmt::Result {
        write!(f, "{}(", <Self as Syscall3>::NAME)?;
        if set == 0 {
            write!(f, "ignored")?;
        } else {
            RtSigprocmaskHow::display(f, how)?;
        }
        write!(f, ", ")?;
        Pointer::display(f, set)?;
        write!(f, ", ")?;
        Pointer::display(f, oldset)?;
        write!(f, ")")
    }
}

enum_arg! {
    pub enum RtSigprocmaskHow {
        Block = 0,
        Unblock = 1,
        SetMask = 2,
    }
}

struct SysFcntl;

impl Syscall3 for SysFcntl {
    const NO: usize = 72;
    const NAME: &'static str = "fcntl";

    type Arg0 = Fd;
    type Arg1 = FcntlCmd;
    type Arg2 = u64;

    fn execute(_thread: &mut Thread, _fd: Fd, cmd: FcntlCmd, _arg: u64) -> Result<u64> {
        match cmd {
            FcntlCmd::SetFd => {
                // FIXME: implement this
                Ok(0)
            }
        }
    }
}

enum_arg! {
    pub enum FcntlCmd {
        SetFd = 2,
    }
}

struct SysSigaltstack;

impl Syscall2 for SysSigaltstack {
    const NO: usize = 131;
    const NAME: &'static str = "sigaltstack";

    type Arg0 = Pointer;
    type Arg1 = Pointer;

    fn execute(thread: &mut Thread, ss: Pointer, old_ss: Pointer) -> Result<u64> {
        let process = thread.process().clone();

        if !old_ss.is_null() {
            let old_ss_value = thread.sigaltstack.unwrap_or_else(|| {
                let mut stack = Stack::zeroed();
                stack.flags |= StackFlags::DISABLE;
                stack
            });
            process.write(old_ss.get(), bytes_of(&old_ss_value));
        }

        if !ss.is_null() {
            let mut ss_value = Stack::zeroed();
            process.read(ss.get(), bytes_of_mut(&mut ss_value))?;

            let allowed_flags = StackFlags::AUTODISARM;
            if !allowed_flags.contains(ss_value.flags) {
                return Err(Error::Inval);
            }

            thread.sigaltstack = Some(ss_value);
        }

        Ok(0)
    }
}

struct SysArchPrctl;

impl Syscall2 for SysArchPrctl {
    const NO: usize = 158;
    const NAME: &'static str = "arch_prctl";

    type Arg0 = ArchPrctlCode;
    type Arg1 = Pointer;

    fn execute(thread: &mut Thread, code: ArchPrctlCode, addr: Pointer) -> Result<u64> {
        match code {
            ArchPrctlCode::SetFs => {
                thread.registers.fs_base = addr.get().as_u64();
                Ok(0)
            }
        }
    }
}

enum_arg! {
    pub enum ArchPrctlCode {
        SetFs = 0x1002,
    }
}

struct SysSetTidAddress;

impl Syscall1 for SysSetTidAddress {
    const NO: usize = 218;
    const NAME: &'static str = "set_tid_address";

    type Arg0 = Pointer;

    fn execute(thread: &mut Thread, tidptr: Pointer) -> Result<u64> {
        thread.clear_child_tid = tidptr.get().as_u64();
        Ok(u64::from(thread.tid))
    }
}

struct SysExitGroup;

impl Syscall1 for SysExitGroup {
    const NO: usize = 231;
    const NAME: &'static str = "exit_group";

    type Arg0 = u64;

    fn execute(_thread: &mut Thread, error_code: u64) -> Result<u64> {
        todo!("exit: {error_code}")
    }
}

bitflags! {
    pub struct OpenFlags {
        const WRONLY = 1 << 0;
        const RDWR = 1 << 1;
        const SYNC = 1 << 19;
    }
}

bitflags! {
    pub struct ProtFlags {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC = 1 << 2;
    }
}

bitflags! {
    pub struct MmapFlags {
        const SHARED = 1 << 0;
        const PRIVATE = 1 << 1;
        const SHARED_VALIDATE = 1 << 0 | 1 << 1;
        const ANONYMOUS = 1 << 5;
        const STACK = 1 << 17;
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct Pollfd {
    fd: i32,
    events: u16,
    revents: u16,
}

#[derive(Clone, Copy)]
pub struct Fd(i32);

impl Fd {
    pub fn new(value: i32) -> Self {
        Self(value)
    }

    pub fn get(self) -> i32 {
        self.0
    }
}

impl Display for Fd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl SyscallArg for Fd {
    fn parse(value: u64) -> Result<Self> {
        match i32::try_from(value) {
            Ok(fd) if fd >= 0 => Ok(Self(fd)),
            _ => Err(Error::BadF),
        }
    }

    fn display(f: &mut dyn fmt::Write, value: u64) -> fmt::Result {
        match Self::parse(value) {
            Ok(fd) => write!(f, "{fd}"),
            Err(_) => write!(f, "{value} (invalid fd)"),
        }
    }
}
