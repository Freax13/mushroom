use core::{
    cmp,
    fmt::{self},
};

use bytemuck::{bytes_of, bytes_of_mut, Zeroable};

use crate::{
    error::Error,
    fs::{
        node::{create_file, lookup_node, Node, WriteonlyFile, ROOT_NODE},
        Path,
    },
    user::process::memory::MemoryPermissions,
};

use self::{
    args::{
        ArchPrctlCode, FcntlCmd, Fd, FileMode, MmapFlags, OpenFlags, Pointer, Pollfd, ProtFlags,
        RtSigprocmaskHow, SyscallArg,
    },
    traits::{
        Syscall1, Syscall2, Syscall3, Syscall4, Syscall6, SyscallHandlers, SyscallResult,
        SyscallResult::*,
    },
};

use super::{
    fd::file::ReadonlyFile,
    thread::{Sigset, Stack, StackFlags, Thread, UserspaceRegisters},
};

pub mod args;
mod traits;

impl Thread {
    pub fn execute_syscall(&mut self) -> bool {
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

        match result {
            Ok(result) => {
                let is_error = (-4095..=-1).contains(&(result as i64));
                assert!(!is_error);
                self.registers.rax = result;
                true
            }
            Err(err) => {
                self.registers.rax = (-(err as i64)) as u64;
                true
            }
            Yield => false,
        }
    }
}

const SYSCALL_HANDLERS: SyscallHandlers = {
    let mut handlers = SyscallHandlers::new();

    handlers.register(SysRead);
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

struct SysRead;

impl Syscall3 for SysRead {
    const NO: usize = 0;
    const NAME: &'static str = "read";

    type Arg0 = Fd;
    type Arg1 = Pointer;
    type Arg2 = u64;

    fn execute(thread: &mut Thread, fd: Fd, buf: Pointer, count: u64) -> SyscallResult {
        let fd = thread.fdtable().get(fd)?;

        let buf = buf.get();
        let count = usize::try_from(count).unwrap();

        let mut chunk = [0u8; 128];
        let max_chunk_len = chunk.len();
        let len = cmp::min(max_chunk_len, count);
        let chunk = &mut chunk[..len];

        let len = fd.read(chunk)?;
        let chunk = &mut chunk[..len];

        thread.virtual_memory().lock().write(buf, chunk)?;

        let len = u64::try_from(len).unwrap();

        Ok(len)
    }
}

struct SysWrite;

impl Syscall3 for SysWrite {
    const NO: usize = 1;
    const NAME: &'static str = "write";

    type Arg0 = Fd;
    type Arg1 = Pointer;
    type Arg2 = u64;

    fn execute(thread: &mut Thread, fd: Fd, buf: Pointer, count: u64) -> SyscallResult {
        let fd = thread.fdtable().get(fd)?;

        let buf = buf.get();
        let count = usize::try_from(count).unwrap();

        let mut chunk = [0u8; 128];
        let max_chunk_len = chunk.len();
        let len = cmp::min(max_chunk_len, count);
        let chunk = &mut chunk[..len];
        thread.virtual_memory().lock().read(buf, chunk)?;

        let len = fd.write(chunk)?;

        let len = u64::try_from(len).unwrap();
        Ok(len)
    }
}

struct SysOpen;

impl Syscall3 for SysOpen {
    const NO: usize = 2;
    const NAME: &'static str = "open";

    type Arg0 = Pointer;
    type Arg1 = OpenFlags;
    type Arg2 = FileMode;

    fn execute(
        thread: &mut Thread,
        filename: Pointer,
        flags: OpenFlags,
        _mode: FileMode,
    ) -> SyscallResult {
        let filename = thread
            .virtual_memory()
            .lock()
            .read_cstring(filename.get(), 4096)?;
        let filename = Path::new(&filename);

        if flags.contains(OpenFlags::WRONLY) {
            if flags.contains(OpenFlags::CREAT) {
                let dynamic_file =
                    create_file(Node::Directory(ROOT_NODE.clone()), &filename, false)?;
                let fd = thread.fdtable().insert(WriteonlyFile::new(dynamic_file));
                Ok(fd.get() as u64)
            } else {
                todo!()
            }
        } else if flags.contains(OpenFlags::RDWR) {
            todo!()
        } else {
            let node = lookup_node(Node::Directory(ROOT_NODE.clone()), &filename)?;

            let file = match node {
                Node::File(file) => file,
                Node::Directory(_) => return Err(Error::IsDir),
            };

            let snapshot = file.read_snapshot()?;
            let fd = thread.fdtable().insert(ReadonlyFile::new(snapshot));
            Ok(fd.get() as u64)
        }
    }
}

struct SysClose;

impl Syscall1 for SysClose {
    const NO: usize = 3;
    const NAME: &'static str = "close";

    type Arg0 = Fd;

    fn execute(thread: &mut Thread, fd: Fd) -> SyscallResult {
        thread.fdtable().close(fd)?;
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

    fn execute(thread: &mut Thread, fds: Pointer, nfds: u64, timeout: u64) -> SyscallResult {
        for i in 0..nfds {
            let mut pollfd = Pollfd::zeroed();
            thread
                .virtual_memory()
                .lock()
                .read(fds.get() + i * 8, bytes_of_mut(&mut pollfd))?;
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
    ) -> SyscallResult {
        if flags.contains(MmapFlags::SHARED_VALIDATE) {
            todo!("{addr} {len} {prot:?} {flags:?} {fd} {off}");
        } else if flags.contains(MmapFlags::SHARED) {
            todo!("{addr} {len} {prot:?} {flags:?} {fd} {off}");
        } else if flags.contains(MmapFlags::PRIVATE) {
            if flags.contains(MmapFlags::STACK) {
                assert!(flags.contains(MmapFlags::ANONYMOUS));
                assert_eq!(prot, ProtFlags::READ | ProtFlags::WRITE);

                assert_eq!(addr.get().as_u64(), 0);
                let addr = thread.virtual_memory().lock().allocate_stack(None, len)?;

                Ok(addr.as_u64())
            } else if flags.contains(MmapFlags::ANONYMOUS) {
                assert_eq!(addr.get().as_u64(), 0);

                let permissions = MemoryPermissions::from(prot);
                let addr = thread
                    .virtual_memory()
                    .lock()
                    .mmap_zero(None, len, permissions)?;

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

    fn execute(thread: &mut Thread, start: Pointer, len: u64, prot: ProtFlags) -> SyscallResult {
        thread
            .virtual_memory()
            .lock()
            .mprotect(start.get(), len, prot)?;
        Ok(0)
    }
}

struct SysBrk;

impl Syscall1 for SysBrk {
    const NO: usize = 12;
    const NAME: &'static str = "brk";

    type Arg0 = u64;

    fn execute(_thread: &mut Thread, brk: u64) -> SyscallResult {
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
    ) -> SyscallResult {
        let signum = usize::try_from(signum).unwrap();

        // FIXME: SIGKILL and SIGSTOP are special
        // FIXME: sigsetsize

        if !oldact.is_null() {
            let sigaction = thread.sigaction.get(signum).ok_or(Error::Inval)?;
            thread
                .virtual_memory()
                .lock()
                .write(oldact.get(), bytes_of(sigaction))?;
        }
        if !act.is_null() {
            let memory_manager = thread.virtual_memory().clone();
            let sigaction = thread.sigaction.get_mut(signum).ok_or(Error::Inval)?;
            memory_manager
                .lock()
                .read(act.get(), bytes_of_mut(sigaction))?;
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

    fn execute(thread: &mut Thread, how: u64, set: Pointer, oldset: Pointer) -> SyscallResult {
        if !oldset.is_null() {
            thread
                .virtual_memory()
                .lock()
                .write(oldset.get(), bytes_of(&thread.sigmask))?;
        }

        if !set.is_null() {
            let mut set_value = Sigset::zeroed();
            thread
                .virtual_memory()
                .lock()
                .read(set.get(), bytes_of_mut(&mut set_value))?;

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

struct SysFcntl;

impl Syscall3 for SysFcntl {
    const NO: usize = 72;
    const NAME: &'static str = "fcntl";

    type Arg0 = Fd;
    type Arg1 = FcntlCmd;
    type Arg2 = u64;

    fn execute(_thread: &mut Thread, _fd: Fd, cmd: FcntlCmd, _arg: u64) -> SyscallResult {
        match cmd {
            FcntlCmd::SetFd => {
                // FIXME: implement this
                Ok(0)
            }
        }
    }
}

struct SysSigaltstack;

impl Syscall2 for SysSigaltstack {
    const NO: usize = 131;
    const NAME: &'static str = "sigaltstack";

    type Arg0 = Pointer;
    type Arg1 = Pointer;

    fn execute(thread: &mut Thread, ss: Pointer, old_ss: Pointer) -> SyscallResult {
        if !old_ss.is_null() {
            let old_ss_value = thread.sigaltstack.unwrap_or_else(|| {
                let mut stack = Stack::zeroed();
                stack.flags |= StackFlags::DISABLE;
                stack
            });
            thread
                .virtual_memory()
                .lock()
                .write(old_ss.get(), bytes_of(&old_ss_value));
        }

        if !ss.is_null() {
            let mut ss_value = Stack::zeroed();
            thread
                .virtual_memory()
                .lock()
                .read(ss.get(), bytes_of_mut(&mut ss_value))?;

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

    fn execute(thread: &mut Thread, code: ArchPrctlCode, addr: Pointer) -> SyscallResult {
        match code {
            ArchPrctlCode::SetFs => {
                thread.registers.fs_base = addr.get().as_u64();
                Ok(0)
            }
        }
    }
}

struct SysSetTidAddress;

impl Syscall1 for SysSetTidAddress {
    const NO: usize = 218;
    const NAME: &'static str = "set_tid_address";

    type Arg0 = Pointer;

    fn execute(thread: &mut Thread, tidptr: Pointer) -> SyscallResult {
        thread.clear_child_tid = tidptr.get().as_u64();
        Ok(u64::from(thread.tid))
    }
}

struct SysExitGroup;

impl Syscall1 for SysExitGroup {
    const NO: usize = 231;
    const NAME: &'static str = "exit_group";

    type Arg0 = u64;

    fn execute(_thread: &mut Thread, error_code: u64) -> SyscallResult {
        todo!("exit: {error_code}")
    }
}
