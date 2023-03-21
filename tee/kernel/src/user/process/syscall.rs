use core::{
    cmp,
    fmt::{self},
    num::NonZeroU32,
};

use alloc::{sync::Arc, vec::Vec};
use bytemuck::{bytes_of, bytes_of_mut, Zeroable};
use x86_64::VirtAddr;

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
        ArchPrctlCode, CloneFlags, FcntlCmd, FdNum, FileMode, FutexOp, FutexOpWithFlags, MmapFlags,
        OpenFlags, Pipe2Flags, Pointer, Pollfd, ProtFlags, RtSigprocmaskHow, SyscallArg,
        WaitOptions,
    },
    traits::{
        Syscall0, Syscall1, Syscall2, Syscall3, Syscall4, Syscall5, Syscall6, SyscallHandlers,
        SyscallResult, SyscallResult::*,
    },
};

use super::{
    fd::{file::ReadonlyFile, pipe, FileDescriptorTable},
    memory::VirtualMemoryActivator,
    thread::{Sigset, Stack, StackFlags, Thread, UserspaceRegisters, THREADS},
    Process,
};

pub mod args;
mod traits;

impl Thread {
    /// Returns true if the thread should continue to run.
    pub fn execute_syscall(&mut self, vm_activator: &mut VirtualMemoryActivator) -> bool {
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

        let result = SYSCALL_HANDLERS.execute(
            self,
            vm_activator,
            syscall_no,
            arg0,
            arg1,
            arg2,
            arg3,
            arg4,
            arg5,
        );

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

    /// Execute the exit syscall.
    pub fn exit(&mut self, vm_activator: &mut VirtualMemoryActivator, status: u8) {
        <SysExit as Syscall1>::execute(self, vm_activator, u64::from(status));
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
    handlers.register(SysGetpid);
    handlers.register(SysClone);
    handlers.register(SysExecve);
    handlers.register(SysExit);
    handlers.register(SysWait4);
    handlers.register(SysFcntl);
    handlers.register(SysSigaltstack);
    handlers.register(SysArchPrctl);
    handlers.register(SysGettid);
    handlers.register(SysFutex);
    handlers.register(SysSetTidAddress);
    handlers.register(SysExitGroup);
    handlers.register(SysPipe2);

    handlers
};

struct SysRead;

impl Syscall3 for SysRead {
    const NO: usize = 0;
    const NAME: &'static str = "read";

    type Arg0 = FdNum;
    type Arg1 = Pointer;
    type Arg2 = u64;

    fn execute(
        thread: &mut Thread,
        vm_activator: &mut VirtualMemoryActivator,
        fd_num: FdNum,
        buf: Pointer,
        count: u64,
    ) -> SyscallResult {
        let fd = thread.fdtable().get(fd_num)?;

        let buf = buf.get();
        let count = usize::try_from(count).unwrap();

        let mut chunk = [0u8; 128];
        let max_chunk_len = chunk.len();
        let len = cmp::min(max_chunk_len, count);
        let chunk = &mut chunk[..len];

        let len = fd.read(chunk)?;
        let chunk = &mut chunk[..len];

        vm_activator.activate(thread.virtual_memory(), |vm| vm.write(buf, &chunk))?;

        let len = u64::try_from(len).unwrap();

        Ok(len)
    }
}

struct SysWrite;

impl Syscall3 for SysWrite {
    const NO: usize = 1;
    const NAME: &'static str = "write";

    type Arg0 = FdNum;
    type Arg1 = Pointer;
    type Arg2 = u64;

    fn execute(
        thread: &mut Thread,
        vm_activator: &mut VirtualMemoryActivator,
        fd_num: FdNum,
        buf: Pointer,
        count: u64,
    ) -> SyscallResult {
        let fd = thread.fdtable().get(fd_num)?;

        let buf = buf.get();
        let count = usize::try_from(count).unwrap();

        let mut chunk = [0u8; 128];
        let max_chunk_len = chunk.len();
        let len = cmp::min(max_chunk_len, count);
        let chunk = &mut chunk[..len];
        vm_activator.activate(thread.virtual_memory(), |vm| vm.read(buf, chunk))?;

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
        vm_activator: &mut VirtualMemoryActivator,
        filename: Pointer,
        flags: OpenFlags,
        _mode: FileMode,
    ) -> SyscallResult {
        let filename = vm_activator.activate(thread.virtual_memory(), |vm| {
            vm.read_cstring(filename.get(), 4096)
        })?;
        let filename = Path::new(filename.as_bytes());

        if flags.contains(OpenFlags::WRONLY) {
            if flags.contains(OpenFlags::CREAT) {
                let dynamic_file =
                    create_file(Node::Directory(ROOT_NODE.clone()), &filename, false)?;
                let fd_num = thread.fdtable().insert(WriteonlyFile::new(dynamic_file));
                Ok(fd_num.get() as u64)
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
            let fd_num = thread.fdtable().insert(ReadonlyFile::new(snapshot));
            Ok(fd_num.get() as u64)
        }
    }
}

struct SysClose;

impl Syscall1 for SysClose {
    const NO: usize = 3;
    const NAME: &'static str = "close";

    type Arg0 = FdNum;

    fn execute(
        thread: &mut Thread,
        _vm_activator: &mut VirtualMemoryActivator,
        fd_num: FdNum,
    ) -> SyscallResult {
        thread.fdtable().close(fd_num)?;
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

    fn execute(
        thread: &mut Thread,
        vm_activator: &mut VirtualMemoryActivator,
        fds: Pointer,
        nfds: u64,
        timeout: u64,
    ) -> SyscallResult {
        vm_activator.activate(thread.virtual_memory(), |vm| {
            for i in 0..nfds {
                let mut pollfd = Pollfd::zeroed();
                vm.read(fds.get() + i * 8, bytes_of_mut(&mut pollfd))?;
            }
            Result::Ok(())
        })?;

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
        vm_activator: &mut VirtualMemoryActivator,
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
                let addr = vm_activator
                    .activate(thread.virtual_memory(), |vm| vm.allocate_stack(None, len))?;

                Ok(addr.as_u64())
            } else if flags.contains(MmapFlags::ANONYMOUS) {
                assert_eq!(addr.get().as_u64(), 0);

                let permissions = MemoryPermissions::from(prot);
                let addr = vm_activator.activate(thread.virtual_memory(), |vm| {
                    vm.mmap_zero(None, len, permissions)
                })?;

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

    fn execute(
        thread: &mut Thread,
        vm_activator: &mut VirtualMemoryActivator,
        start: Pointer,
        len: u64,
        prot: ProtFlags,
    ) -> SyscallResult {
        vm_activator.activate(thread.virtual_memory(), |vm| {
            vm.mprotect(start.get(), len, prot)
        })?;
        Ok(0)
    }
}

struct SysBrk;

impl Syscall1 for SysBrk {
    const NO: usize = 12;
    const NAME: &'static str = "brk";

    type Arg0 = u64;

    fn execute(
        _thread: &mut Thread,
        _vm_activator: &mut VirtualMemoryActivator,
        brk: u64,
    ) -> SyscallResult {
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
        vm_activator: &mut VirtualMemoryActivator,
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
            vm_activator.activate(thread.virtual_memory(), |vm| {
                vm.write(oldact.get(), bytes_of(sigaction))
            })?;
        }
        if !act.is_null() {
            let virtual_memory = thread.virtual_memory().clone();
            let sigaction = thread.sigaction.get_mut(signum).ok_or(Error::Inval)?;
            vm_activator.activate(&virtual_memory, |vm| {
                vm.read(act.get(), bytes_of_mut(sigaction))
            })?;
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

    fn execute(
        thread: &mut Thread,
        vm_activator: &mut VirtualMemoryActivator,
        how: u64,
        set: Pointer,
        oldset: Pointer,
    ) -> SyscallResult {
        if !oldset.is_null() {
            vm_activator.activate(thread.virtual_memory(), |vm| {
                vm.write(oldset.get(), bytes_of(&thread.sigmask))
            })?;
        }

        if !set.is_null() {
            let mut set_value = Sigset::zeroed();
            vm_activator.activate(thread.virtual_memory(), |vm| {
                vm.read(set.get(), bytes_of_mut(&mut set_value))
            })?;

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

struct SysGetpid;

impl Syscall0 for SysGetpid {
    const NO: usize = 39;
    const NAME: &'static str = "getpid";

    fn execute(thread: &mut Thread, _vm_activator: &mut VirtualMemoryActivator) -> SyscallResult {
        let pid = thread.process().pid;
        Ok(u64::from(pid))
    }
}

struct SysClone;

impl Syscall5 for SysClone {
    const NO: usize = 56;
    const NAME: &'static str = "clone";

    type Arg0 = CloneFlags;
    type Arg1 = Pointer;
    type Arg2 = Pointer;
    type Arg3 = Pointer;
    type Arg4 = u64;

    fn execute(
        thread: &mut Thread,
        vm_activator: &mut VirtualMemoryActivator,
        flags: CloneFlags,
        stack: Pointer,
        parent_tid: Pointer,
        child_tid: Pointer,
        tls: u64,
    ) -> SyscallResult {
        let new_process = if flags.contains(CloneFlags::THREAD) {
            None
        } else {
            Some(Arc::new(Process::new(thread.tid)))
        };

        let new_virtual_memory = if flags.contains(CloneFlags::VM) {
            None
        } else {
            todo!()
        };

        let new_fdtable = if flags.contains(CloneFlags::FILES) {
            None
        } else {
            Some(Arc::new(FileDescriptorTable::new()))
        };

        let new_clear_child_tid = if flags.contains(CloneFlags::CHILD_CLEARTID) {
            Some(child_tid.get())
        } else {
            None
        };

        let new_tls = if flags.contains(CloneFlags::SETTLS) {
            Some(tls)
        } else {
            None
        };

        let new_thread = thread.clone(
            new_process,
            new_virtual_memory,
            new_fdtable,
            stack.get(),
            new_clear_child_tid,
            new_tls,
        );
        let tid = new_thread.tid;

        if flags.contains(CloneFlags::PARENT_SETTID) {
            vm_activator.activate(thread.virtual_memory(), |vm| {
                vm.write(parent_tid.get(), &tid.to_ne_bytes())
            })?;
        }

        if flags.contains(CloneFlags::CHILD_SETTID) {
            vm_activator.activate(new_thread.virtual_memory(), |vm| {
                vm.write(child_tid.get(), &tid.to_ne_bytes())
            })?;
        }

        new_thread.spawn();

        Ok(u64::from(tid))
    }
}

struct SysExecve;

impl Syscall3 for SysExecve {
    const NO: usize = 59;
    const NAME: &'static str = "execve";

    type Arg0 = Pointer;
    type Arg1 = Pointer;
    type Arg2 = Pointer;

    fn execute(
        thread: &mut Thread,
        vm_activator: &mut VirtualMemoryActivator,
        pathname: Pointer,
        argv: Pointer,
        envp: Pointer,
    ) -> SyscallResult {
        let (pathname, args, envs) = vm_activator.activate(thread.virtual_memory(), |vm| {
            let pathname = vm.read_cstring(pathname.get(), 0x1000)?;

            let mut args = Vec::new();
            for i in 0u64.. {
                let argpp = argv.get() + i * 8;
                let mut argp = 0u64;
                vm.read(argpp, bytes_of_mut(&mut argp))?;
                if argp == 0 {
                    break;
                }
                let argp = VirtAddr::try_new(argp).map_err(|_| Error::Fault)?;
                args.push(vm.read_cstring(argp, 0x1000)?);
            }

            let mut envs = Vec::new();
            for i in 0u64.. {
                let envpp = envp.get() + i * 8;
                let mut envp = 0u64;
                vm.read(envpp, bytes_of_mut(&mut envp))?;
                if envp == 0 {
                    break;
                }
                let envp = VirtAddr::try_new(envp).map_err(|_| Error::Fault)?;
                envs.push(vm.read_cstring(envp, 0x1000)?);
            }

            Result::Ok((pathname, args, envs))
        })?;

        let path = Path::new(pathname.as_bytes());
        Process::create(thread.tid, &path, &args, &envs, vm_activator)?;

        Yield
    }
}

struct SysExit;

impl Syscall1 for SysExit {
    const NO: usize = 60;
    const NAME: &'static str = "exit";

    type Arg0 = u64;

    fn execute(
        thread: &mut Thread,
        vm_activator: &mut VirtualMemoryActivator,
        _status: Self::Arg0,
    ) -> SyscallResult {
        if thread.clear_child_tid != 0 {
            let clear_child_tid = VirtAddr::new(thread.clear_child_tid);
            vm_activator.activate(thread.virtual_memory(), |vm| {
                vm.write(clear_child_tid, &0u32.to_ne_bytes())
            })?;

            thread.process().futexes.wake(clear_child_tid, 1, None);
        }

        THREADS.lock().remove(&thread.tid);
        Yield
    }
}

struct SysWait4;

impl Syscall4 for SysWait4 {
    const NO: usize = 61;
    const NAME: &'static str = "wait4";

    type Arg0 = u64;
    type Arg1 = Pointer;
    type Arg2 = WaitOptions;
    type Arg3 = Pointer;

    fn execute(
        _thread: &mut Thread,
        _vm_activator: &mut VirtualMemoryActivator,
        _pid: u64,
        _wstatus: Pointer,
        _options: WaitOptions,
        _rusage: Pointer,
    ) -> SyscallResult {
        Yield
    }
}

struct SysFcntl;

impl Syscall3 for SysFcntl {
    const NO: usize = 72;
    const NAME: &'static str = "fcntl";

    type Arg0 = FdNum;
    type Arg1 = FcntlCmd;
    type Arg2 = u64;

    fn execute(
        _thread: &mut Thread,
        _vm_activator: &mut VirtualMemoryActivator,
        _fd_num: FdNum,
        cmd: FcntlCmd,
        _arg: u64,
    ) -> SyscallResult {
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

    fn execute(
        thread: &mut Thread,
        vm_activator: &mut VirtualMemoryActivator,
        ss: Pointer,
        old_ss: Pointer,
    ) -> SyscallResult {
        if !old_ss.is_null() {
            let old_ss_value = thread.sigaltstack.unwrap_or_else(|| {
                let mut stack = Stack::zeroed();
                stack.flags |= StackFlags::DISABLE;
                stack
            });

            vm_activator.activate(thread.virtual_memory(), |vm| {
                vm.write(old_ss.get(), bytes_of(&old_ss_value))
            })?;
        }

        if !ss.is_null() {
            let mut ss_value = Stack::zeroed();
            vm_activator.activate(thread.virtual_memory(), |vm| {
                vm.read(ss.get(), bytes_of_mut(&mut ss_value))
            })?;

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

    fn execute(
        thread: &mut Thread,
        _vm_activator: &mut VirtualMemoryActivator,
        code: ArchPrctlCode,
        addr: Pointer,
    ) -> SyscallResult {
        match code {
            ArchPrctlCode::SetFs => {
                thread.registers.fs_base = addr.get().as_u64();
                Ok(0)
            }
        }
    }
}

struct SysGettid;

impl Syscall0 for SysGettid {
    const NO: usize = 186;
    const NAME: &'static str = "gettid";

    fn execute(thread: &mut Thread, _vm_activator: &mut VirtualMemoryActivator) -> SyscallResult {
        let tid = thread.tid;
        Ok(u64::from(tid))
    }
}

struct SysFutex;

impl Syscall6 for SysFutex {
    const NO: usize = 202;
    const NAME: &'static str = "futex";

    type Arg0 = Pointer;
    type Arg1 = FutexOpWithFlags;
    type Arg2 = u32;
    type Arg3 = u64;
    type Arg4 = Pointer;
    type Arg5 = u64;

    fn execute(
        thread: &mut Thread,
        vm_activator: &mut VirtualMemoryActivator,
        uaddr: Pointer,
        op: FutexOpWithFlags,
        val: u32,
        _utime: u64,
        _uaddr2: Pointer,
        val3: u64,
    ) -> SyscallResult {
        match op.op {
            FutexOp::Wait => {
                assert_eq!(_utime, 0);

                vm_activator.activate(&thread.virtual_memory(), |vm| {
                    thread
                        .process()
                        .futexes
                        .wait(thread.tid, uaddr.get(), val, None, vm)
                })?;

                Yield
            }
            FutexOp::Wake => {
                let woken = thread.process().futexes.wake(uaddr.get(), val, None);
                Ok(u64::from(woken))
            }
            FutexOp::Fd => Err(Error::NoSys),
            FutexOp::REQUEUE => Err(Error::NoSys),
            FutexOp::CmpRequeue => Err(Error::NoSys),
            FutexOp::WakeOp => Err(Error::NoSys),
            FutexOp::LockPi => Err(Error::NoSys),
            FutexOp::UnlockPi => Err(Error::NoSys),
            FutexOp::TrylockPi => Err(Error::NoSys),
            FutexOp::WaitBitset => {
                assert_eq!(_utime, 0);
                let bitset = NonZeroU32::new(val3 as u32).ok_or(Error::Inval)?;

                vm_activator.activate(&thread.virtual_memory(), |vm| {
                    thread
                        .process()
                        .futexes
                        .wait(thread.tid, uaddr.get(), val, Some(bitset), vm)
                })?;

                Yield
            }
            FutexOp::WakeBitset => {
                let bitset = NonZeroU32::new(val3 as u32).ok_or(Error::Inval)?;
                let woken = thread
                    .process()
                    .futexes
                    .wake(uaddr.get(), val, Some(bitset));
                Ok(u64::from(woken))
            }
            FutexOp::WaitRequeuePi => Err(Error::NoSys),
            FutexOp::CmpRequeuePi => Err(Error::NoSys),
            FutexOp::LockPi2 => Err(Error::NoSys),
        }
    }
}

struct SysSetTidAddress;

impl Syscall1 for SysSetTidAddress {
    const NO: usize = 218;
    const NAME: &'static str = "set_tid_address";

    type Arg0 = Pointer;

    fn execute(
        thread: &mut Thread,
        _vm_activator: &mut VirtualMemoryActivator,
        tidptr: Pointer,
    ) -> SyscallResult {
        thread.clear_child_tid = tidptr.get().as_u64();
        Ok(u64::from(thread.tid))
    }
}

struct SysExitGroup;

impl Syscall1 for SysExitGroup {
    const NO: usize = 231;
    const NAME: &'static str = "exit_group";

    type Arg0 = u64;

    fn execute(
        thread: &mut Thread,
        vm_activator: &mut VirtualMemoryActivator,
        status: u64,
    ) -> SyscallResult {
        let status = thread.process().exit(status as u8);
        <SysExit as Syscall1>::execute(thread, vm_activator, u64::from(status))
    }
}

struct SysPipe2;

impl Syscall2 for SysPipe2 {
    const NO: usize = 293;
    const NAME: &'static str = "pipe2";

    type Arg0 = Pointer;
    type Arg1 = Pipe2Flags;

    fn execute(
        thread: &mut Thread,
        vm_activator: &mut VirtualMemoryActivator,
        pipefd: Pointer,
        flags: Pipe2Flags,
    ) -> SyscallResult {
        if flags != Pipe2Flags::CLOEXEC {
            todo!()
        }

        let (read_half, write_half) = pipe::new();

        let fdtable = thread.fdtable();
        let read_half = fdtable.insert(read_half);
        let write_half = fdtable.insert(write_half);

        let mut bytes = [0; 8];
        bytes[0..4].copy_from_slice(&read_half.get().to_ne_bytes());
        bytes[4..8].copy_from_slice(&write_half.get().to_ne_bytes());
        vm_activator.activate(thread.virtual_memory(), |vm| vm.write(pipefd.get(), &bytes))?;

        Ok(0)
    }
}
