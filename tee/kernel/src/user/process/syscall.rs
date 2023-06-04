use core::{
    cmp,
    fmt::{self},
    num::NonZeroU32,
};

use alloc::{sync::Arc, vec::Vec};
use bytemuck::{bytes_of, bytes_of_mut, Zeroable};
use kernel_macros::syscall;
use x86_64::VirtAddr;

use crate::{
    error::Error,
    fs::{
        node::{create_file, lookup_node, Node, ROOT_NODE},
        Path,
    },
    user::process::memory::MemoryPermissions,
};

use self::{
    args::{
        ArchPrctlCode, CloneFlags, CopyFileRangeFlags, FcntlCmd, FdNum, FileMode, FutexOp,
        FutexOpWithFlags, MmapFlags, OpenFlags, Pipe2Flags, Pointer, Pollfd, ProtFlags,
        RtSigprocmaskHow, SyscallArg, WaitOptions,
    },
    traits::{
        Syscall0, Syscall1, Syscall2, Syscall3, Syscall4, Syscall5, Syscall6, SyscallHandlers,
        SyscallResult, SyscallResult::*,
    },
};

use super::{
    fd::{
        file::{ReadonlyFileFileDescription, WriteonlyFileFileDescription},
        pipe, FileDescriptorTable,
    },
    memory::VirtualMemoryActivator,
    thread::{
        new_tid, schedule_thread, Sigset, Stack, StackFlags, Thread, UserspaceRegisters, Waiter,
        THREADS,
    },
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
                self.registers.rax = (-(err.kind() as i64)) as u64;
                true
            }
            Yield => false,
        }
    }

    /// Execute the exit syscall.
    pub fn exit(&mut self, vm_activator: &mut VirtualMemoryActivator, status: u8) {
        exit(self, vm_activator, u64::from(status));
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
    handlers.register(SysCopyFileRange);

    handlers
};

#[syscall(no = 0)]
fn read(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    fd: FdNum,
    buf: Pointer,
    count: u64,
) -> SyscallResult {
    let fd = thread.fdtable().get(fd)?;

    let buf = buf.get();
    let count = usize::try_from(count).unwrap();

    let mut chunk = [0u8; 128];
    let max_chunk_len = chunk.len();
    let len = cmp::min(max_chunk_len, count);
    let chunk = &mut chunk[..len];

    let len = fd.read(chunk)?;
    let chunk = &mut chunk[..len];

    vm_activator.activate(thread.virtual_memory(), |vm| vm.write(buf, chunk))?;

    let len = u64::try_from(len).unwrap();

    Ok(len)
}

#[syscall(no = 1)]
fn write(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    fd: FdNum,
    buf: Pointer,
    count: u64,
) -> SyscallResult {
    let fd = thread.fdtable().get(fd)?;

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

#[syscall(no = 2)]
fn open(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    pathname: Pointer,
    flags: OpenFlags,
    mode: FileMode,
) -> SyscallResult {
    let filename = vm_activator.activate(thread.virtual_memory(), |vm| {
        vm.read_cstring(pathname.get(), 4096)
    })?;
    let filename = Path::new(filename.as_bytes());

    if flags.contains(OpenFlags::WRONLY) {
        if flags.contains(OpenFlags::CREAT) {
            let file = create_file(Node::Directory(ROOT_NODE.clone()), &filename, mode)?;
            let fd = thread
                .fdtable()
                .insert(WriteonlyFileFileDescription::new(file));
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
            Node::Directory(_) => return Err(Error::is_dir()),
        };
        let fd = thread
            .fdtable()
            .insert(ReadonlyFileFileDescription::new(file));
        Ok(fd.get() as u64)
    }
}

#[syscall(no = 3)]
fn close(thread: &mut Thread, fd: FdNum) -> SyscallResult {
    thread.fdtable().close(fd)?;
    Ok(0)
}

#[syscall(no = 7)]
fn poll(
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

#[syscall(no = 9)]
fn mmap(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    addr: Pointer,
    length: u64,
    prot: ProtFlags,
    flags: MmapFlags,
    fd: u64,
    offset: u64,
) -> SyscallResult {
    if flags.contains(MmapFlags::SHARED_VALIDATE) {
        todo!("{addr} {length} {prot:?} {flags:?} {fd} {offset}");
    } else if flags.contains(MmapFlags::SHARED) {
        todo!("{addr} {length} {prot:?} {flags:?} {fd} {offset}");
    } else if flags.contains(MmapFlags::PRIVATE) {
        if flags.contains(MmapFlags::STACK) {
            assert!(flags.contains(MmapFlags::ANONYMOUS));
            assert_eq!(prot, ProtFlags::READ | ProtFlags::WRITE);

            assert_eq!(addr.get().as_u64(), 0);
            let addr = vm_activator.activate(thread.virtual_memory(), |vm| {
                vm.allocate_stack(None, length)
            })?;

            Ok(addr.as_u64())
        } else if flags.contains(MmapFlags::ANONYMOUS) {
            assert_eq!(addr.get().as_u64(), 0);

            let permissions = MemoryPermissions::from(prot);
            let addr = vm_activator.activate(thread.virtual_memory(), |vm| {
                vm.mmap_zero(None, length, permissions)
            })?;

            Ok(addr.as_u64())
        } else {
            todo!("{addr} {length} {prot:?} {flags:?} {fd} {offset}");
        }
    } else {
        return Err(Error::inval());
    }
}

#[syscall(no = 10)]
fn mprotect(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    addr: Pointer,
    len: u64,
    prot: ProtFlags,
) -> SyscallResult {
    vm_activator.activate(thread.virtual_memory(), |vm| {
        vm.mprotect(addr.get(), len, prot)
    })?;
    Ok(0)
}

// FIXME: use correct name for brk_value
#[syscall(no = 12)]
fn brk(brk_value: u64) -> SyscallResult {
    if brk_value == 0 || brk_value == 0x1000 {
        return Ok(0);
    }

    Err(Error::no_mem())
}

#[syscall(no = 13)]
fn rt_sigaction(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    signum: u64,
    act: Pointer,
    oldact: Pointer,
    sigsetsize: u64,
) -> SyscallResult {
    let signum = usize::try_from(signum).unwrap();

    // FIXME: SIGKILL and SIGSTOP are special
    // FIXME: sigsetsize

    if !oldact.is_null() {
        let sigaction = thread.sigaction.get(signum).ok_or(Error::inval())?;
        vm_activator.activate(thread.virtual_memory(), |vm| {
            vm.write(oldact.get(), bytes_of(sigaction))
        })?;
    }
    if !act.is_null() {
        let virtual_memory = thread.virtual_memory().clone();
        let sigaction = thread.sigaction.get_mut(signum).ok_or(Error::inval())?;
        vm_activator.activate(&virtual_memory, |vm| {
            vm.read(act.get(), bytes_of_mut(sigaction))
        })?;
    }

    Ok(0)
}

struct SysRtSigprocmask;

impl Syscall3 for SysRtSigprocmask {
    const NO: usize = 14;
    const NAME: &'static str = "rt_sigprocmask";

    type Arg0 = u64;
    const ARG0_NAME: &'static str = "how";
    type Arg1 = Pointer;
    const ARG1_NAME: &'static str = "set";
    type Arg2 = Pointer;
    const ARG2_NAME: &'static str = "oldset";

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
        write!(
            f,
            "{}({}=",
            <Self as Syscall3>::NAME,
            <Self as Syscall3>::ARG0_NAME
        )?;
        if set == 0 {
            write!(f, "ignored")?;
        } else {
            RtSigprocmaskHow::display(f, how)?;
        }
        write!(f, ", {}=", <Self as Syscall3>::ARG1_NAME)?;
        Pointer::display(f, set)?;
        write!(f, ", {}=", <Self as Syscall3>::ARG2_NAME)?;
        Pointer::display(f, oldset)?;
        write!(f, ")")
    }
}

#[syscall(no = 39)]
fn getpid(thread: &mut Thread) -> SyscallResult {
    let pid = thread.process().pid;
    Ok(u64::from(pid))
}

#[syscall(no = 56)]
fn clone(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    flags: CloneFlags,
    stack: Pointer,
    parent_tid: Pointer,
    child_tid: Pointer,
    tls: u64,
) -> SyscallResult {
    let new_tid = new_tid();

    let new_process = if flags.contains(CloneFlags::THREAD) {
        None
    } else {
        Some(Arc::new(Process::new(new_tid)))
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

    let tid = Thread::spawn(|weak_thread| {
        let new_thread = thread.clone(
            new_tid,
            weak_thread,
            new_process,
            new_virtual_memory,
            new_fdtable,
            stack.get(),
            new_clear_child_tid,
            new_tls,
        );

        if flags.contains(CloneFlags::PARENT_SETTID) {
            vm_activator.activate(thread.virtual_memory(), |vm| {
                vm.write(parent_tid.get(), &new_tid.to_ne_bytes())
            })?;
        }

        if flags.contains(CloneFlags::CHILD_SETTID) {
            vm_activator.activate(new_thread.virtual_memory(), |vm| {
                vm.write(child_tid.get(), &new_tid.to_ne_bytes())
            })?;
        }

        Result::Ok(new_thread)
    })?;

    Ok(u64::from(tid))
}

#[syscall(no = 59)]
fn execve(
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
            let argp = VirtAddr::try_new(argp).map_err(|_| Error::fault())?;
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
            let envp = VirtAddr::try_new(envp).map_err(|_| Error::fault())?;
            envs.push(vm.read_cstring(envp, 0x1000)?);
        }

        Result::Ok((pathname, args, envs))
    })?;

    let path = Path::new(pathname.as_bytes());
    thread.execve(&path, &args, &envs, vm_activator)?;

    Ok(0)
}

#[syscall(no = 60)]
fn exit(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    status: u64,
) -> SyscallResult {
    if thread.clear_child_tid != 0 {
        let clear_child_tid = VirtAddr::new(thread.clear_child_tid);
        vm_activator.activate(thread.virtual_memory(), |vm| {
            vm.write(clear_child_tid, &0u32.to_ne_bytes())
        })?;

        thread.process().futexes.wake(clear_child_tid, 1, None);
    }

    for Waiter { thread, wstatus: _ } in core::mem::take(&mut thread.waiters) {
        {
            let Some(thread) = thread.upgrade() else { continue; };
            let mut guard = thread.lock();
            guard.registers.rax = 0;
        }

        schedule_thread(thread);
    }

    THREADS.remove(thread.tid);

    Yield
}

#[syscall(no = 61)]
fn wait4(
    thread: &mut Thread,
    pid: u64,
    wstatus: Pointer,
    options: WaitOptions,
    rusage: Pointer,
) -> SyscallResult {
    if !rusage.is_null() {
        todo!()
    }

    match pid as i64 {
        ..=-2 => todo!(),
        -1 => todo!(),
        0 => todo!(),
        1.. => {
            let t = THREADS.by_id(pid as u32).ok_or_else(Error::child)?;

            let mut guard = t.lock();
            guard.waiters.push(Waiter {
                thread: thread.weak().clone(),
                wstatus: wstatus.get(),
            });

            Yield
        }
    }
}

#[syscall(no = 72)]
fn fcntl(fd: FdNum, cmd: FcntlCmd, arg: u64) -> SyscallResult {
    match cmd {
        FcntlCmd::SetFd => {
            // FIXME: implement this
            Ok(0)
        }
    }
}

#[syscall(no = 131)]
fn sigaltstack(
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
            return Err(Error::inval());
        }

        thread.sigaltstack = Some(ss_value);
    }

    Ok(0)
}

#[syscall(no = 158)]
fn arch_prctl(thread: &mut Thread, code: ArchPrctlCode, addr: Pointer) -> SyscallResult {
    match code {
        ArchPrctlCode::SetFs => {
            thread.registers.fs_base = addr.get().as_u64();
            Ok(0)
        }
    }
}

#[syscall(no = 186)]
fn gettid(thread: &mut Thread) -> SyscallResult {
    let tid = thread.tid;
    Ok(u64::from(tid))
}

#[syscall(no = 202)]
fn futex(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    uaddr: Pointer,
    op: FutexOpWithFlags,
    val: u32,
    utime: u64,
    uaddr2: Pointer,
    val3: u64,
) -> SyscallResult {
    match op.op {
        FutexOp::Wait => {
            assert_eq!(utime, 0);

            vm_activator.activate(thread.virtual_memory(), |vm| {
                thread
                    .process()
                    .futexes
                    .wait(thread.weak(), uaddr.get(), val, None, vm)
            })?;

            Yield
        }
        FutexOp::Wake => {
            let woken = thread.process().futexes.wake(uaddr.get(), val, None);
            Ok(u64::from(woken))
        }
        FutexOp::Fd => Err(Error::no_sys()),
        FutexOp::Requeue => Err(Error::no_sys()),
        FutexOp::CmpRequeue => Err(Error::no_sys()),
        FutexOp::WakeOp => Err(Error::no_sys()),
        FutexOp::LockPi => Err(Error::no_sys()),
        FutexOp::UnlockPi => Err(Error::no_sys()),
        FutexOp::TrylockPi => Err(Error::no_sys()),
        FutexOp::WaitBitset => {
            assert_eq!(utime, 0);
            let bitset = NonZeroU32::new(val3 as u32).ok_or(Error::inval())?;

            vm_activator.activate(thread.virtual_memory(), |vm| {
                thread
                    .process()
                    .futexes
                    .wait(thread.weak(), uaddr.get(), val, Some(bitset), vm)
            })?;

            Yield
        }
        FutexOp::WakeBitset => {
            let bitset = NonZeroU32::new(val3 as u32).ok_or(Error::inval())?;
            let woken = thread
                .process()
                .futexes
                .wake(uaddr.get(), val, Some(bitset));
            Ok(u64::from(woken))
        }
        FutexOp::WaitRequeuePi => Err(Error::no_sys()),
        FutexOp::CmpRequeuePi => Err(Error::no_sys()),
        FutexOp::LockPi2 => Err(Error::no_sys()),
    }
}

#[syscall(no = 218)]
fn set_tid_address(thread: &mut Thread, tidptr: Pointer) -> SyscallResult {
    thread.clear_child_tid = tidptr.get().as_u64();
    Ok(u64::from(thread.tid))
}

#[syscall(no = 231)]
fn exit_group(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    status: u64,
) -> SyscallResult {
    let status = thread.process().exit(status as u8);
    exit(thread, vm_activator, u64::from(status))
}

#[syscall(no = 293)]
fn pipe2(
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

#[syscall(no = 326)]
fn copy_file_range(
    thread: &mut Thread,
    fd_in: FdNum,
    off_in: Pointer,
    fd_out: FdNum,
    off_out: Pointer,
    len: u64,
    flags: CopyFileRangeFlags,
) -> SyscallResult {
    let fdtable = thread.fdtable();
    let fd_in = fdtable.get(fd_in)?;
    let fd_out = fdtable.get(fd_out)?;

    if !off_in.is_null() || !off_out.is_null() {
        todo!()
    }

    let mut len = usize::try_from(len).unwrap_or(!0);
    let mut copied = 0;

    let mut buffer = [0; 128];

    while len > 0 {
        // Setup buffer.
        let chunk_len = cmp::min(buffer.len(), len);
        let buffer = &mut buffer[..chunk_len];

        // Read from fd_in.
        let num = fd_in.read(buffer)?;
        if num == 0 {
            break;
        }

        // Write to fd_out.
        let buffer = &buffer[..num];
        fd_out.write_all(buffer)?;

        // Update len and copied.
        len -= num;
        let num = u64::try_from(num).unwrap();
        copied += num;
    }

    Ok(copied)
}
