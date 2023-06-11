use core::{
    cmp,
    ffi::{c_void, CStr},
    fmt::{self},
    mem::size_of,
    num::NonZeroU32,
};

use alloc::{sync::Arc, vec::Vec};
use bytemuck::{bytes_of, bytes_of_mut, Zeroable};
use kernel_macros::syscall;
use x86_64::VirtAddr;

use crate::{
    error::{Error, Result},
    fs::node::{
        create_directory, create_file, create_link, hard_link, lookup_and_resolve_node,
        lookup_node, read_link, set_mode, unlink_dir, unlink_file, Directory, Node, NonLinkNode,
        ROOT_NODE,
    },
    user::process::memory::MemoryPermissions,
};

use self::{
    args::{
        Advice, ArchPrctlCode, CloneFlags, CopyFileRangeFlags, FcntlCmd, FdNum, FileMode, FutexOp,
        FutexOpWithFlags, Iovec, LinkOptions, LinuxDirent64, MmapFlags, OpenFlags, Pipe2Flags,
        Pointer, Pollfd, ProtFlags, RtSigprocmaskHow, Stat, SyscallArg, UnlinkOptions, WaitOptions,
        Whence,
    },
    traits::{
        Syscall0, Syscall1, Syscall2, Syscall3, Syscall4, Syscall5, Syscall6, SyscallHandlers,
        SyscallResult, SyscallResult::*,
    },
};

use super::{
    fd::{
        dir::DirectoryFileDescription,
        file::{
            ReadWriteFileFileDescription, ReadonlyFileFileDescription, WriteonlyFileFileDescription,
        },
        pipe,
    },
    memory::VirtualMemoryActivator,
    thread::{
        new_tid, schedule_thread, Sigaction, Sigset, Stack, StackFlags, Thread, UserspaceRegisters,
        Waiter, THREADS,
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
    handlers.register(SysStat);
    handlers.register(SysFstat);
    handlers.register(SysLstat);
    handlers.register(SysPoll);
    handlers.register(SysLseek);
    handlers.register(SysMmap);
    handlers.register(SysMprotect);
    handlers.register(SysMunmap);
    handlers.register(SysBrk);
    handlers.register(SysRtSigaction);
    handlers.register(SysRtSigprocmask);
    handlers.register(SysIoctl);
    handlers.register(SysPread64);
    handlers.register(SysPwrite64);
    handlers.register(SysReadv);
    handlers.register(SysWritev);
    handlers.register(SysAccess);
    handlers.register(SysMadvise);
    handlers.register(SysDup);
    handlers.register(SysDup2);
    handlers.register(SysGetpid);
    handlers.register(SysClone);
    handlers.register(SysVfork);
    handlers.register(SysExecve);
    handlers.register(SysExit);
    handlers.register(SysWait4);
    handlers.register(SysFcntl);
    handlers.register(SysMkdir);
    handlers.register(SysSymlink);
    handlers.register(SysReadlink);
    handlers.register(SysChmod);
    handlers.register(SysFchmod);
    handlers.register(SysSigaltstack);
    handlers.register(SysArchPrctl);
    handlers.register(SysGettid);
    handlers.register(SysFutex);
    handlers.register(SysGetdents64);
    handlers.register(SysSetTidAddress);
    handlers.register(SysOpenat);
    handlers.register(SysExitGroup);
    handlers.register(SysFutimesat);
    handlers.register(SysUnlinkat);
    handlers.register(SysLinkat);
    handlers.register(SysPipe2);
    handlers.register(SysCopyFileRange);

    handlers
};

#[syscall(no = 0)]
fn read(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    fd: FdNum,
    buf: Pointer<[u8]>,
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
    buf: Pointer<[u8]>,
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
    pathname: Pointer<CStr>,
    flags: OpenFlags,
    mode: FileMode,
) -> SyscallResult {
    let filename =
        vm_activator.activate(thread.virtual_memory(), |vm| vm.read_path(pathname.get()))?;

    if flags.contains(OpenFlags::WRONLY) {
        if flags.contains(OpenFlags::CREAT) {
            let file = create_file(ROOT_NODE.clone(), &filename, mode)?;
            let fd = thread
                .fdtable()
                .insert(WriteonlyFileFileDescription::new(file));
            Ok(fd.get() as u64)
        } else {
            todo!()
        }
    } else if flags.contains(OpenFlags::RDWR) {
        if flags.contains(OpenFlags::CREAT) {
            let file = create_file(ROOT_NODE.clone(), &filename, mode)?;
            let fd = thread
                .fdtable()
                .insert(ReadWriteFileFileDescription::new(file));
            Ok(fd.get() as u64)
        } else {
            todo!()
        }
    } else {
        let node = lookup_and_resolve_node(ROOT_NODE.clone(), &filename)?;

        let file = match node {
            NonLinkNode::File(file) => file,
            NonLinkNode::Directory(_) => return Err(Error::is_dir(())),
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

#[syscall(no = 4)]
fn stat(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    filename: Pointer<CStr>,
    statbuf: Pointer<Stat>,
) -> SyscallResult {
    vm_activator.activate(thread.virtual_memory(), |vm| {
        let filename = vm.read_path(filename.get())?;

        let node = lookup_and_resolve_node(ROOT_NODE.clone(), &filename)?;
        let stat = node.stat();

        vm.write(statbuf.get(), bytes_of(&stat))
    })?;

    Ok(0)
}

#[syscall(no = 5)]
fn fstat(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    fd: FdNum,
    statbuf: Pointer<Stat>,
) -> SyscallResult {
    let fd = thread.fdtable().get(fd)?;
    let stat = fd.stat()?;

    vm_activator.activate(thread.virtual_memory(), |vm| {
        vm.write(statbuf.get(), bytes_of(&stat))
    })?;

    Ok(0)
}

#[syscall(no = 6)]
fn lstat(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    filename: Pointer<CStr>,
    statbuf: Pointer<Stat>,
) -> SyscallResult {
    vm_activator.activate(thread.virtual_memory(), |vm| {
        let filename = vm.read_path(filename.get())?;

        let node = lookup_node(ROOT_NODE.clone(), &filename)?;
        let stat = node.stat();

        vm.write(statbuf.get(), bytes_of(&stat))
    })?;

    Ok(0)
}

#[syscall(no = 7)]
fn poll(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    fds: Pointer<FdNum>,
    nfds: u64,
    timeout: u64,
) -> SyscallResult {
    vm_activator.activate(thread.virtual_memory(), |vm| {
        for i in 0..nfds {
            let mut pollfd = Pollfd::zeroed();
            vm.read(fds.get() + i * 8, bytes_of_mut(&mut pollfd))?;
        }
        Result::<_>::Ok(())
    })?;

    if timeout != 0 {
        todo!()
    }

    Ok(0)
}

#[syscall(no = 8)]
fn lseek(thread: &mut Thread, fd: FdNum, offset: u64, whence: Whence) -> SyscallResult {
    let offset = usize::try_from(offset)?;

    let fd = thread.fdtable().get(fd)?;
    let offset = fd.seek(offset, whence)?;

    let offset = u64::try_from(offset)?;
    Ok(offset)
}

#[syscall(no = 9)]
fn mmap(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    addr: Pointer<c_void>,
    length: u64,
    prot: ProtFlags,
    flags: MmapFlags,
    fd: u64,
    offset: u64,
) -> SyscallResult {
    let addr = if flags.contains(MmapFlags::FIXED) {
        Some(addr.get())
    } else {
        None
    };

    if flags.contains(MmapFlags::SHARED_VALIDATE) {
        todo!("{addr:?} {length} {prot:?} {flags:?} {fd} {offset}");
    } else if flags.contains(MmapFlags::SHARED) {
        todo!("{addr:?} {length} {prot:?} {flags:?} {fd} {offset}");
    } else if flags.contains(MmapFlags::PRIVATE) {
        if flags.contains(MmapFlags::STACK) {
            assert!(flags.contains(MmapFlags::ANONYMOUS));
            assert_eq!(prot, ProtFlags::READ | ProtFlags::WRITE);

            let addr = vm_activator.activate(thread.virtual_memory(), |vm| {
                vm.allocate_stack(addr, length)
            })?;

            Ok(addr.as_u64())
        } else if flags.contains(MmapFlags::ANONYMOUS) {
            let permissions = MemoryPermissions::from(prot);
            let addr = vm_activator.activate(thread.virtual_memory(), |vm| {
                vm.mmap_zero(addr, length, permissions)
            })?;

            Ok(addr.as_u64())
        } else {
            let fd = FdNum::parse(fd)?;
            let fd = thread.fdtable().get(fd)?;

            let permissions = MemoryPermissions::from(prot);
            let addr = vm_activator.activate(thread.virtual_memory(), |vm| {
                fd.mmap(vm, addr, offset, length, permissions)
            })?;
            Ok(addr.as_u64())
        }
    } else {
        return Err(Error::inval(()));
    }
}

#[syscall(no = 10)]
fn mprotect(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    addr: Pointer<c_void>,
    len: u64,
    prot: ProtFlags,
) -> SyscallResult {
    vm_activator.activate(thread.virtual_memory(), |vm| {
        vm.mprotect(addr.get(), len, prot)
    })?;
    Ok(0)
}

#[syscall(no = 11)]
fn munmap(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    addr: Pointer<c_void>,
    length: u64,
) -> SyscallResult {
    let addr = addr.get();
    if !addr.is_aligned(0x1000u64) || length % 0x1000 != 0 {
        return Err(Error::inval(()));
    }
    vm_activator.activate(thread.virtual_memory(), |a| a.unmap(addr, length));
    Ok(0)
}

// FIXME: use correct name for brk_value
#[syscall(no = 12)]
fn brk(brk_value: u64) -> SyscallResult {
    if brk_value == 0 || brk_value == 0x1000 {
        return Ok(0);
    }

    Err(Error::no_mem(()))
}

#[syscall(no = 13)]
fn rt_sigaction(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    signum: u64,
    act: Pointer<Sigaction>,
    oldact: Pointer<Sigaction>,
    sigsetsize: u64,
) -> SyscallResult {
    let signum = usize::try_from(signum).unwrap();

    // FIXME: SIGKILL and SIGSTOP are special
    // FIXME: sigsetsize

    if !oldact.is_null() {
        let sigaction = thread.sigaction.get(signum).ok_or(Error::inval(()))?;
        vm_activator.activate(thread.virtual_memory(), |vm| {
            vm.write(oldact.get(), bytes_of(sigaction))
        })?;
    }
    if !act.is_null() {
        let virtual_memory = thread.virtual_memory().clone();
        let sigaction = thread.sigaction.get_mut(signum).ok_or(Error::inval(()))?;
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
    type Arg1 = Pointer<Sigset>;
    const ARG1_NAME: &'static str = "set";
    type Arg2 = Pointer<Sigset>;
    const ARG2_NAME: &'static str = "oldset";

    fn execute(
        thread: &mut Thread,
        vm_activator: &mut VirtualMemoryActivator,
        how: u64,
        set: Pointer<Sigset>,
        oldset: Pointer<Sigset>,
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

    fn display(
        f: &mut dyn fmt::Write,
        how: u64,
        set: u64,
        oldset: u64,
        thread: &Thread,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        write!(
            f,
            "{}({}=",
            <Self as Syscall3>::NAME,
            <Self as Syscall3>::ARG0_NAME
        )?;
        if set == 0 {
            write!(f, "ignored")?;
        } else {
            RtSigprocmaskHow::display(f, how, thread, vm_activator)?;
        }
        write!(f, ", {}=", <Self as Syscall3>::ARG1_NAME)?;
        Pointer::<Sigset>::display(f, set, thread, vm_activator)?;
        write!(f, ", {}=", <Self as Syscall3>::ARG2_NAME)?;
        Pointer::<Sigset>::display(f, oldset, thread, vm_activator)?;
        write!(f, ")")
    }
}

#[syscall(no = 16)]
fn ioctl(fd: FdNum, cmd: u32, arg: u64) -> SyscallResult {
    SyscallResult::Err(Error::no_tty(()))
}

#[syscall(no = 17)]
fn pread64(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    fd: FdNum,
    buf: Pointer<c_void>,
    count: u64,
    pos: u64,
) -> SyscallResult {
    let fd = thread.fdtable().get(fd)?;

    let buf = buf.get();
    let count = usize::try_from(count)?;
    let pos = usize::try_from(pos)?;

    let mut chunk = [0u8; 8192];
    let max_chunk_len = chunk.len();
    let len = cmp::min(max_chunk_len, count);
    let chunk = &mut chunk[..len];

    let len = fd.pread(pos, chunk)?;
    let chunk = &mut chunk[..len];

    vm_activator.activate(thread.virtual_memory(), |vm| vm.write(buf, chunk))?;

    let len = u64::try_from(len)?;

    Ok(len)
}

#[syscall(no = 18)]
fn pwrite64(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    fd: FdNum,
    buf: Pointer<c_void>,
    count: u64,
    pos: u64,
) -> SyscallResult {
    let fd = thread.fdtable().get(fd)?;

    let buf = buf.get();
    let count = usize::try_from(count)?;
    let pos = usize::try_from(pos)?;

    let mut chunk = [0u8; 8192];
    let max_chunk_len = chunk.len();
    let len = cmp::min(max_chunk_len, count);
    let chunk = &mut chunk[..len];
    vm_activator.activate(thread.virtual_memory(), |vm| vm.read(buf, chunk))?;

    let len = fd.pwrite(pos, chunk)?;

    let len = u64::try_from(len)?;
    Ok(len)
}

#[syscall(no = 19)]
fn readv(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    fd: FdNum,
    vec: Pointer<Iovec>,
    vlen: u64,
) -> SyscallResult {
    if vlen == 0 {
        return SyscallResult::Ok(0);
    }
    let vlen = usize::try_from(vlen)?;

    let iovec = vm_activator.activate(thread.virtual_memory(), |vm| {
        let mut iovec = Iovec::zeroed();
        for i in 0..vlen {
            vm.read(vec.get() + size_of::<Iovec>() * i, bytes_of_mut(&mut iovec))?;
            if iovec.len != 0 {
                break;
            }
        }
        Result::<_>::Ok(iovec)
    })?;

    let addr = Pointer::parse(iovec.base)?;
    read(thread, vm_activator, fd, addr, iovec.len)
}

#[syscall(no = 20)]
fn writev(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    fd: FdNum,
    vec: Pointer<Iovec>,
    vlen: u64,
) -> SyscallResult {
    if vlen == 0 {
        return SyscallResult::Ok(0);
    }
    let vlen = usize::try_from(vlen)?;

    let iovec = vm_activator.activate(thread.virtual_memory(), |vm| {
        let mut iovec = Iovec::zeroed();
        for i in 0..vlen {
            vm.read(vec.get() + size_of::<Iovec>() * i, bytes_of_mut(&mut iovec))?;
            if iovec.len != 0 {
                break;
            }
        }
        Result::<_>::Ok(iovec)
    })?;

    let addr = Pointer::parse(iovec.base)?;
    write(thread, vm_activator, fd, addr, iovec.len)
}

#[syscall(no = 21)]
fn access(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    pathname: Pointer<CStr>,
    mode: u64, // FIXME: use correct type
) -> SyscallResult {
    let path = vm_activator.activate(thread.virtual_memory(), |vm| vm.read_path(pathname.get()))?;
    let _node = lookup_and_resolve_node(ROOT_NODE.clone(), &path)?;
    // FIXME: implement the actual access checks.
    Ok(0)
}

#[syscall(no = 28)]
fn madvise(addr: Pointer<c_void>, len: u64, advice: Advice) -> SyscallResult {
    match advice {
        Advice::Free => {
            // Ignore the advise.
            Ok(0)
        }
    }
}

#[syscall(no = 32)]
fn dup(thread: &mut Thread, fildes: FdNum) -> SyscallResult {
    let fdtable = thread.fdtable();
    let fd = fdtable.get(fildes)?;
    let newfd = fdtable.insert(fd);

    Ok(newfd.get() as u64)
}

#[syscall(no = 33)]
fn dup2(thread: &mut Thread, oldfd: FdNum, newfd: FdNum) -> SyscallResult {
    let fdtable = thread.fdtable();
    let fd = fdtable.get(oldfd)?;

    if oldfd != newfd {
        fdtable.replace(newfd, fd);
    }

    Ok(newfd.get() as u64)
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
    stack: Pointer<c_void>,
    parent_tid: Pointer<u32>,
    child_tid: Pointer<u32>,
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
        // Reuse the same files.
        thread.fdtable().clone()
    } else {
        // Create a shallow copy of the files.
        Arc::new((**thread.fdtable()).clone())
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
            false,
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

#[syscall(no = 58)]
fn vfork(thread: &mut Thread) -> SyscallResult {
    let tid = Thread::spawn(|self_weak| {
        let new_tid = new_tid();
        let new_process = Some(Arc::new(Process::new(new_tid)));
        let new_fdtable = Arc::new((**thread.fdtable()).clone());

        Result::Ok(thread.clone(
            new_tid,
            self_weak,
            new_process,
            None,
            new_fdtable,
            VirtAddr::zero(),
            None,
            None,
            true,
        ))
    })?;

    thread.registers.rax = u64::from(tid);

    Yield
}

#[syscall(no = 59)]
fn execve(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    pathname: Pointer<CStr>,
    argv: Pointer<[&'static CStr]>,
    envp: Pointer<[&'static CStr]>,
) -> SyscallResult {
    let (pathname, args, envs) =
        vm_activator.activate(thread.virtual_memory(), |vm| -> Result<_> {
            let pathname = vm.read_path(pathname.get())?;

            let mut args = Vec::new();
            for i in 0u64.. {
                let argpp = argv.get() + i * 8;
                let mut argp = 0u64;
                vm.read(argpp, bytes_of_mut(&mut argp))?;
                if argp == 0 {
                    break;
                }
                let argp = VirtAddr::try_new(argp).map_err(|_| Error::fault(()))?;
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
                let envp = VirtAddr::try_new(envp).map_err(|_| Error::fault(()))?;
                envs.push(vm.read_cstring(envp, 0x1000)?);
            }

            Result::Ok((pathname, args, envs))
        })?;

    thread.execve(&pathname, &args, &envs, vm_activator)?;

    if let Some(vfork_parent) = thread.vfork_parent.take() {
        schedule_thread(vfork_parent);
    }

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

    if let Some(vfork_parent) = thread.vfork_parent.take() {
        schedule_thread(vfork_parent);
    }

    THREADS.remove(thread.tid());

    thread.dead = true;

    Yield
}

#[syscall(no = 61)]
fn wait4(
    thread: &mut Thread,
    pid: u64,
    wstatus: Pointer<c_void>, // FIXME: use correct type
    options: WaitOptions,
    rusage: Pointer<c_void>, // FIXME: use correct type
) -> SyscallResult {
    if !rusage.is_null() {
        todo!()
    }

    match pid as i64 {
        ..=-2 => todo!(),
        -1 => todo!(),
        0 => todo!(),
        1.. => {
            let t = THREADS.by_id(pid as u32).ok_or_else(|| Error::child(()))?;

            let mut guard = t.lock();
            if guard.dead {
                // Return immediatly for dead tasks.
                return Ok(0);
            }

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
        FcntlCmd::GetFd => {
            // FIXME: implement this
            Ok(0)
        }
        FcntlCmd::SetFd => {
            // FIXME: implement this
            Ok(0)
        }
        FcntlCmd::GetFl => {
            // FIXME: implement this
            Ok(0)
        }
    }
}

#[syscall(no = 83)]
fn mkdir(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    pathname: Pointer<CStr>,
    mode: FileMode,
) -> SyscallResult {
    let pathname =
        vm_activator.activate(thread.virtual_memory(), |vm| vm.read_path(pathname.get()))?;

    create_directory(ROOT_NODE.clone(), &pathname, mode)?;

    Ok(0)
}

#[syscall(no = 88)]
fn symlink(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    oldname: Pointer<CStr>,
    newname: Pointer<CStr>,
) -> SyscallResult {
    let (oldname, newname) = vm_activator.activate(thread.virtual_memory(), |vm| {
        let oldname = vm.read_path(oldname.get())?;
        let newname = vm.read_path(newname.get())?;
        Result::<_, Error>::Ok((oldname, newname))
    })?;

    create_link(ROOT_NODE.clone(), &newname, oldname)?;

    Ok(0)
}

#[syscall(no = 89)]
fn readlink(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    pathname: Pointer<CStr>,
    buf: Pointer<[u8]>,
    bufsiz: u64,
) -> SyscallResult {
    let bufsiz = usize::try_from(bufsiz)?;

    let len = vm_activator.activate(thread.virtual_memory(), |vm| {
        let pathname = vm.read_path(pathname.get())?;
        let target = read_link(ROOT_NODE.clone(), &pathname)?;

        let bytes = target.to_bytes();
        // Truncate to `bufsiz`.
        let len = cmp::min(bytes.len(), bufsiz);
        let bytes = &bytes[..len];

        vm.write(buf.get(), bytes)?;

        Result::<_, Error>::Ok(len)
    })?;

    let len = u64::try_from(len)?;
    Ok(len)
}

#[syscall(no = 90)]
fn chmod(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    filename: Pointer<CStr>,
    mode: FileMode,
) -> SyscallResult {
    let path = vm_activator.activate(thread.virtual_memory(), |vm| vm.read_path(filename.get()))?;

    set_mode(ROOT_NODE.clone(), &path, mode)?;

    Ok(0)
}

#[syscall(no = 91)]
fn fchmod(thread: &mut Thread, fd: FdNum, mode: FileMode) -> SyscallResult {
    let fd = thread.fdtable().get(fd)?;
    fd.set_mode(mode)?;
    Ok(0)
}

#[syscall(no = 131)]
fn sigaltstack(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    ss: Pointer<Stack>,
    old_ss: Pointer<Stack>,
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
            return Err(Error::inval(()));
        }

        thread.sigaltstack = Some(ss_value);
    }

    Ok(0)
}

#[syscall(no = 158)]
fn arch_prctl(thread: &mut Thread, code: ArchPrctlCode, addr: Pointer<c_void>) -> SyscallResult {
    match code {
        ArchPrctlCode::SetFs => {
            thread.registers.fs_base = addr.get().as_u64();
            Ok(0)
        }
    }
}

#[syscall(no = 186)]
fn gettid(thread: &mut Thread) -> SyscallResult {
    let tid = thread.tid();
    Ok(u64::from(tid))
}

#[syscall(no = 202)]
fn futex(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    uaddr: Pointer<c_void>,
    op: FutexOpWithFlags,
    val: u32,
    utime: u64,
    uaddr2: Pointer<c_void>,
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
        FutexOp::Fd => Err(Error::no_sys(())),
        FutexOp::Requeue => Err(Error::no_sys(())),
        FutexOp::CmpRequeue => Err(Error::no_sys(())),
        FutexOp::WakeOp => Err(Error::no_sys(())),
        FutexOp::LockPi => Err(Error::no_sys(())),
        FutexOp::UnlockPi => Err(Error::no_sys(())),
        FutexOp::TrylockPi => Err(Error::no_sys(())),
        FutexOp::WaitBitset => {
            assert_eq!(utime, 0);
            let bitset = NonZeroU32::try_from(val3 as u32)?;

            vm_activator.activate(thread.virtual_memory(), |vm| {
                thread
                    .process()
                    .futexes
                    .wait(thread.weak(), uaddr.get(), val, Some(bitset), vm)
            })?;

            Yield
        }
        FutexOp::WakeBitset => {
            let bitset = NonZeroU32::try_from(val3 as u32)?;
            let woken = thread
                .process()
                .futexes
                .wake(uaddr.get(), val, Some(bitset));
            Ok(u64::from(woken))
        }
        FutexOp::WaitRequeuePi => Err(Error::no_sys(())),
        FutexOp::CmpRequeuePi => Err(Error::no_sys(())),
        FutexOp::LockPi2 => Err(Error::no_sys(())),
    }
}

#[syscall(no = 217)]
fn getdents64(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    fd: FdNum,
    dirent: Pointer<LinuxDirent64>,
    count: u64,
) -> SyscallResult {
    let capacity = usize::try_from(count)?;
    let fd = thread.fdtable().get(fd)?;
    let entries = fd.getdents64(capacity)?;

    let len = vm_activator.activate(thread.virtual_memory(), |vm| -> Result<_> {
        let mut addr = dirent.get();
        for entry in entries {
            let dirent = LinuxDirent64 {
                ino: entry.ino,
                off: i64::try_from(entry.len())?,
                reclen: u16::try_from(entry.len())?,
                ty: entry.ty as u8,
                name: [],
                _padding: [0; 5],
            };
            vm.write(addr, bytes_of(&dirent))?;
            vm.write(addr + 19u64, entry.name.as_ref())?;
            vm.write(addr + 19u64 + entry.name.as_ref().len(), &[0])?;

            addr += entry.len();
        }

        let len = addr - dirent.get();

        Result::Ok(len)
    })?;

    Ok(len)
}

#[syscall(no = 218)]
fn set_tid_address(thread: &mut Thread, tidptr: Pointer<u32>) -> SyscallResult {
    thread.clear_child_tid = tidptr.get().as_u64();
    Ok(u64::from(thread.tid()))
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

#[syscall(no = 257)]
fn openat(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    dfd: FdNum,
    filename: Pointer<CStr>,
    flags: OpenFlags,
    mode: FileMode,
) -> SyscallResult {
    let filename =
        vm_activator.activate(thread.virtual_memory(), |vm| vm.read_path(filename.get()))?;

    let fdtable = thread.fdtable();

    let start_dir = if dfd == FdNum::CWD {
        let node = lookup_and_resolve_node(ROOT_NODE.clone(), &thread.cwd)?;
        <Arc<dyn Directory>>::try_from(node)?
    } else {
        let fd = fdtable.get(dfd)?;
        fd.as_dir()?
    };

    let node = if flags.contains(OpenFlags::NOFOLLOW) {
        lookup_node(start_dir, &filename)?
    } else {
        Node::from(lookup_and_resolve_node(start_dir, &filename)?)
    };

    if flags.contains(OpenFlags::DIRECTORY) {
        match node {
            Node::File(_) => Err(Error::not_dir(())),
            Node::Directory(dir) => {
                let fd = fdtable.insert(DirectoryFileDescription::new(dir));
                Ok(fd.get() as u64)
            }
            Node::Link(_) => Err(Error::r#loop(())),
        }
    } else {
        todo!()
    }
}

#[syscall(no = 261)]
fn futimesat(
    dirfd: FdNum,
    pathname: Pointer<CStr>,
    times: Pointer<c_void>, // FIXME: use correct type
) -> SyscallResult {
    // FIXME: Implement this.
    Ok(0)
}

#[syscall(no = 263)]
fn unlinkat(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    dfd: FdNum,
    pathname: Pointer<CStr>,
    flags: UnlinkOptions,
) -> SyscallResult {
    let pathname =
        vm_activator.activate(thread.virtual_memory(), |vm| vm.read_path(pathname.get()))?;

    let fdtable = thread.fdtable();

    let start_dir = if dfd == FdNum::CWD {
        let node = lookup_and_resolve_node(ROOT_NODE.clone(), &thread.cwd)?;
        <Arc<dyn Directory>>::try_from(node)?
    } else {
        let fd = fdtable.get(dfd)?;
        fd.as_dir()?
    };

    if flags.contains(UnlinkOptions::REMOVEDIR) {
        unlink_dir(start_dir, &pathname)?;
    } else {
        unlink_file(start_dir, &pathname)?;
    }

    Ok(0)
}

#[syscall(no = 265)]
fn linkat(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    olddirfd: FdNum,
    oldpath: Pointer<CStr>,
    newdirfd: FdNum,
    newpath: Pointer<CStr>,
    flags: LinkOptions,
) -> SyscallResult {
    let (oldpath, newpath) = vm_activator.activate(thread.virtual_memory(), |vm| -> Result<_> {
        let oldpath = vm.read_path(oldpath.get())?;
        let newpath = vm.read_path(newpath.get())?;
        Result::Ok((oldpath, newpath))
    })?;

    let fdtable = thread.fdtable();

    let olddir = if olddirfd == FdNum::CWD {
        let node = lookup_and_resolve_node(ROOT_NODE.clone(), &thread.cwd)?;
        <Arc<dyn Directory>>::try_from(node)?
    } else {
        let fd = fdtable.get(olddirfd)?;
        fd.as_dir()?
    };
    let newdir = if newdirfd == FdNum::CWD {
        let node = lookup_and_resolve_node(ROOT_NODE.clone(), &thread.cwd)?;
        <Arc<dyn Directory>>::try_from(node)?
    } else {
        let fd = fdtable.get(newdirfd)?;
        fd.as_dir()?
    };

    hard_link(
        newdir,
        &newpath,
        olddir,
        &oldpath,
        flags.contains(LinkOptions::SYMLINK_FOLLOW),
    )?;

    Ok(0)
}

#[syscall(no = 293)]
fn pipe2(
    thread: &mut Thread,
    vm_activator: &mut VirtualMemoryActivator,
    pipefd: Pointer<[FdNum; 2]>,
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
    off_in: Pointer<u64>,
    fd_out: FdNum,
    off_out: Pointer<u64>,
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
