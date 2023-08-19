use core::{
    cmp,
    ffi::{c_void, CStr},
    fmt,
    mem::size_of,
    num::NonZeroU32,
};

use alloc::{sync::Arc, vec, vec::Vec};
use bit_field::BitField;
use bytemuck::{bytes_of, bytes_of_mut, checked::try_pod_read_unaligned, Zeroable};
use kernel_macros::syscall;
use x86_64::VirtAddr;

use crate::{
    error::{Error, Result},
    fs::node::{
        self, create_directory, create_file, create_link,
        devtmpfs::{self, RandomFile},
        hard_link, lookup_and_resolve_node, lookup_node, read_link, set_mode, unlink_dir,
        unlink_file, Directory, Node, ROOT_NODE,
    },
    rt::oneshot,
    time,
    user::process::{
        memory::MemoryPermissions,
        syscall::args::{UserDesc, UserDescFlags},
    },
};

use self::{
    args::{
        Advice, ArchPrctlCode, ClockId, CloneFlags, CopyFileRangeFlags, Domain, EpollCreate1Flags,
        EpollCtlOp, EpollEvent, EventFdFlags, ExtractableThreadState, FcntlCmd, FdNum, FileMode,
        FutexOp, FutexOpWithFlags, GetRandomFlags, Iovec, LinkOptions, LinuxDirent64, MmapFlags,
        MountFlags, OpenFlags, Pipe2Flags, Pointer, Pollfd, ProtFlags, RtSigprocmaskHow,
        SocketPairType, Stat, SyscallArg, Timespec, UnlinkOptions, WStatus, WaitOptions, Whence,
    },
    traits::{Syscall, SyscallArgs, SyscallHandlers, SyscallResult},
};

use super::{
    fd::{
        dir::DirectoryFileDescription,
        do_io,
        epoll::Epoll,
        eventfd::EventFd,
        file::{
            ReadWriteFileFileDescription, ReadonlyFileFileDescription, WriteonlyFileFileDescription,
        },
        pipe,
        unix_socket::UnixSocket,
        Events, FileDescriptorTable,
    },
    memory::{VirtualMemory, VirtualMemoryActivator},
    thread::{new_tid, Sigaction, Sigset, Stack, StackFlags, Thread, ThreadGuard, THREADS},
    Process,
};

pub mod args;
pub mod cpu_state;
mod traits;

impl Thread {
    /// Returns true if the thread should continue to run.
    pub async fn execute_syscall(self: Arc<Self>) {
        let guard = self.cpu_state.lock();
        let args = guard.syscall_args().unwrap();
        drop(guard);

        let result = SYSCALL_HANDLERS.execute(self.clone(), args).await;

        let mut guard = self.cpu_state.lock();
        guard.set_syscall_result(result).unwrap();
    }
}

impl ThreadGuard<'_> {
    /// Execute the exit syscall.
    pub fn exit(&mut self, vm_activator: &mut VirtualMemoryActivator, status: u8) {
        let _ = exit(
            self,
            vm_activator,
            self.virtual_memory().clone(),
            u64::from(status),
        );
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
    handlers.register(SysMmap2);
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
    handlers.register(SysPipe);
    handlers.register(SysMadvise);
    handlers.register(SysDup);
    handlers.register(SysDup2);
    handlers.register(SysGetpid);
    handlers.register(SysSendfile);
    handlers.register(SysSocketpair);
    handlers.register(SysClone);
    handlers.register(SysFork);
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
    handlers.register(SysMount);
    handlers.register(SysGettid);
    handlers.register(SysFutex);
    handlers.register(SysSetThreadArea);
    handlers.register(SysGetdents64);
    handlers.register(SysSetTidAddress);
    handlers.register(SysClockGettime);
    handlers.register(SysOpenat);
    handlers.register(SysExitGroup);
    handlers.register(SysEpollWait);
    handlers.register(SysEpollCtl);
    handlers.register(SysFutimesat);
    handlers.register(SysUnlinkat);
    handlers.register(SysLinkat);
    handlers.register(SysEventfd);
    handlers.register(SysEpollCreate1);
    handlers.register(SysPipe2);
    handlers.register(SysGetrandom);
    handlers.register(SysCopyFileRange);

    handlers
};

#[syscall(i386 = 3, amd64 = 0)]
async fn read(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    buf: Pointer<[u8]>,
    count: u64,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;

    let buf = buf.get();
    let count = usize::try_from(count)?;

    let len = cmp::min(count, 8192);
    let mut buffer = vec![0; len];
    let len = do_io(&*fd, Events::READ, || fd.read(&mut buffer)).await?;
    buffer.truncate(len);

    VirtualMemoryActivator::use_from_async(virtual_memory, move |vm| vm.write(buf, &buffer))
        .await?;

    Ok(len.try_into()?)
}

#[syscall(i386 = 4, amd64 = 1)]
async fn write(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    buf: Pointer<[u8]>,
    count: u64,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;

    let buf = buf.get();
    let count = usize::try_from(count)?;
    let len = cmp::min(8192, count);
    let mut chunk = vec![0u8; len];

    let chunk = VirtualMemoryActivator::use_from_async(virtual_memory, move |vm| -> Result<_> {
        vm.read(buf, &mut chunk)?;
        Ok(chunk)
    })
    .await?;

    let len = do_io(&*fd, Events::WRITE, || fd.write(&chunk)).await?;

    let len = u64::try_from(len)?;
    Ok(len)
}

#[syscall(i386 = 5, amd64 = 2)]
fn open(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    pathname: Pointer<CStr>,
    flags: OpenFlags,
    mode: u64,
) -> SyscallResult {
    let mode = FileMode::from_bits_truncate(mode);
    let filename = vm_activator.activate(&virtual_memory, |vm| vm.read_path(pathname.get()))?;

    let file = if flags.contains(OpenFlags::CREAT) {
        create_file(ROOT_NODE.clone(), &filename, mode)?
    } else {
        let node = lookup_and_resolve_node(ROOT_NODE.clone(), &filename)?;
        node.try_into()?
    };

    let fd = if flags.contains(OpenFlags::WRONLY) {
        fdtable.insert(WriteonlyFileFileDescription::new(file))?
    } else if flags.contains(OpenFlags::RDWR) {
        fdtable.insert(ReadWriteFileFileDescription::new(file))?
    } else {
        fdtable.insert(ReadonlyFileFileDescription::new(file))?
    };

    Ok(fd.get() as u64)
}

#[syscall(i386 = 6, amd64 = 3)]
fn close(#[state] fdtable: Arc<FileDescriptorTable>, fd: FdNum) -> SyscallResult {
    fdtable.close(fd)?;
    Ok(0)
}

#[syscall(i386 = 106, amd64 = 4)]
fn stat(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    filename: Pointer<CStr>,
    statbuf: Pointer<Stat>,
) -> SyscallResult {
    vm_activator.activate(&virtual_memory, |vm| {
        let filename = vm.read_path(filename.get())?;

        let node = lookup_and_resolve_node(ROOT_NODE.clone(), &filename)?;
        let stat = node.stat();

        vm.write(statbuf.get(), bytes_of(&stat))
    })?;

    Ok(0)
}

#[syscall(i386 = 108, amd64 = 5)]
fn fstat(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    statbuf: Pointer<Stat>,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let stat = fd.stat()?;

    vm_activator.activate(&virtual_memory, |vm| {
        vm.write(statbuf.get(), bytes_of(&stat))
    })?;

    Ok(0)
}

#[syscall(i386 = 107, amd64 = 6)]
fn lstat(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    filename: Pointer<CStr>,
    statbuf: Pointer<Stat>,
) -> SyscallResult {
    vm_activator.activate(&virtual_memory, |vm| {
        let filename = vm.read_path(filename.get())?;

        let node = lookup_node(ROOT_NODE.clone(), &filename)?;
        let stat = node.stat();

        vm.write(statbuf.get(), bytes_of(&stat))
    })?;

    Ok(0)
}

#[syscall(i386 = 168, amd64 = 7)]
fn poll(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    fds: Pointer<FdNum>,
    nfds: u64,
    timeout: u64,
) -> SyscallResult {
    vm_activator.activate(&virtual_memory, |vm| {
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

#[syscall(i386 = 19, amd64 = 8)]
fn lseek(
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    offset: u64,
    whence: Whence,
) -> SyscallResult {
    let offset = usize::try_from(offset)?;

    let fd = fdtable.get(fd)?;
    let offset = fd.seek(offset, whence)?;

    let offset = u64::try_from(offset)?;
    Ok(offset)
}

#[syscall(i386 = 90, amd64 = 9)]
fn mmap(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
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

    if length > (1 << 47) {
        return Err(Error::no_mem(()));
    }

    if flags.contains(MmapFlags::SHARED_VALIDATE) {
        todo!("{addr:?} {length} {prot:?} {flags:?} {fd} {offset}");
    } else if flags.contains(MmapFlags::SHARED) {
        todo!("{addr:?} {length} {prot:?} {flags:?} {fd} {offset}");
    } else if flags.contains(MmapFlags::PRIVATE) {
        if flags.contains(MmapFlags::STACK) {
            assert!(flags.contains(MmapFlags::ANONYMOUS));
            assert_eq!(prot, ProtFlags::READ | ProtFlags::WRITE);

            let addr =
                vm_activator.activate(&virtual_memory, |vm| vm.allocate_stack(addr, length))?;

            Ok(addr.as_u64())
        } else if flags.contains(MmapFlags::ANONYMOUS) {
            let permissions = MemoryPermissions::from(prot);
            let addr = vm_activator.activate(&virtual_memory, |vm| {
                vm.mmap_zero(addr, length, permissions)
            })?;

            Ok(addr.as_u64())
        } else {
            let fd = FdNum::parse(fd)?;
            let fd = fdtable.get(fd)?;

            let permissions = MemoryPermissions::from(prot);
            let addr = vm_activator.activate(&virtual_memory, |vm| {
                fd.mmap(vm, addr, offset, length, permissions)
            })?;
            Ok(addr.as_u64())
        }
    } else {
        return Err(Error::inval(()));
    }
}

#[syscall(i386 = 192)]
fn mmap2(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    addr: Pointer<c_void>,
    length: u64,
    prot: ProtFlags,
    flags: MmapFlags,
    fd: u64,
    offset: u64,
) -> SyscallResult {
    mmap(
        vm_activator,
        virtual_memory,
        fdtable,
        addr,
        length,
        prot,
        flags,
        fd,
        offset * 4096,
    )
}

#[syscall(i386 = 125, amd64 = 10)]
fn mprotect(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    addr: Pointer<c_void>,
    len: u64,
    prot: ProtFlags,
) -> SyscallResult {
    vm_activator.activate(&virtual_memory, |vm| vm.mprotect(addr.get(), len, prot))?;
    Ok(0)
}

#[syscall(i386 = 91, amd64 = 11)]
fn munmap(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    addr: Pointer<c_void>,
    length: u64,
) -> SyscallResult {
    let addr = addr.get();
    if !addr.is_aligned(0x1000u64) || length % 0x1000 != 0 {
        return Err(Error::inval(()));
    }
    vm_activator.activate(&virtual_memory, |a| a.unmap(addr, length));
    Ok(0)
}

// FIXME: use correct name for brk_value
#[syscall(i386 = 45, amd64 = 12)]
fn brk(brk_value: u64) -> SyscallResult {
    if brk_value == 0 || brk_value == 0x1000 {
        return Ok(0);
    }

    Err(Error::no_mem(()))
}

#[syscall(i386 = 174, amd64 = 13)]
fn rt_sigaction(
    thread: &mut ThreadGuard,
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    signum: u64,
    act: Pointer<Sigaction>,
    oldact: Pointer<Sigaction>,
    sigsetsize: u64,
) -> SyscallResult {
    let signum = usize::try_from(signum)?;

    // FIXME: SIGKILL and SIGSTOP are special
    // FIXME: sigsetsize

    if !oldact.is_null() {
        let sigaction = thread.sigaction.get(signum).ok_or(Error::inval(()))?;
        vm_activator.activate(&virtual_memory, |vm| {
            vm.write(oldact.get(), bytes_of(sigaction))
        })?;
    }
    if !act.is_null() {
        let sigaction = thread.sigaction.get_mut(signum).ok_or(Error::inval(()))?;
        vm_activator.activate(&virtual_memory, |vm| {
            vm.read(act.get(), bytes_of_mut(sigaction))
        })?;
    }

    Ok(0)
}

struct SysRtSigprocmask;

impl Syscall for SysRtSigprocmask {
    const NO_I386: Option<usize> = Some(175);
    const NO_AMD64: Option<usize> = Some(14);
    const NAME: &'static str = "rt_sigprocmask";

    async fn execute(thread: Arc<Thread>, syscall_args: SyscallArgs) -> SyscallResult {
        let how = <u64 as SyscallArg>::parse(syscall_args.args[0])?;
        let set = <Pointer<Sigset> as SyscallArg>::parse(syscall_args.args[1])?;
        let oldset = <Pointer<Sigset> as SyscallArg>::parse(syscall_args.args[2])?;

        VirtualMemoryActivator::r#do(move |vm_activator| {
            let mut thread = thread.lock();

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
        })
        .await
    }

    fn display(
        f: &mut dyn fmt::Write,
        syscall_args: SyscallArgs,
        thread: &ThreadGuard<'_>,
        vm_activator: &mut VirtualMemoryActivator,
    ) -> fmt::Result {
        let how = syscall_args.args[0];
        let set = syscall_args.args[1];
        let oldset = syscall_args.args[2];

        write!(f, "rt_sigprocmask(set=")?;
        if set == 0 {
            write!(f, "ignored")?;
        } else {
            RtSigprocmaskHow::display(f, how, thread, vm_activator)?;
        }
        write!(f, ", set=")?;
        Pointer::<Sigset>::display(f, set, thread, vm_activator)?;
        write!(f, ", oldset=")?;
        Pointer::<Sigset>::display(f, oldset, thread, vm_activator)?;
        write!(f, ")")
    }
}

#[syscall(i386 = 54, amd64 = 16)]
fn ioctl(fd: FdNum, cmd: u32, arg: u64) -> SyscallResult {
    SyscallResult::Err(Error::no_tty(()))
}

#[syscall(i386 = 180, amd64 = 17)]
fn pread64(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    buf: Pointer<c_void>,
    count: u64,
    pos: u64,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;

    let buf = buf.get();
    let count = usize::try_from(count)?;
    let pos = usize::try_from(pos)?;

    let mut chunk = [0u8; 8192];
    let max_chunk_len = chunk.len();
    let len = cmp::min(max_chunk_len, count);
    let chunk = &mut chunk[..len];

    let len = fd.pread(pos, chunk)?;
    let chunk = &mut chunk[..len];

    vm_activator.activate(&virtual_memory, |vm| vm.write(buf, chunk))?;

    let len = u64::try_from(len)?;

    Ok(len)
}

#[syscall(i386 = 181, amd64 = 18)]
fn pwrite64(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    buf: Pointer<c_void>,
    count: u64,
    pos: u64,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;

    let buf = buf.get();
    let count = usize::try_from(count)?;
    let pos = usize::try_from(pos)?;

    let mut chunk = [0u8; 8192];
    let max_chunk_len = chunk.len();
    let len = cmp::min(max_chunk_len, count);
    let chunk = &mut chunk[..len];
    vm_activator.activate(&virtual_memory, |vm| vm.read(buf, chunk))?;

    let len = fd.pwrite(pos, chunk)?;

    let len = u64::try_from(len)?;
    Ok(len)
}

#[syscall(i386 = 145, amd64 = 19)]
async fn readv(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    vec: Pointer<Iovec>,
    vlen: u64,
) -> SyscallResult {
    if vlen == 0 {
        return SyscallResult::Ok(0);
    }
    let vlen = usize::try_from(vlen)?;

    let iovec = VirtualMemoryActivator::use_from_async(virtual_memory.clone(), move |vm| {
        let mut iovec = Iovec::zeroed();
        for i in 0..vlen {
            vm.read(vec.get() + size_of::<Iovec>() * i, bytes_of_mut(&mut iovec))?;
            if iovec.len != 0 {
                break;
            }
        }
        Result::<_>::Ok(iovec)
    })
    .await?;

    let addr = Pointer::parse(iovec.base)?;
    read(virtual_memory, fdtable, fd, addr, iovec.len).await
}

#[syscall(i386 = 146, amd64 = 20)]
async fn writev(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    vec: Pointer<Iovec>,
    vlen: u64,
) -> SyscallResult {
    if vlen == 0 {
        return SyscallResult::Ok(0);
    }
    let vlen = usize::try_from(vlen)?;

    let iovec = VirtualMemoryActivator::use_from_async(virtual_memory.clone(), move |vm| {
        let mut iovec = Iovec::zeroed();
        for i in 0..vlen {
            vm.read(vec.get() + size_of::<Iovec>() * i, bytes_of_mut(&mut iovec))?;
            if iovec.len != 0 {
                break;
            }
        }
        Result::<_>::Ok(iovec)
    })
    .await?;

    let addr = Pointer::parse(iovec.base)?;
    write(virtual_memory, fdtable, fd, addr, iovec.len).await
}

#[syscall(i386 = 33, amd64 = 21)]
fn access(
    #[state] virtual_memory: Arc<VirtualMemory>,
    vm_activator: &mut VirtualMemoryActivator,
    pathname: Pointer<CStr>,
    mode: u64, // FIXME: use correct type
) -> SyscallResult {
    let path = vm_activator.activate(&virtual_memory, |vm| vm.read_path(pathname.get()))?;
    let _node = lookup_and_resolve_node(ROOT_NODE.clone(), &path)?;
    // FIXME: implement the actual access checks.
    Ok(0)
}

#[syscall(i386 = 42, amd64 = 22)]
fn pipe(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    pipefd: Pointer<[FdNum; 2]>,
) -> SyscallResult {
    pipe2(
        vm_activator,
        virtual_memory,
        fdtable,
        pipefd,
        Pipe2Flags::empty(),
    )
}

#[syscall(i386 = 219, amd64 = 28)]
fn madvise(addr: Pointer<c_void>, len: u64, advice: Advice) -> SyscallResult {
    match advice {
        Advice::Free => {
            // Ignore the advise.
            Ok(0)
        }
    }
}

#[syscall(i386 = 41, amd64 = 32)]
fn dup(#[state] fdtable: Arc<FileDescriptorTable>, fildes: FdNum) -> SyscallResult {
    let fd = fdtable.get(fildes)?;
    let newfd = fdtable.insert(fd)?;

    Ok(newfd.get() as u64)
}

#[syscall(i386 = 63, amd64 = 33)]
fn dup2(#[state] fdtable: Arc<FileDescriptorTable>, oldfd: FdNum, newfd: FdNum) -> SyscallResult {
    let fd = fdtable.get(oldfd)?;

    if oldfd != newfd {
        fdtable.replace(newfd, fd);
    }

    Ok(newfd.get() as u64)
}

#[syscall(i386 = 20, amd64 = 39)]
fn getpid(thread: &mut ThreadGuard) -> SyscallResult {
    let pid = thread.process().pid;
    Ok(u64::from(pid))
}

#[syscall(i386 = 187, amd64 = 40)]
async fn sendfile(
    #[state] fdtable: Arc<FileDescriptorTable>,
    out: FdNum,
    r#in: FdNum,
    offset: Pointer<u64>,
    count: u64,
) -> SyscallResult {
    let out = fdtable.get(out)?;
    let r#in = fdtable.get(r#in)?;

    if !offset.is_null() {
        todo!();
    }

    let buffer = &mut [0; 8192];
    let mut total_len = 0;
    loop {
        let len = do_io(&*r#in, Events::READ, || r#in.read(buffer)).await?;
        let buffer = &buffer[..len];
        if buffer.is_empty() {
            break;
        }
        total_len += buffer.len();

        out.write_all(buffer).await?;
    }

    let len = u64::try_from(total_len)?;
    Ok(len)
}

#[syscall(i386 = 360, amd64 = 53)]
fn socketpair(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    vm_activator: &mut VirtualMemoryActivator,
    domain: Domain,
    r#type: SocketPairType,
    protocol: i32,
    sv: Pointer<[FdNum; 2]>,
) -> SyscallResult {
    let res1;
    let res2;

    match domain {
        Domain::Unix => {
            if protocol != 0 {
                return Err(Error::inval(()));
            }

            let (half1, half2) = UnixSocket::new_pair();
            res1 = fdtable.insert(half1);
            res2 = fdtable.insert(half2);
        }
    }

    // Make sure we don't leak a file descriptor if inserting the other one failed.
    let (fd1, fd2) = match (res1, res2) {
        (Result::Ok(fd1), Result::Ok(fd2)) => (fd1, fd2),
        (Result::Ok(fd), Result::Err(err)) | (Result::Err(err), Result::Ok(fd)) => {
            let _ = fdtable.close(fd);
            return Err(err);
        }
        (Result::Err(err), Result::Err(_)) => return Err(err),
    };

    vm_activator.activate(&virtual_memory, |vm| {
        vm.write(sv.get(), bytes_of(&[fd1.get(), fd2.get()]))
    })?;

    Ok(0)
}

#[syscall(i386 = 120, amd64 = 56)]
fn clone(
    thread: &mut ThreadGuard,
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
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
        fdtable
    } else {
        // Create a shallow copy of the files.
        Arc::new((*fdtable).clone())
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
            None,
        );

        if flags.contains(CloneFlags::PARENT_SETTID) {
            vm_activator.activate(&virtual_memory, |vm| {
                vm.write(parent_tid.get(), &new_tid.to_ne_bytes())
            })?;
        }

        if flags.contains(CloneFlags::CHILD_SETTID) {
            let guard = new_thread.lock();
            vm_activator.activate(guard.virtual_memory(), |vm| {
                vm.write(child_tid.get(), &new_tid.to_ne_bytes())
            })?;
        }

        Result::Ok(new_thread)
    })?;

    Ok(u64::from(tid))
}

#[syscall(i386 = 2, amd64 = 57)]
fn fork(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    vm_activator: &mut VirtualMemoryActivator,
) -> SyscallResult {
    let tid = Thread::spawn(|self_weak| {
        let new_tid = new_tid();
        let new_process = Some(Arc::new(Process::new(new_tid)));
        let virtual_memory = (*virtual_memory).clone(vm_activator)?;
        let new_virtual_memory = Some(Arc::new(virtual_memory));
        let new_fdtable = Arc::new((*fdtable).clone());

        Result::Ok(thread.clone(
            new_tid,
            self_weak,
            new_process,
            new_virtual_memory,
            new_fdtable,
            VirtAddr::zero(),
            None,
            None,
            None,
        ))
    })?;

    Ok(u64::from(tid))
}

#[syscall(i386 = 190, amd64 = 58)]
async fn vfork(thread: Arc<Thread>, #[state] fdtable: Arc<FileDescriptorTable>) -> SyscallResult {
    let (sender, receiver) = oneshot::new();

    let guard = thread.lock();
    let tid = Thread::spawn(|self_weak| {
        let new_tid = new_tid();
        let new_process = Some(Arc::new(Process::new(new_tid)));
        let new_fdtable = Arc::new((*fdtable).clone());

        Result::Ok(guard.clone(
            new_tid,
            self_weak,
            new_process,
            None,
            new_fdtable,
            VirtAddr::zero(),
            None,
            None,
            Some(sender),
        ))
    })?;
    drop(guard);

    let _ = receiver.recv().await;

    Ok(u64::from(tid))
}

#[syscall(i386 = 11, amd64 = 59)]
fn execve(
    thread: &mut ThreadGuard,
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    pathname: Pointer<CStr>,
    argv: Pointer<[&'static CStr]>,
    envp: Pointer<[&'static CStr]>,
) -> SyscallResult {
    let (pathname, args, envs) = vm_activator.activate(&virtual_memory, |vm| -> Result<_> {
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

    log::info!("execve({pathname:?}, {args:?}, {envs:?})");

    thread.execve(&pathname, &args, &envs, vm_activator)?;

    if let Some(vfork_parent) = thread.vfork_done.take() {
        let _ = vfork_parent.send(());
    }

    Ok(0)
}

#[syscall(i386 = 1, amd64 = 60)]
fn exit(
    thread: &mut ThreadGuard,
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    status: u64,
) -> SyscallResult {
    let status = status as u8;

    thread.close_all_fds();

    if core::mem::take(&mut thread.clear_child_tid) != 0 {
        let clear_child_tid = VirtAddr::new(thread.clear_child_tid);
        let _ = vm_activator.activate(&virtual_memory, |vm| {
            vm.write(clear_child_tid, &0u32.to_ne_bytes())
        });

        thread.process().futexes.wake(clear_child_tid, 1, None);
    }

    if !core::mem::replace(&mut thread.notified_parent_about_exit, true) {
        if let Some(parent) = thread.parent().upgrade() {
            parent.add_child_death(thread.tid(), status);
        }
    }

    thread.set_exit_status(status);

    Ok(0)
}

#[syscall(i386 = 114, amd64 = 61)]
async fn wait4(
    thread: Arc<Thread>,
    #[state] virtual_memory: Arc<VirtualMemory>,
    pid: i64,
    wstatus: Pointer<WStatus>, // FIXME: use correct type
    options: WaitOptions,
    rusage: Pointer<c_void>, // FIXME: use correct type
) -> SyscallResult {
    if !rusage.is_null() {
        todo!()
    }

    let (tid, status) = match pid {
        ..=-2 => todo!(),
        -1 => {
            if options.contains(WaitOptions::NOHANG) {
                let Some((tid, status)) = thread.try_wait_for_child_death() else {
                    return Ok(0);
                };
                (tid, status)
            } else {
                thread.wait_for_child_death().await
            }
        }
        0 => todo!(),
        1.. => {
            let t = THREADS.by_id(pid as u32).ok_or_else(|| Error::child(()))?;
            let status = t.wait_for_exit().await;
            (t.tid(), status)
        }
    };

    if !wstatus.is_null() {
        let addr = wstatus.get();
        let wstatus = WStatus::exit(status);

        VirtualMemoryActivator::use_from_async(virtual_memory, move |vm| {
            vm.write(addr, bytes_of(&wstatus))
        })
        .await?;
    }

    THREADS.remove(tid);

    Ok(u64::from(tid))
}

#[syscall(i386 = 55, amd64 = 72)]
fn fcntl(
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    cmd: FcntlCmd,
    arg: u64,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;

    match cmd {
        FcntlCmd::DupFd => {
            let min = i32::try_from(arg)?;
            let fd_num = fdtable.insert_after(min, fd)?;
            Ok(fd_num.get().try_into()?)
        }
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

#[syscall(i386 = 39, amd64 = 83)]
fn mkdir(
    #[state] virtual_memory: Arc<VirtualMemory>,
    vm_activator: &mut VirtualMemoryActivator,
    pathname: Pointer<CStr>,
    mode: FileMode,
) -> SyscallResult {
    let pathname = vm_activator.activate(&virtual_memory, |vm| vm.read_path(pathname.get()))?;
    create_directory(ROOT_NODE.clone(), &pathname, mode)?;
    Ok(0)
}

#[syscall(i386 = 83, amd64 = 88)]
fn symlink(
    #[state] virtual_memory: Arc<VirtualMemory>,
    vm_activator: &mut VirtualMemoryActivator,
    oldname: Pointer<CStr>,
    newname: Pointer<CStr>,
) -> SyscallResult {
    let (oldname, newname) = vm_activator.activate(&virtual_memory, |vm| {
        let oldname = vm.read_path(oldname.get())?;
        let newname = vm.read_path(newname.get())?;
        Result::<_, Error>::Ok((oldname, newname))
    })?;

    create_link(ROOT_NODE.clone(), &newname, oldname)?;

    Ok(0)
}

#[syscall(i386 = 85, amd64 = 89)]
fn readlink(
    #[state] virtual_memory: Arc<VirtualMemory>,
    vm_activator: &mut VirtualMemoryActivator,
    pathname: Pointer<CStr>,
    buf: Pointer<[u8]>,
    bufsiz: u64,
) -> SyscallResult {
    let bufsiz = usize::try_from(bufsiz)?;

    let len = vm_activator.activate(&virtual_memory, |vm| {
        let pathname = vm.read_path(pathname.get())?;
        let target = read_link(ROOT_NODE.clone(), &pathname)?;

        let bytes = target.as_bytes();
        // Truncate to `bufsiz`.
        let len = cmp::min(bytes.len(), bufsiz);
        let bytes = &bytes[..len];

        vm.write(buf.get(), bytes)?;

        Result::<_, Error>::Ok(len)
    })?;

    let len = u64::try_from(len)?;
    Ok(len)
}

#[syscall(i386 = 15, amd64 = 90)]
fn chmod(
    #[state] virtual_memory: Arc<VirtualMemory>,
    vm_activator: &mut VirtualMemoryActivator,
    filename: Pointer<CStr>,
    mode: FileMode,
) -> SyscallResult {
    let path = vm_activator.activate(&virtual_memory, |vm| vm.read_path(filename.get()))?;

    set_mode(ROOT_NODE.clone(), &path, mode)?;

    Ok(0)
}

#[syscall(i386 = 94, amd64 = 91)]
fn fchmod(#[state] fdtable: Arc<FileDescriptorTable>, fd: FdNum, mode: FileMode) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    fd.set_mode(mode)?;
    Ok(0)
}

#[syscall(i386 = 186, amd64 = 131)]
fn sigaltstack(
    thread: &mut ThreadGuard,
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    ss: Pointer<Stack>,
    old_ss: Pointer<Stack>,
) -> SyscallResult {
    if !old_ss.is_null() {
        let old_ss_value = thread.sigaltstack.unwrap_or_else(|| {
            let mut stack = Stack::zeroed();
            stack.flags |= StackFlags::DISABLE;
            stack
        });

        vm_activator.activate(&virtual_memory, |vm| {
            vm.write(old_ss.get(), bytes_of(&old_ss_value))
        })?;
    }

    if !ss.is_null() {
        let mut ss_value = Stack::zeroed();
        vm_activator.activate(&virtual_memory, |vm| {
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

#[syscall(i386 = 384, amd64 = 158)]
fn arch_prctl(
    thread: &mut ThreadGuard,
    code: ArchPrctlCode,
    addr: Pointer<c_void>,
) -> SyscallResult {
    match code {
        ArchPrctlCode::SetFs => {
            thread
                .thread
                .cpu_state
                .lock()
                .set_tls(addr.get().as_u64())?;
            Ok(0)
        }
    }
}

#[syscall(i386 = 21, amd64 = 165)]
fn mount(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    dev_name: Pointer<CStr>,
    dir_name: Pointer<CStr>,
    r#type: Pointer<CStr>,
    mode: MountFlags,
    data: Pointer<c_void>,
) -> SyscallResult {
    let (_dev_name, dir_name, r#type) =
        vm_activator.activate(&virtual_memory, |vm| -> Result<_> {
            let dev_name = vm.read_path(dev_name.get())?;
            let dir_name = vm.read_path(dir_name.get())?;
            let r#type = vm.read_cstring(r#type.get(), 0x10)?;
            Result::Ok((dev_name, dir_name, r#type))
        })?;

    let node = match r#type.as_bytes() {
        b"devtmpfs" => Node::Directory(Arc::new(devtmpfs::new()?)),
        _ => return Err(Error::no_dev(())),
    };

    node::mount(&dir_name, node)?;

    Ok(0)
}

#[syscall(i386 = 224, amd64 = 186)]
fn gettid(thread: &mut ThreadGuard) -> SyscallResult {
    let tid = thread.tid();
    Ok(u64::from(tid))
}

#[syscall(i386 = 240, amd64 = 202)]
async fn futex(
    thread: Arc<Thread>,
    #[state] virtual_memory: Arc<VirtualMemory>,
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

            thread
                .process()
                .futexes
                .clone()
                .wait(uaddr.get(), val, None, None, virtual_memory)
                .await?;

            Ok(0)
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
            let bitset = NonZeroU32::try_from(val3 as u32)?;

            let deadline = if utime != 0 {
                let deadline = VirtualMemoryActivator::use_from_async(
                    virtual_memory.clone(),
                    move |vm| -> Result<_> {
                        let mut time = Timespec::zeroed();
                        vm.read(VirtAddr::new(utime), bytes_of_mut(&mut time))?;
                        Ok(time)
                    },
                )
                .await?;
                Some(deadline)
            } else {
                None
            };

            thread
                .process()
                .futexes
                .clone()
                .wait(uaddr.get(), val, Some(bitset), deadline, virtual_memory)
                .await?;

            Ok(0)
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

#[syscall(i386 = 243, amd64 = 205)]
fn set_thread_area(
    thread: &mut ThreadGuard,
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    u_info: Pointer<UserDesc>,
) -> SyscallResult {
    let u_info_addr = u_info.get();
    let mut bytes = [0; size_of::<UserDesc>()];
    vm_activator.activate(&virtual_memory, |vm| vm.read(u_info_addr, &mut bytes))?;
    let u_info = try_pod_read_unaligned::<UserDesc>(&bytes)?;

    let mut access_byte = 0u8;
    access_byte.set_bit(7, !u_info.flags.contains(UserDescFlags::SEG_NOT_PRESENT)); // present bit
    access_byte.set_bits(5..=6, 3); // DPL
    access_byte.set_bit(4, true); // descriptor type bit
    access_byte.set_bit(3, u_info.flags.contains(UserDescFlags::READ_EXEC_ONLY)); // executable bit
    access_byte.set_bit(2, false); // DC bit
    access_byte.set_bit(1, true); // RW bit
    access_byte.set_bit(0, true); // accessed bit

    let mut flags = 0u8;
    flags.set_bit(0, false); // reserved
    flags.set_bit(1, u_info.flags.contains(UserDescFlags::LM)); // L bit
    flags.set_bit(2, u_info.flags.contains(UserDescFlags::SEG_32BIT)); // DB bit
    flags.set_bit(3, u_info.flags.contains(UserDescFlags::LIMIT_IN_PAGES)); // DB bit

    let mut desc = 0;
    desc.set_bits(0..=15, u64::from(u_info.limit.get_bits(0..=15)));
    desc.set_bits(48..=51, u64::from(u_info.limit.get_bits(16..=19)));
    desc.set_bits(16..=39, u64::from(u_info.base_addr.get_bits(0..=23)));
    desc.set_bits(56..=63, u64::from(u_info.base_addr.get_bits(24..=31)));
    desc.set_bits(40..=47, u64::from(access_byte));
    desc.set_bits(52..=55, u64::from(flags));

    assert_eq!(
        u_info.entry_number, !0,
        "we only support adding entries for now"
    );

    let mut cpu_state = thread.thread.cpu_state.lock();
    let entry = cpu_state.add_gd(desc)?;
    drop(cpu_state);

    let entry = u32::from(entry);
    vm_activator.activate(&virtual_memory, |vm| {
        vm.write(u_info_addr, &entry.to_ne_bytes())
    })?;

    Ok(0)
}

#[syscall(i386 = 220, amd64 = 217)]
fn getdents64(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    dirent: Pointer<LinuxDirent64>,
    count: u64,
) -> SyscallResult {
    let capacity = usize::try_from(count)?;
    let fd = fdtable.get(fd)?;
    let entries = fd.getdents64(capacity)?;

    let len = vm_activator.activate(&virtual_memory, |vm| -> Result<_> {
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

#[syscall(i386 = 258, amd64 = 218)]
fn set_tid_address(thread: &mut ThreadGuard, tidptr: Pointer<u32>) -> SyscallResult {
    thread.clear_child_tid = tidptr.get().as_u64();
    Ok(u64::from(thread.tid()))
}

#[syscall(i386 = 265, amd64 = 228)]
fn clock_gettime(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    clock_id: ClockId,
    tp: Pointer<Timespec>,
) -> SyscallResult {
    let time = match clock_id {
        ClockId::Realtime | ClockId::Monotonic => time::now(),
    };

    vm_activator.activate(&virtual_memory, |vm| vm.write(tp.get(), bytes_of(&time)))?;

    Ok(0)
}

#[syscall(i386 = 252, amd64 = 231)]
async fn exit_group(thread: Arc<Thread>, status: u64) -> SyscallResult {
    let process = thread.process().clone();
    process.exit(status as u8);
    core::future::pending().await
}

#[syscall(i386 = 256, amd64 = 232)]
async fn epoll_wait(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    epfd: FdNum,
    event: Pointer<EpollEvent>,
    maxevents: i32,
    timeout: i32,
) -> SyscallResult {
    let maxevents = usize::try_from(maxevents)?;

    let epoll = fdtable.get(epfd)?;
    let events = epoll.epoll_wait(maxevents).await?;
    assert!(events.len() <= maxevents);

    let len = events.len();

    VirtualMemoryActivator::use_from_async(virtual_memory, move |vm| -> Result<_> {
        for (i, e) in events.iter().enumerate() {
            let ptr = event.get() + i * size_of::<EpollEvent>();
            vm.write(ptr, bytes_of(e))?;
        }
        Result::Ok(())
    })
    .await?;

    Ok(len.try_into()?)
}

#[syscall(i386 = 255, amd64 = 233)]
fn epoll_ctl(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    epfd: FdNum,
    op: EpollCtlOp,
    fd: FdNum,
    event: Pointer<EpollEvent>,
) -> SyscallResult {
    let event = if !event.is_null() {
        vm_activator.activate(&virtual_memory, |vm| -> Result<_> {
            let mut bytes = [0; size_of::<EpollEvent>()];
            vm.read(event.get(), &mut bytes)?;
            let event = try_pod_read_unaligned::<EpollEvent>(&bytes)?;
            Result::Ok(Some(event))
        })?
    } else {
        None
    };

    let epoll = fdtable.get(epfd)?;
    let fd = fdtable.get(fd)?;

    match op {
        EpollCtlOp::Add => {
            // Poll the fd once to check if it supports epoll.
            let _ = fd.poll_ready(Events::empty())?;

            let event = event.ok_or_else(|| Error::inval(()))?;
            epoll.epoll_add(fd, event)?
        }
    }

    Ok(0)
}

#[syscall(i386 = 295, amd64 = 257)]
fn openat(
    thread: &mut ThreadGuard,
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    dfd: FdNum,
    filename: Pointer<CStr>,
    flags: OpenFlags,
    mode: u64,
) -> SyscallResult {
    let filename = vm_activator.activate(&virtual_memory, |vm| vm.read_path(filename.get()))?;

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
                let fd = fdtable.insert(DirectoryFileDescription::new(dir))?;
                Ok(fd.get() as u64)
            }
            Node::Link(_) => Err(Error::r#loop(())),
        }
    } else {
        todo!()
    }
}

#[syscall(i386 = 299, amd64 = 261)]
fn futimesat(
    dirfd: FdNum,
    pathname: Pointer<CStr>,
    times: Pointer<c_void>, // FIXME: use correct type
) -> SyscallResult {
    // FIXME: Implement this.
    Ok(0)
}

#[syscall(i386 = 301, amd64 = 263)]
fn unlinkat(
    thread: &mut ThreadGuard,
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    dfd: FdNum,
    pathname: Pointer<CStr>,
    flags: UnlinkOptions,
) -> SyscallResult {
    let pathname = vm_activator.activate(&virtual_memory, |vm| vm.read_path(pathname.get()))?;

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

#[syscall(i386 = 303, amd64 = 265)]
fn linkat(
    thread: &mut ThreadGuard,
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    olddirfd: FdNum,
    oldpath: Pointer<CStr>,
    newdirfd: FdNum,
    newpath: Pointer<CStr>,
    flags: LinkOptions,
) -> SyscallResult {
    let (oldpath, newpath) = vm_activator.activate(&virtual_memory, |vm| -> Result<_> {
        let oldpath = vm.read_path(oldpath.get())?;
        let newpath = vm.read_path(newpath.get())?;
        Result::Ok((oldpath, newpath))
    })?;

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

#[syscall(i386 = 323, amd64 = 290)]
fn eventfd(
    #[state] fdtable: Arc<FileDescriptorTable>,
    initval: u32,
    flags: EventFdFlags,
) -> SyscallResult {
    let fd_num = fdtable.insert(EventFd::new(initval))?;
    Ok(fd_num.get().try_into().unwrap())
}

#[syscall(i386 = 329, amd64 = 291)]
fn epoll_create1(
    #[state] fdtable: Arc<FileDescriptorTable>,
    flags: EpollCreate1Flags,
) -> SyscallResult {
    let fd_num = fdtable.insert(Epoll::new())?;
    Ok(fd_num.get().try_into().unwrap())
}

#[syscall(i386 = 331, amd64 = 293)]
fn pipe2(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    pipefd: Pointer<[FdNum; 2]>,
    flags: Pipe2Flags,
) -> SyscallResult {
    if flags != Pipe2Flags::CLOEXEC {
        todo!()
    }

    let (read_half, write_half) = pipe::new();

    // Insert the first read half.
    let read_half = fdtable.insert(read_half)?;
    // Insert the second write half.
    let res = fdtable.insert(write_half);
    // Ensure that we close the first fd, if inserting the second failed.
    if res.is_err() {
        let _ = fdtable.close(read_half);
    }
    let write_half = res?;

    let mut bytes = [0; 8];
    bytes[0..4].copy_from_slice(&read_half.get().to_ne_bytes());
    bytes[4..8].copy_from_slice(&write_half.get().to_ne_bytes());
    vm_activator.activate(&virtual_memory, |vm| vm.write(pipefd.get(), &bytes))?;

    Ok(0)
}

#[syscall(i386 = 355, amd64 = 318)]
fn getrandom(
    vm_activator: &mut VirtualMemoryActivator,
    #[state] virtual_memory: Arc<VirtualMemory>,
    buf: Pointer<c_void>,
    buflen: u64,
    flags: GetRandomFlags,
) -> SyscallResult {
    vm_activator.activate(&virtual_memory, |vm| {
        let mut len = 0;
        for (i, random) in (0..buflen).zip(RandomFile::random_bytes()) {
            vm.write(buf.get() + i, &[random])?;
            len += 1;
        }
        Ok(len)
    })
}

#[syscall(i386 = 377, amd64 = 326)]
async fn copy_file_range(
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd_in: FdNum,
    off_in: Pointer<u64>,
    fd_out: FdNum,
    off_out: Pointer<u64>,
    len: u64,
    flags: CopyFileRangeFlags,
) -> SyscallResult {
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
        let num = do_io(&*fd_in, Events::READ, || fd_in.read(buffer)).await?;
        if num == 0 {
            break;
        }

        // Write to fd_out.
        let buffer = &buffer[..num];
        fd_out.write_all(buffer).await?;

        // Update len and copied.
        len -= num;
        let num = u64::try_from(num)?;
        copied += num;
    }

    Ok(copied)
}
