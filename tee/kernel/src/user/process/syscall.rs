use core::{cmp, ffi::c_void, fmt, future::pending, mem::size_of, num::NonZeroU32, pin::pin};

use alloc::{
    ffi::CString,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use arrayvec::ArrayVec;
use bit_field::{BitArray, BitField};
use bytemuck::{Zeroable, bytes_of, bytes_of_mut, checked};
use constants::{ApBitmap, ApIndex};
use futures::{
    FutureExt, StreamExt,
    future::{self, Either, Fuse},
    select_biased,
    stream::FuturesUnordered,
};
use kernel_macros::syscall;
use log::warn;
use usize_conversions::{FromUsize, usize_from};
use x86_64::VirtAddr;

use crate::{
    char_dev::mem::random_bytes,
    error::{ErrorKind, Result, bail, ensure, err},
    fs::{
        StatFs,
        fd::{
            Events, FdFlags, FileDescriptorTable, KernelReadBuf, KernelWriteBuf,
            StrongFileDescriptor, UserBuf, VectoredUserBuf, WriteBuf, do_io, do_write_io,
            epoll::Epoll,
            eventfd::EventFd,
            inotify::Inotify,
            path::PathFd,
            pipe,
            stream_buffer::{self, SpliceBlockedError},
            unix_socket::{SeqPacketUnixSocket, StreamUnixSocket},
        },
        node::{
            self, DirEntry, FileAccessContext, Link, OldDirEntry, Permission, create_char_dev,
            create_directory, create_fifo, create_file, create_link, devtmpfs, hard_link,
            lookup_and_resolve_link, lookup_link, procfs, read_soft_link, unlink_dir, unlink_file,
        },
        path::Path,
    },
    net::{netlink::NetlinkSocket, tcp::TcpSocket, udp::UdpSocket},
    rt::{oneshot, r#yield},
    time::{self, now, sleep_until},
    user::process::{ProcessGroup, memory::MemoryPermissions, syscall::args::*},
};

use self::traits::{Abi, Syscall, SyscallArgs, SyscallHandlers, SyscallResult};

use super::{
    Process, WaitFilter,
    futex::FutexScope,
    limits::{CurrentNoFileLimit, CurrentStackLimit},
    memory::{Bias, VirtualMemory},
    thread::{
        Gid, NewTls, SigFields, SigInfo, SigInfoCode, Sigaction, Sigset, Stack, StackFlags, Thread,
        ThreadGuard, Uid, new_tid,
    },
};

pub mod args;
pub mod cpu_state;
pub mod traits;

pub use cpu_state::init;

impl Thread {
    /// Returns true if the thread should continue to run.
    pub async fn execute_syscall(self: Arc<Self>, args: SyscallArgs) {
        let result = SYSCALL_HANDLERS.execute(self.clone(), args).await;

        let mut guard = self.cpu_state.lock();
        guard.set_syscall_result(result).unwrap();
        if result.is_err_and(|e| e.kind() == ErrorKind::RestartNoIntr) {
            guard.restart_syscall(args.no);
        }
    }
}

impl ThreadGuard<'_> {
    /// Release the threads resources.
    pub fn do_exit(&mut self) {
        if let Some(vfork_parent) = self.vfork_done.take() {
            let _ = vfork_parent.send(());
        }

        self.close_all_fds();

        let clear_child_tid = core::mem::take(&mut self.clear_child_tid);
        if !clear_child_tid.is_null() {
            let virtual_memory = self.virtual_memory();
            let _ = virtual_memory.write(clear_child_tid, 0u32);
            let _ = virtual_memory.futex_wake(clear_child_tid, 1, FutexScope::Global, None);
        }
    }
}

const SYSCALL_HANDLERS: SyscallHandlers = {
    let mut handlers = SyscallHandlers::new();

    handlers.register(SysRead);
    handlers.register(SysWrite);
    handlers.register(SysOpen);
    handlers.register(SysClose);
    handlers.register(SysStat);
    handlers.register(SysStat64);
    handlers.register(SysFstat);
    handlers.register(SysFstat64);
    handlers.register(SysLstat);
    handlers.register(SysLstat64);
    handlers.register(SysPoll);
    handlers.register(SysLseek);
    handlers.register(SysMmap);
    handlers.register(SysMmap2);
    handlers.register(SysMprotect);
    handlers.register(SysMunmap);
    handlers.register(SysBrk);
    handlers.register(SysRtSigaction);
    handlers.register(SysRtSigprocmask);
    handlers.register(SysRtSigreturn);
    handlers.register(SysIoctl);
    handlers.register(SysPread64);
    handlers.register(SysPwrite64);
    handlers.register(SysReadv);
    handlers.register(SysWritev);
    handlers.register(SysAccess);
    handlers.register(SysPipe);
    handlers.register(SysSelect);
    handlers.register(SysSchedYield);
    handlers.register(SysMsync);
    handlers.register(SysMadvise);
    handlers.register(SysDup);
    handlers.register(SysDup2);
    handlers.register(SysNanosleep);
    handlers.register(SysAlarm);
    handlers.register(SysGetpid);
    handlers.register(SysSendfile);
    handlers.register(SysSendfile64);
    handlers.register(SysSocket);
    handlers.register(SysConnect);
    handlers.register(SysAccept);
    handlers.register(SysSendto);
    handlers.register(SysRecvFrom);
    handlers.register(SysSendmsg);
    handlers.register(SysRecvmsg);
    handlers.register(SysShutdown);
    handlers.register(SysBind);
    handlers.register(SysListen);
    handlers.register(SysGetsockname);
    handlers.register(SysGetpeername);
    handlers.register(SysSocketpair);
    handlers.register(SysClone);
    handlers.register(SysSetsockopt);
    handlers.register(SysGetsockopt);
    handlers.register(SysFork);
    handlers.register(SysVfork);
    handlers.register(SysExecve);
    handlers.register(SysExit);
    handlers.register(SysWait4);
    handlers.register(SysKill);
    handlers.register(SysUname);
    handlers.register(SysFcntl);
    handlers.register(SysFcntl64);
    handlers.register(SysFlock);
    handlers.register(SysFsync);
    handlers.register(SysFdatasync);
    handlers.register(SysFtruncate);
    handlers.register(SysGetdents);
    handlers.register(SysGetcwd);
    handlers.register(SysChdir);
    handlers.register(SysFchdir);
    handlers.register(SysRename);
    handlers.register(SysMkdir);
    handlers.register(SysRmdir);
    handlers.register(SysCreat);
    handlers.register(SysLink);
    handlers.register(SysUnlink);
    handlers.register(SysSymlink);
    handlers.register(SysReadlink);
    handlers.register(SysChmod);
    handlers.register(SysFchmod);
    handlers.register(SysChown);
    handlers.register(SysFchown);
    handlers.register(SysLchown);
    handlers.register(SysUmask);
    handlers.register(SysGettimeofday);
    handlers.register(SysGetrlimit);
    handlers.register(SysGetrusage);
    handlers.register(SysSysinfo);
    handlers.register(SysGetuid);
    handlers.register(SysGetgid);
    handlers.register(SysSetuid);
    handlers.register(SysSetgid);
    handlers.register(SysGeteuid);
    handlers.register(SysGetegid);
    handlers.register(SysSetpgid);
    handlers.register(SysGetppid);
    handlers.register(SysGetpgrp);
    handlers.register(SysSetsid);
    handlers.register(SysSetreuid);
    handlers.register(SysSetregid);
    handlers.register(SysGetgroups);
    handlers.register(SysSetgroups);
    handlers.register(SysSetresuid);
    handlers.register(SysGetresuid);
    handlers.register(SysSetresgid);
    handlers.register(SysGetresgid);
    handlers.register(SysGetpgid);
    handlers.register(SysSetfsuid);
    handlers.register(SysSetfsgid);
    handlers.register(SysGetsid);
    handlers.register(SysRtSigsuspend);
    handlers.register(SysSigaltstack);
    handlers.register(SysStatfs);
    handlers.register(SysMknod);
    handlers.register(SysFstatfs);
    handlers.register(SysGetpriority);
    handlers.register(SysSetpriority);
    handlers.register(SysPrctl);
    handlers.register(SysArchPrctl);
    handlers.register(SysMount);
    handlers.register(SysGettid);
    handlers.register(SysTime);
    handlers.register(SysFutex);
    handlers.register(SysSchedSetaffinity);
    handlers.register(SysSchedGetaffinity);
    handlers.register(SysSetThreadArea);
    handlers.register(SysGetdents64);
    handlers.register(SysEpollCreate);
    handlers.register(SysSetTidAddress);
    handlers.register(SysClockSettime);
    handlers.register(SysClockGettime);
    handlers.register(SysClockGetres);
    handlers.register(SysClockNanosleep);
    handlers.register(SysTgkill);
    handlers.register(SysInotifyInit);
    handlers.register(SysInotifyAddWatch);
    handlers.register(SysInotifyRmWatch);
    handlers.register(SysOpenat);
    handlers.register(SysMkdirat);
    handlers.register(SysExitGroup);
    handlers.register(SysEpollWait);
    handlers.register(SysEpollCtl);
    handlers.register(SysMknodat);
    handlers.register(SysFchownat);
    handlers.register(SysFutimesat);
    handlers.register(SysNewfstatat);
    handlers.register(SysUnlinkat);
    handlers.register(SysRenameat);
    handlers.register(SysLinkat);
    handlers.register(SysSymlinkat);
    handlers.register(SysReadlinkat);
    handlers.register(SysFchmodat);
    handlers.register(SysFaccessat);
    handlers.register(SysPselect6);
    handlers.register(SysPpoll);
    handlers.register(SysSplice);
    handlers.register(SysUtimensat);
    handlers.register(SysEpollPwait);
    handlers.register(SysAccept4);
    handlers.register(SysEventfd);
    handlers.register(SysEpollCreate1);
    handlers.register(SysDup3);
    handlers.register(SysPipe2);
    handlers.register(SysInotifyInit1);
    handlers.register(SysPreadv);
    handlers.register(SysPwritev);
    handlers.register(SysRecvmmsg);
    handlers.register(SysPrlimit64);
    handlers.register(SysSendmmsg);
    handlers.register(SysGetcpu);
    handlers.register(SysRenameat2);
    handlers.register(SysGetrandom);
    handlers.register(SysCopyFileRange);
    handlers.register(SysFchmodat2);

    handlers
};

#[syscall(i386 = 3, amd64 = 0, interruptable, restartable)]
async fn read(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    buf: Pointer<[u8]>,
    count: u64,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let count = usize_from(count);
    let mut buf = UserBuf::new(&virtual_memory, buf, count);
    let len = do_io(&**fd, Events::READ, || fd.read(&mut buf)).await?;
    let len = u64::from_usize(len);
    Ok(len)
}

#[syscall(i386 = 4, amd64 = 1)]
async fn write(
    thread: Arc<Thread>,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    buf: Pointer<[u8]>,
    count: u64,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;

    let count = usize_from(count);

    // Start writing to the file descriptor. This first write can be
    // interrupted and restarted. Any errors that occur are report to
    // userspace.
    let res = thread
        .interruptable(
            do_write_io(&**fd, count, || {
                let buf = UserBuf::new(&virtual_memory, buf, count);
                fd.write(&buf)
            }),
            true,
        )
        .await;
    if res.is_err_and(|err| err.kind() == ErrorKind::Pipe) {
        let sig_info = SigInfo {
            signal: Signal::PIPE,
            code: SigInfoCode::KERNEL,
            fields: SigFields::None,
        };
        thread.queue_signal(sig_info);
    }

    // Try to write the rest of the bytes that weren't written in the first
    // write call. This can be interrupted as well, but if that happens, it
    // won't be reported to userspace. Any errors that occur also won't be
    // reported to userspace.
    let mut written = res?;
    while written != count {
        let res = thread
            .interruptable(
                do_write_io(&**fd, count - written, || {
                    let buf =
                        UserBuf::new(&virtual_memory, buf.bytes_offset(written), count - written);
                    fd.write(&buf)
                }),
                false,
            )
            .await;
        let Ok(newly_written) = res else {
            break;
        };
        written += newly_written;
    }

    let len = u64::from_usize(written);
    Ok(len)
}

#[syscall(i386 = 5, amd64 = 2, interruptable, restartable)]
async fn open(
    thread: Arc<Thread>,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    #[state] no_file_limit: CurrentNoFileLimit,
    pathname: Pointer<Path>,
    flags: OpenFlags,
    mode: u64,
) -> SyscallResult {
    openat(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        no_file_limit,
        FdNum::CWD,
        pathname,
        flags,
        mode,
    )
    .await
}

#[syscall(i386 = 6, amd64 = 3)]
fn close(#[state] fdtable: Arc<FileDescriptorTable>, fd: FdNum) -> SyscallResult {
    fdtable.close(fd)?;
    Ok(0)
}

#[syscall(i386 = 106, amd64 = 4)]
fn stat(
    thread: &mut ThreadGuard,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] mut ctx: FileAccessContext,
    filename: Pointer<Path>,
    statbuf: Pointer<Stat>,
) -> SyscallResult {
    let filename = virtual_memory.read(filename)?;

    let link = lookup_and_resolve_link(thread.process().cwd(), &filename, &mut ctx)?;
    let stat = link.node.stat()?;

    virtual_memory.write_with_abi(statbuf, stat, abi)?;

    Ok(0)
}

#[syscall(i386 = 195)]
fn stat64(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] mut ctx: FileAccessContext,
    filename: Pointer<Path>,
    statbuf: Pointer<Stat64>,
) -> SyscallResult {
    let filename = virtual_memory.read(filename)?;

    let link = lookup_and_resolve_link(thread.process().cwd(), &filename, &mut ctx)?;
    let stat = link.node.stat()?;
    let stat64 = Stat64::from(stat);

    virtual_memory.write(statbuf, stat64)?;

    Ok(0)
}

#[syscall(i386 = 108, amd64 = 5)]
fn fstat(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    statbuf: Pointer<Stat>,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let stat = fd.stat()?;

    virtual_memory.write_with_abi(statbuf, stat, abi)?;

    Ok(0)
}

#[syscall(i386 = 197)]
fn fstat64(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    statbuf: Pointer<Stat64>,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let stat = fd.stat()?;
    let stat64 = Stat64::from(stat);

    virtual_memory.write(statbuf, stat64)?;

    Ok(0)
}

#[syscall(i386 = 107, amd64 = 6)]
fn lstat(
    thread: &mut ThreadGuard,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] mut ctx: FileAccessContext,
    filename: Pointer<Path>,
    statbuf: Pointer<Stat>,
) -> SyscallResult {
    let filename = virtual_memory.read(filename)?;

    let link = lookup_link(thread.process().cwd(), &filename, &mut ctx)?;
    let stat = link.node.stat()?;

    virtual_memory.write_with_abi(statbuf, stat, abi)?;

    Ok(0)
}

#[syscall(i386 = 196)]
fn lstat64(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] mut ctx: FileAccessContext,
    filename: Pointer<Path>,
    statbuf: Pointer<Stat64>,
) -> SyscallResult {
    let filename = virtual_memory.read(filename)?;

    let link = lookup_link(thread.process().cwd(), &filename, &mut ctx)?;
    let stat = link.node.stat()?;
    let stat64 = Stat64::from(stat);

    virtual_memory.write(statbuf, stat64)?;

    Ok(0)
}

#[syscall(i386 = 168, amd64 = 7, interruptable)]
async fn poll(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fds: Pointer<Pollfd>,
    nfds: u64,
    timeout: i32,
) -> SyscallResult {
    let deadline = match timeout {
        ..=-1 => Some(None),
        0 => None,
        1.. => Some(Some(
            now(ClockId::Monotonic) + Timespec::from_ms(timeout.into()),
        )),
    };
    poll_impl(virtual_memory, fdtable, fds, nfds, deadline).await
}

async fn poll_impl(
    virtual_memory: Arc<VirtualMemory>,
    fdtable: Arc<FileDescriptorTable>,
    fds: Pointer<Pollfd>,
    nfds: u64,
    deadline: Option<Option<Timespec>>,
) -> SyscallResult {
    // Read the pollfds.
    let mut pollfds = (0..usize_from(nfds))
        .map(|i| virtual_memory.read(fds.bytes_offset(i * size_of::<Pollfd>())))
        .collect::<Result<Vec<_>>>()?;

    let mut num_non_zero = 0;
    let mut futures = FuturesUnordered::new();
    loop {
        futures.clear();

        for pollfd in pollfds.iter_mut() {
            if pollfd.fd.get() < 0 {
                pollfd.revents = PollEvents::empty();
            } else if let Ok(fd) = fdtable.get(pollfd.fd) {
                let events = Events::from(pollfd.events) | Events::HUP | Events::ERR;
                let revents = fd.poll_ready(events).map_or(Events::empty(), Events::from);
                pollfd.revents = PollEvents::from(revents);

                futures.push(async move { fd.ready(events).await });
            } else {
                pollfd.revents = PollEvents::NVAL;
            }

            if !pollfd.revents.is_empty() {
                num_non_zero += 1;
            }
        }

        // Exit if a file descriptor is ready.
        if num_non_zero != 0 {
            break;
        }

        // Exit early if non-blocking behavior was requested.
        let Some(deadline) = deadline else {
            break;
        };

        // Wait for a file descriptor to become ready or for the timeout to
        // expire.
        let ready_fut = futures.next();
        let sleep_fut = async {
            if let Some(deadline) = deadline {
                sleep_until(deadline, ClockId::Monotonic).await;
            } else {
                // Infinite timeout.
                pending::<()>().await;
            }
        };
        let ready_fut = pin!(ready_fut);
        let sleep_fut = pin!(sleep_fut);
        let res = future::select(ready_fut, sleep_fut).await;
        match res {
            Either::Left((res, _)) => {
                if res.is_some() {
                    // A file descriptor became ready.
                } else {
                    // There are no file descriptors. Exit early.
                    break;
                }
            }
            Either::Right(_) => {
                // The timeout expired.
                break;
            }
        }
    }

    // Write the results back.
    for (i, pollfd) in pollfds.into_iter().enumerate() {
        virtual_memory.write(fds.bytes_offset(i * size_of::<Pollfd>()), pollfd)?;
    }

    Ok(num_non_zero)
}

#[syscall(i386 = 19, amd64 = 8)]
fn lseek(
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    offset: u64,
    whence: Whence,
) -> SyscallResult {
    let offset = usize_from(offset);

    let fd = fdtable.get(fd)?;
    let offset = fd.seek(offset, whence)?;

    let offset = u64::from_usize(offset);
    Ok(offset)
}

#[syscall(i386 = 90, amd64 = 9)]
fn mmap(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    addr: Pointer<c_void>,
    length: u64,
    prot: ProtFlags,
    flags: MmapFlags,
    fd: u64,
    offset: u64,
) -> SyscallResult {
    let bias = if flags.contains(MmapFlags::FIXED) {
        Bias::Fixed(addr.get())
    } else {
        Bias::Dynamic(abi)
    };

    ensure!(length != 0, Inval);
    ensure!(length < (1 << 47), NoMem);
    if flags.contains(MmapFlags::ANONYMOUS) {
        ensure!(offset % 0x1000 == 0, Inval);
    }
    if let Bias::Fixed(bias) = bias {
        ensure!(bias.is_aligned(0x1000u64), Inval);
    }

    if flags.contains(MmapFlags::SHARED_VALIDATE) {
        todo!("{bias:?} {length} {prot:?} {flags:?} {fd} {offset}");
    } else if flags.contains(MmapFlags::SHARED) {
        assert!(!flags.contains(MmapFlags::ANONYMOUS));
        let fd = FdNum::parse(fd, abi)?;
        let fd = fdtable.get(fd)?;

        let permissions = MemoryPermissions::from(prot);
        let addr =
            virtual_memory
                .modify()
                .mmap_file(bias, length, fd, offset, permissions, true)?;
        Ok(addr.as_u64())
    } else if flags.contains(MmapFlags::PRIVATE) {
        if flags.contains(MmapFlags::ANONYMOUS) {
            let permissions = MemoryPermissions::from(prot);
            let addr = virtual_memory.modify().mmap_zero(bias, length, permissions);
            Ok(addr.as_u64())
        } else {
            let fd = FdNum::parse(fd, abi)?;
            let fd = fdtable.get(fd)?;

            let permissions = MemoryPermissions::from(prot);
            let addr =
                virtual_memory
                    .modify()
                    .mmap_file(bias, length, fd, offset, permissions, false)?;
            Ok(addr.as_u64())
        }
    } else {
        bail!(Inval)
    }
}

#[syscall(i386 = 192)]
fn mmap2(
    abi: Abi,
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
        abi,
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
    #[state] virtual_memory: Arc<VirtualMemory>,
    addr: Pointer<c_void>,
    len: u64,
    prot: ProtFlags,
) -> SyscallResult {
    virtual_memory
        .modify()
        .mprotect(addr.get(), len, MemoryPermissions::from(prot))?;
    Ok(0)
}

#[syscall(i386 = 91, amd64 = 11)]
fn munmap(
    #[state] virtual_memory: Arc<VirtualMemory>,
    addr: Pointer<c_void>,
    length: u64,
) -> SyscallResult {
    let addr = addr.get();
    ensure!(addr.is_aligned(0x1000u64), Inval);
    virtual_memory.modify().unmap(addr, length);
    Ok(0)
}

#[syscall(i386 = 45, amd64 = 12)]
fn brk(#[state] virtual_memory: Arc<VirtualMemory>, brk_value: u64) -> SyscallResult {
    ensure!(brk_value % 0x1000 == 0, Inval);

    if brk_value != 0 {
        if let Ok(brk_value) = VirtAddr::try_new(brk_value) {
            let _ = virtual_memory.modify().set_brk_end(brk_value);
        }
    }

    Ok(virtual_memory.brk_end().as_u64())
}

#[syscall(i386 = 174, amd64 = 13)]
fn rt_sigaction(
    thread: &mut ThreadGuard,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    signum: u64,
    act: Pointer<Sigaction>,
    oldact: Pointer<Sigaction>,
    sigsetsize: u64,
) -> SyscallResult {
    let signum = u8::try_from(signum)?;
    let signum = Signal::new(signum)?;

    // FIXME: SIGKILL and SIGSTOP are special
    // FIXME: sigsetsize

    let signal_handler_table = &thread.signal_handler_table;

    let mut old_sigaction = None;
    if !act.is_null() {
        let sigaction_in = virtual_memory.read_with_abi(act, abi)?;
        old_sigaction = Some(signal_handler_table.set(signum, sigaction_in));
    }

    if !oldact.is_null() {
        let sigaction = old_sigaction.unwrap_or_else(|| thread.signal_handler_table.get(signum));
        virtual_memory.write_with_abi(oldact, sigaction, abi)?;
    }
    Ok(0)
}

struct SysRtSigprocmask;

impl Syscall for SysRtSigprocmask {
    const NO_I386: Option<usize> = Some(175);
    const NO_AMD64: Option<usize> = Some(14);

    async fn execute(thread: Arc<Thread>, syscall_args: SyscallArgs) -> SyscallResult {
        let how = <u64 as SyscallArg>::parse(syscall_args.args[0], syscall_args.abi)?;
        let set = <Pointer<Sigset> as SyscallArg>::parse(syscall_args.args[1], syscall_args.abi)?;
        let oldset =
            <Pointer<Sigset> as SyscallArg>::parse(syscall_args.args[2], syscall_args.abi)?;

        let mut thread = thread.lock();
        let virtual_memory = thread.virtual_memory();

        if !oldset.is_null() {
            virtual_memory.write_bytes(oldset.get(), bytes_of(&thread.sigmask))?;
        }

        if !set.is_null() {
            let mut set_value = Sigset::zeroed();
            virtual_memory.read_bytes(set.get(), bytes_of_mut(&mut set_value))?;

            let how = RtSigprocmaskHow::parse(how, syscall_args.abi)?;
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
        syscall_args: SyscallArgs,
        thread: &ThreadGuard<'_>,
    ) -> fmt::Result {
        let how = syscall_args.args[0];
        let set = syscall_args.args[1];
        let oldset = syscall_args.args[2];

        write!(f, "rt_sigprocmask(set=")?;
        if set == 0 {
            write!(f, "ignored")?;
        } else {
            RtSigprocmaskHow::display(f, how, syscall_args.abi, thread)?;
        }
        write!(f, ", set=")?;
        Pointer::<Sigset>::display(f, set, syscall_args.abi, thread)?;
        write!(f, ", oldset=")?;
        Pointer::<Sigset>::display(f, oldset, syscall_args.abi, thread)?;
        write!(f, ")")
    }
}

#[syscall(i386 = 173, amd64 = 15)]
fn rt_sigreturn(
    thread: &mut ThreadGuard,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
) -> SyscallResult {
    let mut cpu_state = thread.thread.cpu_state.lock();
    (thread.sigaltstack, thread.sigmask) = cpu_state.finish_signal_handler(&virtual_memory, abi)?;
    Ok(0)
}

#[syscall(i386 = 54, amd64 = 16)]
fn ioctl(
    abi: Abi,
    thread: &mut ThreadGuard,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    cmd: u32,
    arg: Pointer<c_void>,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    fd.ioctl(thread, cmd, arg, abi)
}

#[syscall(i386 = 180, amd64 = 17)]
fn pread64(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    buf: Pointer<[u8]>,
    count: u64,
    pos: u64,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let count = usize_from(count);
    let pos = usize_from(pos);
    let mut buf = UserBuf::new(&virtual_memory, buf, count);
    let len = fd.pread(pos, &mut buf)?;
    let len = u64::from_usize(len);
    Ok(len)
}

#[syscall(i386 = 181, amd64 = 18)]
fn pwrite64(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    buf: Pointer<[u8]>,
    count: u64,
    pos: u64,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;

    let count = usize_from(count);
    let pos = usize_from(pos);
    let buf = UserBuf::new(&virtual_memory, buf, count);
    let len = fd.pwrite(pos, &buf)?;

    let len = u64::from_usize(len);
    Ok(len)
}

#[syscall(i386 = 145, amd64 = 19)]
async fn readv(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    vec: Pointer<Iovec>,
    vlen: u64,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;

    let mut vectored_buf = VectoredUserBuf::new(&virtual_memory, vec, vlen, abi)?;
    let len = do_io(&**fd, Events::READ, || fd.read(&mut vectored_buf)).await?;
    let len = u64::from_usize(len);
    Ok(len)
}

#[syscall(i386 = 146, amd64 = 20)]
async fn writev(
    thread: Arc<Thread>,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    vec: Pointer<Iovec>,
    vlen: u64,
) -> SyscallResult {
    if vlen == 0 {
        return SyscallResult::Ok(0);
    }
    let vlen = usize_from(vlen);

    let mut iovec = Iovec { base: 0, len: 0 };
    let mut vec = vec;
    for _ in 0..vlen {
        let (len, iovec_value) = virtual_memory.read_sized_with_abi(vec, abi)?;
        vec = vec.bytes_offset(len);
        if iovec_value.len != 0 {
            iovec = iovec_value;
            break;
        }
    }

    let addr = Pointer::parse(iovec.base, abi)?;
    write(thread, virtual_memory, fdtable, fd, addr, iovec.len).await
}

#[syscall(i386 = 33, amd64 = 21)]
fn access(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    pathname: Pointer<Path>,
    mode: AccessMode,
) -> SyscallResult {
    faccessat(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        FdNum::CWD,
        pathname,
        mode,
        FaccessatFlags::empty(),
    )
}

#[syscall(i386 = 42, amd64 = 22)]
fn pipe(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    #[state] no_file_limit: CurrentNoFileLimit,
    pipefd: Pointer<[FdNum; 2]>,
) -> SyscallResult {
    pipe2(
        virtual_memory,
        fdtable,
        ctx,
        no_file_limit,
        pipefd,
        Pipe2Flags::empty(),
    )
}

#[syscall(i386 = 82, amd64 = 23, interruptable)]
async fn select(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    numfds: i32,
    readfds: Pointer<FdSet>,
    writefds: Pointer<FdSet>,
    exceptfds: Pointer<FdSet>,
    timeout: Pointer<Timeval>,
) -> SyscallResult {
    let timeout = if !timeout.is_null() {
        let timeout = virtual_memory.read_with_abi(timeout, abi)?;
        Some(Timespec::from(timeout))
    } else {
        None
    };
    select_impl(
        virtual_memory,
        fdtable,
        numfds,
        readfds,
        writefds,
        exceptfds,
        timeout,
    )
    .await
}

async fn select_impl(
    virtual_memory: Arc<VirtualMemory>,
    fdtable: Arc<FileDescriptorTable>,
    numfds: i32,
    readfds: Pointer<FdSet>,
    writefds: Pointer<FdSet>,
    exceptfds: Pointer<FdSet>,
    timeout: Option<Timespec>,
) -> SyscallResult {
    let numfds = usize::try_from(numfds)?;

    let req_readfds = if !readfds.is_null() {
        let mut req_readfds = vec![0; numfds.div_ceil(8)];
        virtual_memory.read_bytes(readfds.get(), &mut req_readfds)?;
        Some(req_readfds)
    } else {
        None
    };
    let req_writefds = if !writefds.is_null() {
        let mut req_writefds = vec![0; numfds.div_ceil(8)];
        virtual_memory.read_bytes(writefds.get(), &mut req_writefds)?;
        Some(req_writefds)
    } else {
        None
    };
    let req_exceptfds = if !exceptfds.is_null() {
        let mut req_exceptfds = vec![0; numfds.div_ceil(8)];
        virtual_memory.read_bytes(exceptfds.get(), &mut req_exceptfds)?;
        Some(req_exceptfds)
    } else {
        None
    };

    let mut result_readfds = req_readfds
        .as_ref()
        .map(|req_readfds| vec![0; req_readfds.len()]);
    let mut result_writefds = req_writefds
        .as_ref()
        .map(|req_writefds| vec![0; req_writefds.len()]);
    let mut result_exceptfds = req_exceptfds
        .as_ref()
        .map(|req_exceptfds| vec![0; req_exceptfds.len()]);

    let deadline = timeout.map(|timeout| now(ClockId::Monotonic) + timeout);
    let mut futures = FuturesUnordered::new();

    let set = loop {
        futures.clear();

        let mut set = 0;

        for i in 0..numfds {
            let read = req_readfds
                .as_ref()
                .is_some_and(|readfds| readfds.get_bit(i));
            let write = req_writefds
                .as_ref()
                .is_some_and(|writefds| writefds.get_bit(i));
            let except = req_exceptfds
                .as_ref()
                .is_some_and(|exceptfds| exceptfds.get_bit(i));

            if !read && !write && !except {
                continue;
            }

            let mut events = Events::empty();
            events.set(Events::READ, read);
            events.set(Events::WRITE, write);
            events.set(Events::PRI, except);

            let fd = fdtable.get(FdNum::new(i as i32))?;
            let ready_events = fd.poll_ready(events).map_or(Events::empty(), Events::from);

            if ready_events.contains(Events::READ) {
                result_readfds.as_mut().unwrap().set_bit(i, true);
                set += 1;
            }
            if ready_events.contains(Events::WRITE) {
                result_writefds.as_mut().unwrap().set_bit(i, true);
                set += 1;
            }
            if ready_events.contains(Events::PRI) {
                result_exceptfds.as_mut().unwrap().set_bit(i, true);
                set += 1;
            }

            futures.push(async move { fd.ready(events).await });
        }

        if set != 0 {
            break set;
        }

        if let Some(deadline) = deadline {
            // If there are no fds to select from, just sleep and return.
            if futures.is_empty() {
                sleep_until(deadline, ClockId::Monotonic).await;
                break 0;
            }

            let sleep_until = pin!(sleep_until(deadline, ClockId::Monotonic));
            let res = future::select(futures.next(), sleep_until).await;

            // Break out of the loop if the timeout expired.
            if matches!(res, Either::Right(_)) {
                break 0;
            }
        } else {
            // If there are no fds to select from, just return.
            let res = futures.next().await;
            if res.is_none() {
                break 0;
            }
        }
    };

    if let Some(result_readfds) = result_readfds {
        virtual_memory.write_bytes(readfds.get(), &result_readfds)?;
    }
    if let Some(result_writefds) = result_writefds {
        virtual_memory.write_bytes(writefds.get(), &result_writefds)?;
    }
    if let Some(result_exceptfds) = result_exceptfds {
        virtual_memory.write_bytes(exceptfds.get(), &result_exceptfds)?;
    }

    Ok(set)
}

#[syscall(i386 = 158, amd64 = 24)]
async fn sched_yield() -> SyscallResult {
    r#yield().await;
    Ok(0)
}

#[syscall(i386 = 144, amd64 = 26)]
fn msync(addr: Pointer<c_void>, len: u64, flags: u64) -> SyscallResult {
    // We don't need to do anything:
    // 1. We don't support persistent disks.
    // 2. Shared mappings always use the same backing memory used by the file.
    Ok(0)
}

#[syscall(i386 = 219, amd64 = 28)]
fn madvise(
    #[state] virtual_memory: Arc<VirtualMemory>,
    addr: Pointer<c_void>,
    len: u64,
    advice: Advice,
) -> SyscallResult {
    match advice {
        Advice::DontNeed => {
            virtual_memory.modify().discard_pages(addr.get(), len)?;
            Ok(0)
        }
        Advice::Free => {
            // Ignore the advise.
            Ok(0)
        }
    }
}

#[syscall(i386 = 41, amd64 = 32)]
fn dup(
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] no_file_limit: CurrentNoFileLimit,
    fildes: FdNum,
) -> SyscallResult {
    let fd = fdtable.get_strong(fildes)?;
    let newfd = fdtable.insert(fd, FdFlags::empty(), no_file_limit)?;

    Ok(newfd.get() as u64)
}

#[syscall(i386 = 63, amd64 = 33)]
fn dup2(
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] no_file_limit: CurrentNoFileLimit,
    oldfd: FdNum,
    newfd: FdNum,
) -> SyscallResult {
    ensure!(newfd.get() >= 0, BadF);

    let fd = fdtable.get_strong(oldfd)?;

    if oldfd != newfd {
        fdtable.replace(newfd, fd, FdFlags::empty(), no_file_limit)?;
    }

    Ok(newfd.get() as u64)
}

#[syscall(i386 = 162, amd64 = 35)]
async fn nanosleep(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    rqtp: Pointer<Timespec>,
    rmtp: Pointer<Timespec>,
) -> SyscallResult {
    let rqtp = virtual_memory.read_with_abi(rqtp, abi)?;

    let now = time::now(ClockId::Monotonic);
    let deadline = now + rqtp;
    sleep_until(deadline, ClockId::Monotonic).await;
    Ok(0)
}

#[syscall(i386 = 27, amd64 = 37)]
fn alarm(thread: &mut ThreadGuard, seconds: u32) -> SyscallResult {
    let remaining = if seconds != 0 {
        thread.process().schedule_alarm(seconds)
    } else {
        thread.process().cancel_alarm()
    };
    Ok(u64::from(remaining))
}

#[syscall(i386 = 20, amd64 = 39)]
fn getpid(thread: &mut ThreadGuard) -> SyscallResult {
    let pid = thread.process().pid;
    Ok(u64::from(pid))
}

#[syscall(i386 = 187, amd64 = 40)]
async fn sendfile(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    out: FdNum,
    r#in: FdNum,
    offset: Pointer<Offset>,
    count: u64,
) -> SyscallResult {
    let out = fdtable.get(out)?;
    let r#in = fdtable.get(r#in)?;
    let count = usize_from(count);

    let mut offset_value = if !offset.is_null() {
        let offset_value = virtual_memory.read_with_abi(offset, abi)?;
        let offset_value = usize::try_from(offset_value.0)?;
        Some(offset_value)
    } else {
        None
    };

    let mut buffer = [0; 8192];
    let mut total_len = 0;
    while total_len < count {
        let chunk_len = cmp::min(count - total_len, buffer.len());
        let buffer = &mut buffer[..chunk_len];

        let len = do_io(&**r#in, Events::READ, || {
            if let Some(offset_value) = offset_value {
                r#in.pread(offset_value, &mut KernelReadBuf::new(buffer))
            } else {
                r#in.read(&mut KernelReadBuf::new(buffer))
            }
        })
        .await?;
        let buffer = &buffer[..len];
        if buffer.is_empty() {
            break;
        }
        total_len += buffer.len();
        if let Some(offset_value) = &mut offset_value {
            *offset_value += buffer.len();
        }

        let mut buffer = buffer;
        while !buffer.is_empty() {
            let n = do_write_io(&**r#in, buffer.len(), || {
                out.write(&KernelWriteBuf::new(buffer))
            })
            .await?;
            buffer = &buffer[n..];
        }
    }

    if !offset.is_null() {
        let offset_value = i64::try_from(offset_value.unwrap())?;
        let offset_value = Offset(offset_value);
        virtual_memory.write_with_abi(offset, offset_value, abi)?;
    }

    let len = u64::from_usize(total_len);
    Ok(len)
}

#[syscall(i386 = 239)]
async fn sendfile64(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    out: FdNum,
    r#in: FdNum,
    offset: Pointer<LongOffset>,
    count: u64,
) -> SyscallResult {
    sendfile(
        Abi::Amd64,
        virtual_memory,
        fdtable,
        out,
        r#in,
        offset.cast(),
        count,
    )
    .await
}

#[syscall(i386 = 359, amd64 = 41)]
fn socket(
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    #[state] no_file_limit: CurrentNoFileLimit,
    domain: Domain,
    r#type: SocketTypeWithFlags,
    protocol: i32,
) -> SyscallResult {
    let fd = match domain {
        Domain::Unix => match r#type.socket_type {
            SocketType::Stream => fdtable.insert(
                StreamUnixSocket::new(
                    r#type.flags,
                    ctx.filesystem_user_id,
                    ctx.filesystem_group_id,
                ),
                r#type,
                no_file_limit,
            )?,
            SocketType::Dgram => bail!(NoSys),
            SocketType::Raw => todo!(),
            SocketType::Seqpacket => todo!(),
        },
        Domain::Inet => match r#type.socket_type {
            SocketType::Stream => fdtable.insert(
                TcpSocket::new(r#type, ctx.filesystem_user_id, ctx.filesystem_group_id),
                r#type,
                no_file_limit,
            )?,
            SocketType::Dgram => fdtable.insert(UdpSocket::new(r#type), r#type, no_file_limit)?,
            SocketType::Raw => todo!(),
            SocketType::Seqpacket => todo!(),
        },
        Domain::Netlink => {
            fdtable.insert(NetlinkSocket::new(r#type, protocol)?, r#type, no_file_limit)?
        }
        Domain::Unspec => bail!(OpNotSupp),
    };
    Ok(fd.get() as u64)
}

#[syscall(i386 = 362, amd64 = 42, interruptable, restartable)]
async fn connect(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    fd: FdNum,
    addr: Pointer<SocketAddr>,
    addrlen: u32,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    fd.connect(&virtual_memory, addr, usize_from(addrlen), &mut ctx)
        .await?;
    Ok(0)
}

#[syscall(amd64 = 43, interruptable, restartable)]
async fn accept(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] no_file_limit: CurrentNoFileLimit,
    fd: FdNum,
    upeer_sockaddr: Pointer<SocketAddr>,
    upeer_addrlen: Pointer<u32>,
) -> SyscallResult {
    accept4(
        virtual_memory,
        fdtable,
        no_file_limit,
        fd,
        upeer_sockaddr,
        upeer_addrlen,
        Accept4Flags::empty(),
    )
    .await
}

#[syscall(i386 = 369, amd64 = 44)]
fn sendto(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    buf: Pointer<[u8]>,
    len: u64,
    flags: SentToFlags,
    dest_addr: Pointer<SocketAddr>,
    addrlen: u64,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let len = usize_from(len);
    let addrlen = usize_from(addrlen);
    let buf = UserBuf::new(&virtual_memory, buf, len);
    let sent = fd.send_to(&virtual_memory, &buf, flags, dest_addr, addrlen)?;
    Ok(u64::try_from(sent)?)
}

#[syscall(i386 = 371, amd64 = 45, interruptable)]
async fn recv_from(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    sockfd: FdNum,
    buf: Pointer<[u8]>,
    len: u64,
    flags: RecvFromFlags,
    src_addr: Pointer<c_void>,
    addrlen: Pointer<c_void>,
) -> SyscallResult {
    assert!(src_addr.is_null());
    assert!(addrlen.is_null());

    let fd = fdtable.get(sockfd)?;

    let count = usize_from(len);
    let mut buf = UserBuf::new(&virtual_memory, buf, count);

    let events = if flags.contains(RecvFromFlags::OOB) {
        Events::PRI
    } else {
        Events::READ
    };
    let len = if !flags.contains(RecvFromFlags::DONTWAIT) {
        do_io(&**fd, events, || fd.recv_from(&mut buf, flags)).await?
    } else {
        fd.recv_from(&mut buf, flags)?
    };

    let len = u64::from_usize(len);
    Ok(len)
}

#[syscall(i386 = 370, amd64 = 46)]
async fn sendmsg(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    msg: Pointer<MsgHdr>,
    flags: SendMsgFlags,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let mut msg_hdr = virtual_memory.read_with_abi(msg, abi)?;
    let len = do_io(&**fd, Events::WRITE, || {
        fd.send_msg(&virtual_memory, abi, &mut msg_hdr, &fdtable)
    })
    .await?;
    virtual_memory.write_with_abi(msg, msg_hdr, abi)?;
    Ok(u64::from_usize(len))
}

#[syscall(i386 = 372, amd64 = 47)]
async fn recvmsg(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] no_file_limit: CurrentNoFileLimit,
    fd: FdNum,
    msg: Pointer<MsgHdr>,
    flags: RecvMsgFlags,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let mut msg_hdr = virtual_memory.read_with_abi(msg, abi)?;
    let len = do_io(&**fd, Events::READ, || {
        fd.recv_msg(&virtual_memory, abi, &mut msg_hdr, &fdtable, no_file_limit)
    })
    .await?;
    virtual_memory.write_with_abi(msg, msg_hdr, abi)?;
    Ok(u64::from_usize(len))
}

#[syscall(i386 = 373, amd64 = 48)]
fn shutdown(
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    how: ShutdownHow,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    fd.shutdown(how)?;
    Ok(0)
}

#[syscall(i386 = 361, amd64 = 49)]
fn bind(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    fd: FdNum,
    addr: Pointer<SocketAddr>,
    addrlen: u32,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    fd.bind(&virtual_memory, addr, usize_from(addrlen), &mut ctx)?;
    Ok(0)
}

#[syscall(i386 = 363, amd64 = 50)]
fn listen(#[state] fdtable: Arc<FileDescriptorTable>, fd: FdNum, backlog: i32) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let backlog = cmp::max(0, backlog) as usize;
    fd.listen(backlog)?;
    Ok(0)
}

#[syscall(i386 = 367, amd64 = 51)]
fn getsockname(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    addr: Pointer<SocketAddr>,
    addrlen: Pointer<u32>,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let max_len = virtual_memory.read(addrlen)?;
    let mut socket_name = fd.get_socket_name()?;
    let actual_len = socket_name.len() as u32;
    if max_len != actual_len {
        virtual_memory.write(addrlen, actual_len)?;
    }
    socket_name.truncate(max_len as usize);
    virtual_memory.write_bytes(addr.get(), &socket_name)?;
    Ok(0)
}

#[syscall(i386 = 368, amd64 = 52)]
fn getpeername(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    addr: Pointer<SocketAddr>,
    addrlen: Pointer<u32>,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let max_len = virtual_memory.read(addrlen)?;
    let mut socket_name = fd.get_peer_name()?;
    let actual_len = socket_name.len() as u32;
    if max_len != actual_len {
        virtual_memory.write(addrlen, actual_len)?;
    }
    socket_name.truncate(max_len as usize);
    virtual_memory.write_bytes(addr.get(), &socket_name)?;
    Ok(0)
}

#[syscall(i386 = 360, amd64 = 53)]
fn socketpair(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    #[state] no_file_limit: CurrentNoFileLimit,
    domain: Domain,
    r#type: SocketTypeWithFlags,
    protocol: i32,
    sv: Pointer<[FdNum; 2]>,
) -> SyscallResult {
    let res1;
    let res2;

    match domain {
        Domain::Unix => {
            ensure!(protocol == 0, Inval);

            match r#type.socket_type {
                SocketType::Seqpacket => {
                    let (half1, half2) = SeqPacketUnixSocket::new_pair(
                        r#type.flags,
                        ctx.filesystem_user_id,
                        ctx.filesystem_group_id,
                    );
                    res1 = fdtable.insert(half1, FdFlags::from(r#type), no_file_limit);
                    res2 = fdtable.insert(half2, FdFlags::from(r#type), no_file_limit);
                }
                SocketType::Stream => {
                    let (half1, half2) = StreamUnixSocket::new_pair(
                        r#type.flags,
                        ctx.filesystem_user_id,
                        ctx.filesystem_group_id,
                    );
                    res1 = fdtable.insert(half1, FdFlags::from(r#type), no_file_limit);
                    res2 = fdtable.insert(half2, FdFlags::from(r#type), no_file_limit);
                }
                _ => bail!(Inval),
            }
        }
        Domain::Unspec | Domain::Inet | Domain::Netlink => bail!(OpNotSupp),
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

    virtual_memory.write(sv, [fd1, fd2])?;

    Ok(0)
}

#[syscall(i386 = 366, amd64 = 54)]
fn setsockopt(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    level: i32,
    optname: i32,
    optval: Pointer<[u8]>,
    optlen: i32,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    fd.set_socket_option(virtual_memory, abi, level, optname, optval, optlen)?;
    Ok(0)
}

#[syscall(i386 = 365, amd64 = 55)]
fn getsockopt(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    level: i32,
    optname: i32,
    optval: Pointer<[u8]>,
    optlen: Pointer<i32>,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let mut value = fd.get_socket_option(abi, level, optname)?;

    let opt_len_value = virtual_memory.read(optlen)?;
    let opt_len_value = usize::try_from(opt_len_value)?;
    if opt_len_value != value.len() {
        let opt_len_value = i32::try_from(value.len())?;
        virtual_memory.write(optlen, opt_len_value)?;
    }
    value.truncate(opt_len_value);
    virtual_memory.write_bytes(optval.get(), &value)?;

    Ok(0)
}

#[syscall(i386 = 120, amd64 = 56)]
async fn clone(
    thread: Arc<Thread>,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    flags: CloneFlags,
    stack: Pointer<c_void>,
    parent_tid: Pointer<u32>,
    child_tid: Pointer<u32>,
    tls: u64,
) -> SyscallResult {
    let mut child_tid = child_tid;
    let mut tls = tls;
    // For i386 child_tid and tls are swapped.
    if let Abi::I386 = abi {
        (child_tid, tls) = (Pointer::new(tls), child_tid.get().as_u64());
    }

    let termination_signal = flags.termination_signal()?;

    let new_tid = new_tid();

    let thread = thread.lock();

    let new_process = if flags.contains(CloneFlags::THREAD) {
        None
    } else {
        let process = thread.process();
        Some(Process::new(
            new_tid,
            Arc::downgrade(process),
            termination_signal,
            process.exe.read().clone(),
            process.credentials.lock().clone(),
            process.cwd(),
            process.process_group.lock().clone(),
            *process.limits.read(),
            *process.umask.lock(),
        ))
    };

    let new_virtual_memory = if flags.contains(CloneFlags::VM) {
        None
    } else {
        Some(Arc::new((**thread.virtual_memory()).clone()?))
    };

    let new_signal_handler_table = if flags.contains(CloneFlags::SIGHAND) {
        None
    } else {
        Some(Arc::new((*thread.signal_handler_table).clone()))
    };

    let new_fdtable = if flags.contains(CloneFlags::FILES) {
        // Reuse the same files.
        fdtable
    } else {
        // Create a shallow copy of the files.
        Arc::new((*fdtable).clone())
    };

    let new_clear_child_tid = if flags.contains(CloneFlags::CHILD_CLEARTID) {
        Some(child_tid)
    } else {
        None
    };

    let new_tls = if flags.contains(CloneFlags::SETTLS) {
        Some(match abi {
            Abi::I386 => {
                let pointer = Pointer::new(tls);
                let u_info = virtual_memory.read(pointer)?;
                NewTls::UserDesc(u_info)
            }
            Abi::Amd64 => NewTls::Fs(tls),
        })
    } else {
        None
    };

    let (vfork_sender, vfork_receiver) = if flags.contains(CloneFlags::VFORK) {
        let (sender, receiver) = oneshot::new();
        (Some(sender), Some(receiver))
    } else {
        (None, None)
    };

    let new_thread = thread.clone(
        new_tid,
        new_process,
        new_virtual_memory,
        new_signal_handler_table,
        new_fdtable,
        stack.get(),
        new_clear_child_tid,
        new_tls,
        vfork_sender,
    );

    if flags.contains(CloneFlags::PARENT_SETTID) {
        virtual_memory.write(parent_tid, new_tid)?;
    }

    if flags.contains(CloneFlags::CHILD_SETTID) {
        let guard = new_thread.lock();
        let virtual_memory = guard.virtual_memory();
        virtual_memory.write(child_tid, new_tid)?;
    }

    Arc::new(new_thread).spawn();

    if let Some(vfork_receiver) = vfork_receiver {
        let _ = vfork_receiver.recv().await;
    }

    Ok(u64::from(new_tid))
}

#[syscall(i386 = 2, amd64 = 57)]
async fn fork(
    thread: Arc<Thread>,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
) -> SyscallResult {
    clone(
        thread,
        abi,
        virtual_memory,
        fdtable,
        CloneFlags::from_bits_retain(Signal::CHLD.get() as u64),
        Pointer::NULL,
        Pointer::NULL,
        Pointer::NULL,
        0,
    )
    .await
}

#[syscall(i386 = 190, amd64 = 58)]
async fn vfork(
    thread: Arc<Thread>,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
) -> SyscallResult {
    clone(
        thread,
        abi,
        virtual_memory,
        fdtable,
        CloneFlags::VM
            | CloneFlags::VFORK
            | CloneFlags::from_bits_retain(Signal::CHLD.get() as u64),
        Pointer::NULL,
        Pointer::NULL,
        Pointer::NULL,
        0,
    )
    .await
}

#[syscall(i386 = 11, amd64 = 59)]
async fn execve(
    thread: Arc<Thread>,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    #[state] stack_limit: CurrentStackLimit,
    pathname: Pointer<Path>,
    argv: Pointer<Pointer<CString>>,
    envp: Pointer<Pointer<CString>>,
) -> SyscallResult {
    let mut argv = argv;
    let mut envp = envp;

    let pathname = virtual_memory.read(pathname)?;

    let mut args = Vec::new();
    loop {
        let (len, argp) = virtual_memory.read_sized_with_abi(argv, abi)?;
        argv = argv.bytes_offset(len);

        if argp.is_null() {
            break;
        }
        args.push(virtual_memory.read_cstring(argp, 0x20000)?);
    }

    let mut envs = Vec::new();
    loop {
        let (len, envp2) = virtual_memory.read_sized_with_abi(envp, abi)?;
        envp = envp.bytes_offset(len);

        if envp2.is_null() {
            break;
        }
        envs.push(virtual_memory.read_cstring(envp2, 0x20000)?);
    }

    // Open the executable.
    let cwd = thread.process().cwd();
    let link = lookup_and_resolve_link(cwd.clone(), &pathname, &mut ctx)?;
    let stat = link.node.stat()?;
    ctx.check_permissions(&stat, Permission::Execute)?;
    let fd = link
        .node
        .open(link.location.clone(), OpenFlags::empty(), &ctx)?;

    // Create a new virtual memory and CPU state.
    let virtual_memory = VirtualMemory::new();
    let (cpu_state, exe) = virtual_memory.start_executable(
        pathname,
        link,
        &fd,
        &args,
        &envs,
        &mut ctx,
        cwd,
        stack_limit,
    )?;

    // Everything was successful, no errors can occour after this point.

    let fdtable = fdtable.prepare_for_execve();
    thread
        .process()
        .execve(virtual_memory, cpu_state, fdtable, exe);
    if let Some(vfork_parent) = thread.lock().vfork_done.take() {
        let _ = vfork_parent.send(());
    }

    // The execve syscall never returns if successful.
    core::future::pending().await
}

#[syscall(i386 = 1, amd64 = 60)]
async fn exit(thread: Arc<Thread>, status: u64) -> SyscallResult {
    thread.lock().exit(WStatus::exit(status as u8));

    core::future::pending().await
}

#[syscall(i386 = 114, amd64 = 61, interruptable, restartable)]
async fn wait4(
    thread: Arc<Thread>,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    pid: i32,
    wstatus: Pointer<WStatus>,
    options: WaitOptions,
    rusage: Pointer<Rusage>,
) -> SyscallResult {
    let no_hang = options.contains(WaitOptions::NOHANG);
    let pid = match pid {
        ..=-2 => WaitFilter::ExactPgid(-pid as u32),
        -1 => WaitFilter::Any,
        0 => WaitFilter::ExactPgid(thread.process().process_group.lock().pgid),
        1.. => WaitFilter::ExactPid(pid as u32),
    };

    let opt = thread.process().wait_for_child_death(pid, no_hang).await?;
    let Some((tid, status, usage)) = opt else {
        return Ok(0);
    };

    if !wstatus.is_null() {
        let addr = wstatus.get();
        virtual_memory.write_bytes(addr, bytes_of(&status))?;
    }

    if !rusage.is_null() {
        virtual_memory.write_with_abi(rusage, usage, abi)?;
    }

    Ok(u64::from(tid))
}

#[syscall(i386 = 37, amd64 = 62)]
fn kill(thread: &mut ThreadGuard, pid: i32, signal: Option<Signal>) -> SyscallResult {
    let sig_info = signal.map(|signal| SigInfo {
        signal,
        code: SigInfoCode::USER,
        fields: SigFields::None,
    });

    match pid {
        1.. => {
            let target = Process::find_by_pid(pid as u32).ok_or(err!(Srch))?;
            if let Some(sig_info) = sig_info {
                ensure!(
                    thread.process().can_send_signal(&target, sig_info.signal),
                    Perm
                );
                target.queue_signal(sig_info);
            }
        }
        0 => {
            let process_group = thread.process().process_group.lock();
            let guard = process_group.processes.lock();
            let processes = guard.iter().filter_map(Weak::upgrade).collect::<Vec<_>>();
            drop(guard);
            drop(process_group);

            ensure!(!processes.is_empty(), Srch);

            if let Some(sig_info) = sig_info {
                let mut processes = processes
                    .into_iter()
                    .filter(|target| thread.process().can_send_signal(target, sig_info.signal))
                    .peekable();
                processes.peek().ok_or(err!(Perm))?;
                for target in processes {
                    target.queue_signal(sig_info);
                }
            }
        }
        -1 => {
            let mut processes = Process::all().filter(|p| p.pid != 1).peekable();
            processes.peek().ok_or(err!(Srch))?;
            if let Some(sig_info) = sig_info {
                let mut processes = processes
                    .filter(|target| thread.process().can_send_signal(target, sig_info.signal))
                    .peekable();
                processes.peek().ok_or(err!(Perm))?;
                for target in processes {
                    target.queue_signal(sig_info);
                }
            }
        }
        ..-1 => {
            let process_group = thread.process().process_group.lock();
            let target = process_group
                .processes
                .lock()
                .iter()
                .filter_map(Weak::upgrade)
                .find(|p| p.pid == -pid as u32)
                .ok_or(err!(Srch))?;
            drop(process_group);
            if let Some(sig_info) = sig_info {
                ensure!(
                    thread.process().can_send_signal(&target, sig_info.signal),
                    Perm
                );
                target.queue_signal(sig_info);
            }
        }
    }
    Ok(0)
}

#[syscall(amd64 = 63)]
fn uname(#[state] virtual_memory: Arc<VirtualMemory>, fd: u64) -> SyscallResult {
    const SIZE: usize = 65;
    virtual_memory.write_bytes(VirtAddr::new(fd), &[0; SIZE * 5])?;
    for (i, bs) in [
        b"Linux\0" as &[u8],
        b"host\0",
        b"6.1.46\0",
        b"mushroom\0",
        b"x86_64\0",
        b"(none)\0",
    ]
    .into_iter()
    .enumerate()
    {
        virtual_memory.write_bytes(VirtAddr::new(fd + (i * SIZE) as u64), bs)?;
    }
    Ok(0)
}

#[syscall(i386 = 55, amd64 = 72)]
fn fcntl(
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] no_file_limit: CurrentNoFileLimit,
    fd_num: FdNum,
    cmd: FcntlCmd,
    arg: u64,
) -> SyscallResult {
    let (fd, flags) = fdtable.get_with_flags(fd_num)?;

    match cmd {
        FcntlCmd::DupFd | FcntlCmd::DupFdCloExec => {
            let fd = fdtable.get_strong(fd_num)?;
            let min = i32::try_from(arg)?;

            let mut flags = FdFlags::empty();
            flags.set(FdFlags::CLOEXEC, matches!(cmd, FcntlCmd::DupFdCloExec));

            let fd_num = fdtable.insert_after(min, fd, flags, no_file_limit)?;
            Ok(fd_num.get().try_into()?)
        }
        FcntlCmd::GetFd => Ok(flags.bits()),
        FcntlCmd::SetFd => {
            fdtable.set_flags(fd_num, FdFlags::from_bits_truncate(arg))?;
            Ok(0)
        }
        FcntlCmd::GetFl => Ok(fd.flags().bits()),
        FcntlCmd::SetFl => {
            fd.set_flags(OpenFlags::from_bits_truncate(arg));
            Ok(0)
        }
        FcntlCmd::SetLkW
        | FcntlCmd::SetOwn
        | FcntlCmd::GetOwn
        | FcntlCmd::SetOwnEx
        | FcntlCmd::GetOwnEx => {
            // TODO: Implement this
            warn!("{cmd} not implemented");
            Ok(0)
        }
    }
}

#[syscall(i386 = 221)]
fn fcntl64(
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] no_file_limit: CurrentNoFileLimit,
    fd_num: FdNum,
    cmd: FcntlCmd,
    arg: u64,
) -> SyscallResult {
    let (fd, flags) = fdtable.get_with_flags(fd_num)?;

    match cmd {
        FcntlCmd::DupFd | FcntlCmd::DupFdCloExec => {
            let fd = fdtable.get_strong(fd_num)?;
            let min = i32::try_from(arg)?;

            let mut flags = FdFlags::empty();
            flags.set(FdFlags::CLOEXEC, matches!(cmd, FcntlCmd::DupFdCloExec));

            let fd_num = fdtable.insert_after(min, fd, flags, no_file_limit)?;
            Ok(fd_num.get().try_into()?)
        }
        FcntlCmd::GetFd => Ok(flags.bits()),
        FcntlCmd::SetFd => {
            fdtable.set_flags(fd_num, FdFlags::from_bits_truncate(arg))?;
            Ok(0)
        }
        FcntlCmd::GetFl => Ok(fd.flags().bits()),
        FcntlCmd::SetFl => {
            let flags = OpenFlags::from_bits_truncate(arg);
            fd.set_flags(flags);
            Ok(0)
        }
        FcntlCmd::SetLkW
        | FcntlCmd::SetOwn
        | FcntlCmd::GetOwn
        | FcntlCmd::SetOwnEx
        | FcntlCmd::GetOwnEx => {
            // TODO: Implement this
            warn!("{cmd} not implemented");
            Ok(0)
        }
    }
}

#[syscall(i386 = 143, amd64 = 73, interruptable, restartable)]
async fn flock(
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    op: FLockOp,
) -> SyscallResult {
    let lock_shared = op.contains(FLockOp::SH);
    let lock_exclusive = op.contains(FLockOp::EX);
    let unlock = op.contains(FLockOp::UN);
    let non_blocking = op.contains(FLockOp::NB);
    // Make sure that exactly one op is set.
    ensure!(
        u8::from(lock_shared) + u8::from(lock_exclusive) + u8::from(unlock) == 1,
        Inval
    );

    let fd = fdtable.get(fd)?;
    let file_lock = fd.file_lock()?;
    if lock_shared {
        file_lock.lock_shared(non_blocking).await?;
    } else if lock_exclusive {
        file_lock.lock_exclusive(non_blocking).await?;
    } else {
        file_lock.unlock();
    }
    Ok(0)
}

#[syscall(i386 = 118, amd64 = 74)]
fn fsync(#[state] fdtable: Arc<FileDescriptorTable>, fd: FdNum) -> SyscallResult {
    fdtable.get(fd)?;
    Ok(0)
}

#[syscall(i386 = 148, amd64 = 75)]
fn fdatasync(#[state] fdtable: Arc<FileDescriptorTable>, fd: FdNum) -> SyscallResult {
    fdtable.get(fd)?;
    Ok(0)
}

#[syscall(i386 = 93, amd64 = 77)]
fn ftruncate(#[state] fdtable: Arc<FileDescriptorTable>, fd: FdNum, length: u64) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    fd.truncate(usize_from(length))?;
    Ok(0)
}

#[syscall(i386 = 141, amd64 = 78)]
fn getdents(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    fd: FdNum,
    dirent: Pointer<[OldDirEntry]>,
    count: u64,
) -> SyscallResult {
    let capacity = usize_from(count);
    let fd = fdtable.get(fd)?;
    let entries = fd.getdents64(capacity, &mut ctx)?;
    let entries = entries.into_iter().map(OldDirEntry).collect::<Vec<_>>();

    let len = virtual_memory.write_with_abi(dirent, &*entries, abi)?;
    let len = u64::from_usize(len);
    Ok(len)
}

#[syscall(i386 = 17, amd64 = 79)]
fn getcwd(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    path: Pointer<Path>,
    size: u64,
) -> SyscallResult {
    let cwd = thread.process().cwd().location.path()?;
    let mut bytes = cwd.as_bytes().to_vec();
    bytes.push(0); // Add null terminator.
    let len = bytes.len();
    ensure!(len <= usize_from(size), Range);
    virtual_memory.write_bytes(path.get(), &bytes)?;
    Ok(u64::from_usize(len))
}

#[syscall(i386 = 12, amd64 = 80)]
fn chdir(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] mut ctx: FileAccessContext,
    path: Pointer<Path>,
) -> SyscallResult {
    let path = virtual_memory.read(path)?;
    let new_cwd = lookup_and_resolve_link(thread.process().cwd(), &path, &mut ctx)?;
    thread.process().chdir(new_cwd);
    Ok(0)
}

#[syscall(i386 = 133, amd64 = 81)]
fn fchdir(
    thread: &mut ThreadGuard,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    fd: FdNum,
) -> SyscallResult {
    let dirfd = fdtable.get(fd)?;
    thread.process().chdir(dirfd.as_dir(&mut ctx)?);
    Ok(0)
}

#[syscall(i386 = 38, amd64 = 82)]
fn rename(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    oldname: Pointer<Path>,
    newname: Pointer<Path>,
) -> SyscallResult {
    renameat(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        FdNum::CWD,
        oldname,
        FdNum::CWD,
        newname,
    )
}

#[syscall(i386 = 39, amd64 = 83)]
fn mkdir(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    pathname: Pointer<Path>,
    mode: u64,
) -> SyscallResult {
    mkdirat(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        FdNum::CWD,
        pathname,
        mode,
    )
}

#[syscall(i386 = 40, amd64 = 84)]
fn rmdir(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] mut ctx: FileAccessContext,
    pathname: Pointer<Path>,
) -> SyscallResult {
    let pathname = virtual_memory.read(pathname)?;
    let start_dir = thread.process().cwd();
    unlink_dir(start_dir, &pathname, &mut ctx)?;
    Ok(0)
}

#[syscall(i386 = 8, amd64 = 85, interruptable, restartable)]
async fn creat(
    thread: Arc<Thread>,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    #[state] no_file_limit: CurrentNoFileLimit,
    pathname: Pointer<Path>,
    mode: u64,
) -> SyscallResult {
    open(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        no_file_limit,
        pathname,
        OpenFlags::CREAT | OpenFlags::WRONLY | OpenFlags::TRUNC,
        mode,
    )
    .await
}

#[syscall(i386 = 9, amd64 = 86)]
fn link(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    oldpath: Pointer<Path>,
    newpath: Pointer<Path>,
) -> SyscallResult {
    linkat(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        FdNum::CWD,
        oldpath,
        FdNum::CWD,
        newpath,
        LinkOptions::empty(),
    )
}

#[syscall(i386 = 10, amd64 = 87)]
fn unlink(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    pathname: Pointer<Path>,
) -> SyscallResult {
    unlinkat(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        FdNum::CWD,
        pathname,
        UnlinkOptions::empty(),
    )
}

#[syscall(i386 = 83, amd64 = 88)]
fn symlink(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    oldname: Pointer<Path>,
    newname: Pointer<Path>,
) -> SyscallResult {
    symlinkat(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        oldname,
        FdNum::CWD,
        newname,
    )
}

#[syscall(i386 = 85, amd64 = 89)]
fn readlink(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    pathname: Pointer<Path>,
    buf: Pointer<[u8]>,
    bufsiz: u64,
) -> SyscallResult {
    readlinkat(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        FdNum::CWD,
        pathname,
        buf,
        bufsiz,
    )
}

#[syscall(i386 = 15, amd64 = 90)]
fn chmod(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    filename: Pointer<Path>,
    mode: u64,
) -> SyscallResult {
    fchmodat(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        FdNum::CWD,
        filename,
        mode,
    )
}

#[syscall(i386 = 94, amd64 = 91)]
fn fchmod(
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    fd: FdNum,
    mode: u64,
) -> SyscallResult {
    let mode = FileMode::from_bits_truncate(mode);
    let fd = fdtable.get(fd)?;
    fd.chmod(mode, &ctx)?;
    fd.update_times(now(ClockId::Realtime), None, None);
    Ok(0)
}

#[syscall(i386 = 212, amd64 = 92)]
fn chown(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    filename: Pointer<Path>,
    user: Uid,
    group: Gid,
) -> SyscallResult {
    fchownat(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        FdNum::CWD,
        filename,
        user,
        group,
        FchownatFlags::empty(),
    )
}

#[syscall(i386 = 207, amd64 = 93)]
fn fchown(
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    fd: FdNum,
    user: Uid,
    group: Gid,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    fd.chown(user, group, &ctx)?;
    Ok(0)
}

#[syscall(i386 = 198, amd64 = 94)]
fn lchown(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    filename: Pointer<Path>,
    user: Uid,
    group: Gid,
) -> SyscallResult {
    fchownat(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        FdNum::CWD,
        filename,
        user,
        group,
        FchownatFlags::SYMLINK_NOFOLLOW,
    )
}

#[syscall(i386 = 60, amd64 = 95)]
fn umask(thread: &mut ThreadGuard, mask: u64) -> SyscallResult {
    let umask = FileMode::from_bits_truncate(mask);
    let old = core::mem::replace(&mut *thread.process().umask.lock(), umask);
    SyscallResult::Ok(old.bits())
}

#[syscall(i386 = 78, amd64 = 96)]
fn gettimeofday(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    tv: Pointer<Timeval>,
    tz: Pointer<c_void>,
) -> SyscallResult {
    if !tz.is_null() {
        todo!();
    }

    if !tv.is_null() {
        let time = now(ClockId::Realtime);
        let time = Timeval::from(time);
        virtual_memory.write_with_abi(tv, time, abi)?;
    }

    Ok(0)
}

#[syscall(i386 = 76, amd64 = 97)]
fn getrlimit(
    thread: &mut ThreadGuard,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    resource: Resource,
    rlim: Pointer<RLimit>,
) -> SyscallResult {
    let value = thread.process().limits.read()[resource];
    virtual_memory.write_with_abi(rlim, value, abi)?;
    Ok(0)
}

#[syscall(i386 = 77, amd64 = 98)]
async fn getrusage(
    abi: Abi,
    thread: Arc<Thread>,
    #[state] virtual_memory: Arc<VirtualMemory>,
    who: GetRusageWho,
    usage: Pointer<Rusage>,
) -> SyscallResult {
    let value = match who {
        GetRusageWho::Self_ => {
            let process = thread.process();
            let threads = process
                .threads
                .lock()
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>();
            threads
                .iter()
                .map(|thread| thread.lock().get_rusage())
                .fold(Rusage::default(), Rusage::merge)
        }
        GetRusageWho::Children => *thread.process().children_usage.lock(),
        GetRusageWho::Thread => thread.lock().get_rusage(),
    };
    virtual_memory.write_with_abi(usage, value, abi)?;
    Ok(0)
}

#[syscall(i386 = 116, amd64 = 99)]
fn sysinfo(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    sys_info: Pointer<SysInfo>,
) -> SyscallResult {
    // TODO: Properly fill in the values.
    virtual_memory.write_with_abi(
        sys_info,
        SysInfo {
            uptime: 123,
            loads: [123, 123, 123],
            totalram: 0x1000000000,
            freeram: 0xc00000000,
            sharedram: 0,
            bufferram: 0,
            totalswap: 0,
            freeswap: 0,
            procs: Process::all().count() as u16,
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 1,
        },
        abi,
    )?;
    Ok(0)
}

#[syscall(i386 = 199, amd64 = 102)]
fn getuid(thread: &mut ThreadGuard) -> SyscallResult {
    Ok(u64::from(
        thread.process().credentials.lock().real_user_id.get(),
    ))
}

#[syscall(i386 = 200, amd64 = 104)]
fn getgid(thread: &mut ThreadGuard) -> SyscallResult {
    Ok(u64::from(
        thread.process().credentials.lock().real_group_id.get(),
    ))
}

#[syscall(i386 = 213, amd64 = 105)]
fn setuid(thread: &mut ThreadGuard, uid: Uid) -> SyscallResult {
    let mut credentials = thread.process().credentials.lock();
    ensure!(
        credentials.is_super_user()
            || credentials.saved_set_user_id == uid
            || credentials.real_user_id == uid,
        Perm
    );
    credentials.real_user_id = uid;
    Ok(0)
}

#[syscall(i386 = 214, amd64 = 106)]
fn setgid(thread: &mut ThreadGuard, gid: Gid) -> SyscallResult {
    let mut credentials = thread.process().credentials.lock();
    ensure!(
        credentials.is_super_user()
            || credentials.saved_set_group_id == gid
            || credentials.real_group_id == gid,
        Perm
    );
    credentials.real_group_id = gid;
    Ok(0)
}

#[syscall(i386 = 201, amd64 = 107)]
fn geteuid(thread: &mut ThreadGuard) -> SyscallResult {
    Ok(u64::from(
        thread.process().credentials.lock().effective_user_id.get(),
    ))
}

#[syscall(i386 = 202, amd64 = 108)]
fn getegid(thread: &mut ThreadGuard) -> SyscallResult {
    Ok(u64::from(
        thread.process().credentials.lock().effective_group_id.get(),
    ))
}

#[syscall(i386 = 57, amd64 = 109)]
fn setpgid(thread: &mut ThreadGuard, pid: u32, pgid: u32) -> SyscallResult {
    let pid = if pid == 0 {
        thread.process().pid()
    } else {
        pid
    };
    let pgid = if pid == 0 { pgid } else { pid };

    let self_process = thread.process();

    let process = self_process.find_by_pid_in(pid).ok_or(err!(Srch))?;

    // TODO: Make sure that the children haven't execve'd.

    let mut group_guard = process.process_group.lock();

    if pgid == pid {
        // Create a new process group.
        let session = group_guard.session.lock().clone();
        *group_guard = ProcessGroup::new(pgid, session);
    } else {
        // Join an existing process group.

        // Find the other process group in the same session.
        let session_guard = group_guard.session.lock();
        let process_groups = session_guard.process_groups.lock();
        let existing_process_group = process_groups
            .iter()
            .filter_map(Weak::upgrade)
            .find(|pg| pg.pgid == pgid)
            .ok_or(err!(Perm))?;
        drop(process_groups);
        drop(session_guard);

        *group_guard = existing_process_group.clone();
    }

    Ok(0)
}

#[syscall(i386 = 64, amd64 = 110)]
fn getppid(thread: &mut ThreadGuard) -> SyscallResult {
    let ppid = thread.process().ppid();
    Ok(u64::from(ppid))
}

#[syscall(i386 = 65, amd64 = 111)]
fn getpgrp(thread: &mut ThreadGuard) -> SyscallResult {
    let pgrp = thread.process().pgrp();
    Ok(u64::from(pgrp))
}

#[syscall(i386 = 66, amd64 = 112)]
fn setsid(thread: &mut ThreadGuard) -> SyscallResult {
    let sid = thread.process().set_sid();
    Ok(u64::from(sid))
}

#[syscall(i386 = 203, amd64 = 113)]
fn setreuid(thread: &mut ThreadGuard, ruid: Uid, euid: Uid) -> SyscallResult {
    let mut credentials = thread.process().credentials.lock();
    let mut new_credentials = credentials.clone();

    if euid != Uid::UNCHANGED {
        ensure!(
            credentials.is_super_user()
                || euid == credentials.real_user_id
                || euid == credentials.effective_user_id
                || euid == credentials.saved_set_user_id,
            Perm
        );
        new_credentials.effective_user_id = euid;
        new_credentials.filesystem_user_id = euid;
    }

    if ruid != Uid::UNCHANGED {
        ensure!(
            credentials.is_super_user()
                || ruid == credentials.real_user_id
                || ruid == credentials.effective_user_id,
            Perm
        );
        new_credentials.real_user_id = euid;
    }

    if ruid != Uid::UNCHANGED || (euid != Uid::UNCHANGED && euid != credentials.real_user_id) {
        new_credentials.saved_set_user_id = new_credentials.effective_user_id;
    }

    *credentials = new_credentials;

    Ok(0)
}

#[syscall(i386 = 204, amd64 = 114)]
fn setregid(thread: &mut ThreadGuard, rguid: Gid, eguid: Gid) -> SyscallResult {
    let mut credentials = thread.process().credentials.lock();
    let mut new_credentials = credentials.clone();

    if eguid != Gid::UNCHANGED {
        ensure!(
            credentials.is_super_user()
                || eguid == credentials.real_group_id
                || eguid == credentials.effective_group_id
                || eguid == credentials.saved_set_group_id,
            Perm
        );
        new_credentials.effective_group_id = eguid;
        new_credentials.filesystem_group_id = eguid;
    }

    if rguid != Gid::UNCHANGED {
        ensure!(
            credentials.is_super_user()
                || rguid == credentials.real_group_id
                || rguid == credentials.effective_group_id,
            Perm
        );
        new_credentials.real_group_id = eguid;
    }

    if rguid != Gid::UNCHANGED || (eguid != Gid::UNCHANGED && eguid != credentials.real_group_id) {
        new_credentials.saved_set_group_id = new_credentials.effective_group_id;
    }

    *credentials = new_credentials;

    Ok(0)
}

#[syscall(i386 = 205, amd64 = 115)]
fn getgroups(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    size: i32,
    list: Pointer<Gid>,
) -> SyscallResult {
    let credentials = thread.process().credentials.lock();

    let size = usize::try_from(size)?;
    if size != 0 {
        ensure!(size >= credentials.supplementary_group_ids.len(), Inval);

        let mut list = list;
        for gid in credentials.supplementary_group_ids.iter().copied() {
            let written = virtual_memory.write(list, gid)?;
            list = list.bytes_offset(written);
        }
    }

    Ok(u64::from_usize(credentials.supplementary_group_ids.len()))
}

#[syscall(i386 = 206, amd64 = 116)]
fn setgroups(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    size: i32,
    list: Pointer<Gid>,
) -> SyscallResult {
    let mut credentials = thread.process().credentials.lock();

    ensure!(credentials.is_super_user(), Perm);

    let size = usize::try_from(size)?;
    const NGROUPS_MAX: usize = 65536;
    ensure!(size <= NGROUPS_MAX, Inval);

    let mut gids = Vec::with_capacity(size);

    let mut list = list;
    for _ in 0..size {
        let (read, gid) = virtual_memory.read_sized(list)?;
        list = list.bytes_offset(read);
        gids.push(gid);
    }
    credentials.supplementary_group_ids = Arc::from(gids);

    Ok(0)
}

#[syscall(i386 = 208, amd64 = 117)]
fn setresuid(thread: &mut ThreadGuard, ruid: Uid, euid: Uid, suid: Uid) -> SyscallResult {
    let mut credentials = thread.process().credentials.lock();
    let mut new_credentials = credentials.clone();

    for (dest, src) in [
        (&mut new_credentials.real_user_id, ruid),
        (&mut new_credentials.effective_user_id, euid),
        (&mut new_credentials.saved_set_user_id, suid),
    ] {
        if src == Uid::UNCHANGED {
            continue;
        }
        ensure!(
            credentials.is_super_user()
                || src == credentials.real_user_id
                || src == credentials.effective_user_id
                || src == credentials.saved_set_user_id,
            Perm
        );
        *dest = src;
    }
    new_credentials.filesystem_user_id = new_credentials.effective_user_id;

    *credentials = new_credentials;
    Ok(0)
}

#[syscall(i386 = 209, amd64 = 118)]
fn getresuid(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    ruid: Pointer<Uid>,
    euid: Pointer<Uid>,
    suid: Pointer<Uid>,
) -> SyscallResult {
    let credentials = thread.process().credentials.lock();
    virtual_memory.write(ruid, credentials.real_user_id)?;
    virtual_memory.write(euid, credentials.effective_user_id)?;
    virtual_memory.write(suid, credentials.saved_set_user_id)?;
    Ok(0)
}

#[syscall(i386 = 210, amd64 = 119)]
fn setresgid(thread: &mut ThreadGuard, rgid: Gid, egid: Gid, sgid: Gid) -> SyscallResult {
    let mut credentials = thread.process().credentials.lock();
    let mut new_credentials = credentials.clone();

    for (dest, src) in [
        (&mut new_credentials.real_group_id, rgid),
        (&mut new_credentials.effective_group_id, egid),
        (&mut new_credentials.saved_set_group_id, sgid),
    ] {
        if src == Gid::UNCHANGED {
            continue;
        }
        ensure!(
            credentials.is_super_user()
                || src == credentials.real_group_id
                || src == credentials.effective_group_id
                || src == credentials.saved_set_group_id,
            Perm
        );
        *dest = src;
    }
    new_credentials.filesystem_group_id = new_credentials.effective_group_id;

    *credentials = new_credentials;
    Ok(0)
}

#[syscall(i386 = 211, amd64 = 120)]
fn getresgid(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    rgid: Pointer<Gid>,
    egid: Pointer<Gid>,
    sgid: Pointer<Gid>,
) -> SyscallResult {
    let credentials = thread.process().credentials.lock();
    virtual_memory.write(rgid, credentials.real_group_id)?;
    virtual_memory.write(egid, credentials.effective_group_id)?;
    virtual_memory.write(sgid, credentials.saved_set_group_id)?;
    Ok(0)
}

#[syscall(i386 = 132, amd64 = 121)]
fn getpgid(thread: &mut ThreadGuard, pid: u32) -> SyscallResult {
    let pgid = if pid == 0 {
        thread.process().pgrp()
    } else {
        Process::find_by_pid(pid).ok_or(err!(Srch))?.pgrp()
    };
    Ok(u64::from(pgid))
}

#[syscall(i386 = 215, amd64 = 122)]
fn setfsuid(thread: &mut ThreadGuard, fsuid: Uid) -> SyscallResult {
    let mut credentials = thread.process().credentials.lock();
    ensure!(
        credentials.is_super_user()
            || credentials.real_user_id == fsuid
            || credentials.effective_user_id == fsuid
            || credentials.saved_set_user_id == fsuid
            || credentials.filesystem_user_id == fsuid,
        Perm
    );
    credentials.filesystem_user_id = fsuid;
    Ok(0)
}

#[syscall(i386 = 216, amd64 = 123)]
fn setfsgid(thread: &mut ThreadGuard, fsgid: Gid) -> SyscallResult {
    let mut credentials = thread.process().credentials.lock();
    ensure!(
        credentials.is_super_user()
            || credentials.real_group_id == fsgid
            || credentials.effective_group_id == fsgid
            || credentials.saved_set_group_id == fsgid
            || credentials.filesystem_group_id == fsgid,
        Perm
    );
    credentials.filesystem_group_id = fsgid;
    Ok(0)
}

#[syscall(i386 = 147, amd64 = 124)]
fn getsid(thread: &mut ThreadGuard, pid: u32) -> SyscallResult {
    let sid = if pid == 0 {
        thread.process().sid()
    } else {
        Process::find_by_pid(pid).ok_or(err!(Srch))?.sid()
    };
    Ok(u64::from(sid))
}

#[syscall(i386 = 179, amd64 = 130)]
async fn rt_sigsuspend(
    thread: Arc<Thread>,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    unewset: Pointer<Sigset>,
    sigsetsize: u64,
) -> SyscallResult {
    let sigmask = virtual_memory.read_with_abi(unewset, abi)?;

    // Replace the signal mask.
    let mut guard = thread.lock();
    let old_mask = core::mem::replace(&mut guard.sigmask, sigmask);
    drop(guard);

    // Wait for the thread to be interrupted.
    let res = thread.interruptable(pending(), false).await;

    // Restore the signal mask.
    let mut guard = thread.lock();
    guard.sigmask = old_mask;

    res
}

#[syscall(i386 = 186, amd64 = 131)]
fn sigaltstack(
    thread: &mut ThreadGuard,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    ss: Pointer<Stack>,
    old_ss: Pointer<Stack>,
) -> SyscallResult {
    if !old_ss.is_null() {
        let old_ss_value = thread.sigaltstack;
        virtual_memory.write_with_abi(old_ss, old_ss_value, abi)?;
    }

    if !ss.is_null() {
        let ss_value = virtual_memory.read_with_abi(ss, abi)?;

        if ss_value.flags.contains(StackFlags::DISABLE) {
            thread.sigaltstack = Stack::default();
        } else {
            let allowed_flags = StackFlags::AUTODISARM;
            ensure!(allowed_flags.contains(ss_value.flags), Inval);
            thread.sigaltstack = ss_value;
        }
    }

    Ok(0)
}

#[syscall(i386 = 14, amd64 = 133)]
fn mknod(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    pathname: Pointer<Path>,
    mode: u64,
    dev: u32,
) -> SyscallResult {
    mknodat(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        FdNum::CWD,
        pathname,
        mode,
        dev,
    )
}

#[syscall(i386 = 99, amd64 = 137)]
fn statfs(
    abi: Abi,
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] mut ctx: FileAccessContext,
    pathname: Pointer<Path>,
    buf: Pointer<StatFs>,
) -> SyscallResult {
    let pathname = virtual_memory.read(pathname)?;
    let cwd = thread.process().cwd();
    let link = lookup_and_resolve_link(cwd, &pathname, &mut ctx)?;
    let statfs = link.node.fs()?.stat();
    virtual_memory.write_with_abi(buf, statfs, abi)?;
    Ok(0)
}

#[syscall(i386 = 100, amd64 = 138)]
fn fstatfs(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    buf: Pointer<StatFs>,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let statfs = fd.fs()?.stat();
    virtual_memory.write_with_abi(buf, statfs, abi)?;
    Ok(0)
}

fn find_priority_targets(
    thread: &mut ThreadGuard,
    which: Which,
    who: u32,
) -> Result<Vec<Arc<Thread>>> {
    let credentials_guard = thread.process().credentials.lock();
    let caller_euid = credentials_guard.effective_user_id;
    let caller_ruid = credentials_guard.real_user_id;
    drop(credentials_guard);

    let find_targets = |processes: &mut dyn Iterator<Item = Arc<Process>>| {
        let mut threads = Vec::new();

        for process in processes {
            let target_euid = process.credentials.lock().effective_user_id;
            ensure!(
                caller_euid == Uid::SUPER_USER
                    || caller_euid == target_euid
                    || caller_ruid == target_euid,
                Perm
            );
            threads.extend(process.threads.lock().iter().filter_map(Weak::upgrade));
        }

        ensure!(!threads.is_empty(), Srch);
        Ok(threads)
    };

    match which {
        Which::Process => {
            let process = if who == 0 {
                thread.process().clone()
            } else {
                Process::find_by_pid(who).ok_or(err!(Srch))?
            };
            find_targets(&mut core::iter::once(process))
        }
        Which::ProcessGroup => {
            let pgid = if who == 0 {
                thread.process().process_group.lock().pgid
            } else {
                who
            };
            find_targets(&mut Process::all().filter(|p| p.process_group.lock().pgid == pgid))
        }
        Which::User => {
            let uid = if who == 0 { caller_ruid } else { Uid::new(who) };
            find_targets(&mut (Process::all().filter(|p| p.credentials.lock().real_user_id == uid)))
        }
    }
}

#[syscall(i386 = 96, amd64 = 140)]
fn getpriority(thread: &mut ThreadGuard, which: Which, who: u32) -> SyscallResult {
    let targets = find_priority_targets(thread, which, who)?;
    let min = targets
        .into_iter()
        .map(|thread| thread.nice.load())
        .max()
        .unwrap();
    Ok(min.as_syscall_return_value())
}

#[syscall(i386 = 97, amd64 = 141)]
fn setpriority(thread: &mut ThreadGuard, which: Which, who: u32, prio: Nice) -> SyscallResult {
    let targets = find_priority_targets(thread, which, who)?;
    for thread in targets {
        thread.nice.store(prio);
    }
    Ok(0)
}

#[syscall(i386 = 172, amd64 = 157)]
fn prctl(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    op: PrctlOp,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> SyscallResult {
    match op {
        PrctlOp::SetDumpable => {
            let dumpable = arg2;
            match dumpable {
                // TODO: implement this
                0 => {}
                // TODO: implement this
                1 => {}
                _ => bail!(Inval),
            }
            Ok(0)
        }
        PrctlOp::SetName => {
            let mut buf = [0; 15];
            virtual_memory.read_bytes(VirtAddr::new(arg2), &mut buf)?;
            let mut task_comm = ArrayVec::new();
            task_comm.extend(buf.into_iter().take_while(|&b| b != 0));
            thread.set_task_comm(task_comm);
            Ok(0)
        }
        PrctlOp::GetName => {
            let name = thread.task_comm();
            let mut buf = Vec::with_capacity(16);
            buf.extend_from_slice(&name);
            buf.push(0);
            virtual_memory.write_bytes(VirtAddr::new(arg2), &buf)?;
            Ok(0)
        }
    }
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
                .set_fs_base(addr.get().as_u64());
            Ok(0)
        }
    }
}

#[syscall(i386 = 21, amd64 = 165)]
fn mount(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] mut ctx: FileAccessContext,
    dev_name: Pointer<Path>,
    dir_name: Pointer<Path>,
    r#type: Pointer<CString>,
    mode: MountFlags,
    data: Pointer<c_void>,
) -> SyscallResult {
    let _dev_name = virtual_memory.read(dev_name)?;
    let dir_name = virtual_memory.read(dir_name)?;
    let r#type = virtual_memory.read_cstring(r#type, 0x10)?;

    let create_node = match r#type.as_bytes() {
        b"devtmpfs" => devtmpfs::new,
        b"procfs" => procfs::new,
        _ => bail!(NoDev),
    };

    node::mount(&dir_name, create_node, &mut ctx)?;

    Ok(0)
}

#[syscall(i386 = 224, amd64 = 186)]
fn gettid(thread: &mut ThreadGuard) -> SyscallResult {
    let tid = thread.tid();
    Ok(u64::from(tid))
}

#[syscall(i386 = 13, amd64 = 201)]
fn time(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    tloc: Pointer<Time>,
) -> SyscallResult {
    let now = now(ClockId::Realtime);
    let tv_sec = u32::try_from(now.tv_sec).unwrap();

    if !tloc.is_null() {
        let time = Time(tv_sec);
        virtual_memory.write_with_abi(tloc, time, abi)?;
    }

    Ok(u64::from(tv_sec))
}

#[syscall(i386 = 240, amd64 = 202, interruptable, restartable)]
async fn futex(
    thread: Arc<Thread>,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    uaddr: Pointer<u32>,
    op: FutexOpWithFlags,
    val: u32,
    utime: Pointer<Timespec>,
    uaddr2: Pointer<c_void>,
    val3: u64,
) -> SyscallResult {
    let scope = if op.flags.contains(FutexFlags::PRIVATE_FLAG) {
        FutexScope::Process(thread.process().pid())
    } else {
        FutexScope::Global
    };

    match op.op {
        FutexOp::Wait => {
            assert!(utime.is_null());
            virtual_memory.futex_wait(uaddr, val, scope, None).await?;
            Ok(0)
        }
        FutexOp::Wake => {
            let woken = virtual_memory.futex_wake(uaddr, val, scope, None)?;
            Ok(u64::from(woken))
        }
        FutexOp::Fd => bail!(NoSys),
        FutexOp::Requeue => bail!(NoSys),
        FutexOp::CmpRequeue => bail!(NoSys),
        FutexOp::WakeOp => bail!(NoSys),
        FutexOp::LockPi => bail!(NoSys),
        FutexOp::UnlockPi => bail!(NoSys),
        FutexOp::TrylockPi => bail!(NoSys),
        FutexOp::WaitBitset => {
            // Set up a future that waits for the futex to be ready.
            let bitset = NonZeroU32::try_from(val3 as u32)?;
            let wait_for_futex = virtual_memory.futex_wait(uaddr, val, scope, Some(bitset));

            // Set up a future that waits for a timeout.
            let sleep_fut;
            let wait_for_deadline = if !utime.is_null() {
                let deadline = virtual_memory.read_with_abi(utime, abi)?;
                let clock_id = if op.flags.contains(FutexFlags::CLOCK_REALTIME) {
                    ClockId::Realtime
                } else {
                    ClockId::Monotonic
                };
                sleep_fut = sleep_until(deadline, clock_id);
                sleep_fut.fuse()
            } else {
                Fuse::terminated()
            };
            let mut wait_for_deadline = pin!(wait_for_deadline);

            select_biased! {
                res = wait_for_futex.fuse() => res?,
                _ = wait_for_deadline => bail!(TimedOut),
            }

            Ok(0)
        }
        FutexOp::WakeBitset => {
            let bitset = NonZeroU32::try_from(val3 as u32)?;
            let woken = virtual_memory.futex_wake(uaddr, val, scope, Some(bitset))?;
            Ok(u64::from(woken))
        }
        FutexOp::WaitRequeuePi => bail!(NoSys),
        FutexOp::CmpRequeuePi => bail!(NoSys),
        FutexOp::LockPi2 => bail!(NoSys),
    }
}

#[syscall(i386 = 241, amd64 = 203)]
fn sched_setaffinity(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    pid: u32,
    cpusetsize: u64,
    mask: Pointer<[u8]>,
) -> SyscallResult {
    let mut affinity = ApBitmap::empty();
    let len = cmp::min(size_of_val(&affinity), usize_from(cpusetsize));
    for idx in 0..len {
        let mask_value: u8 = virtual_memory.read(mask.bytes_offset(idx).cast())?;
        for bit in 0..8 {
            let idx = idx * 8 + bit;
            let Ok(idx) = u8::try_from(idx) else {
                continue;
            };
            let Some(idx) = ApIndex::try_new(idx) else {
                continue;
            };
            affinity.set(idx, mask_value.get_bit(bit));
        }
    }

    if pid == 0 {
        thread.thread.affinity.set_exact(affinity)
    } else {
        Thread::find_by_tid(pid)
            .ok_or(err!(Srch))?
            .affinity
            .set_exact(affinity)
    }

    Ok(0)
}

#[syscall(i386 = 242, amd64 = 204)]
fn sched_getaffinity(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    pid: u32,
    cpusetsize: u64,
    mask: Pointer<[u8]>,
) -> SyscallResult {
    let affinity = if pid == 0 {
        thread.thread.affinity.get_all()
    } else {
        Thread::find_by_tid(pid)
            .ok_or(err!(Srch))?
            .affinity
            .get_all()
    };
    let len = cmp::min(size_of_val(&affinity), usize_from(cpusetsize));

    for idx in 0..len {
        let mut mask_value = 0u8;
        for bit in 0..8 {
            let idx = idx * 8 + bit;
            let Ok(idx) = u8::try_from(idx) else {
                continue;
            };
            let Some(idx) = ApIndex::try_new(idx) else {
                continue;
            };
            mask_value.set_bit(bit, affinity.get(idx));
        }
        virtual_memory.write(mask.bytes_offset(idx).cast(), mask_value)?;
    }
    Ok(u64::from_usize(len))
}

#[syscall(i386 = 243, amd64 = 205)]
fn set_thread_area(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    u_info: Pointer<UserDesc>,
) -> SyscallResult {
    let u_info_pointer = u_info;
    let mut u_info = virtual_memory.read(u_info_pointer)?;

    let mut cpu_state = thread.thread.cpu_state.lock();
    let new_entry_number = cpu_state.add_user_desc(u_info)?;
    drop(cpu_state);

    if let Some(new_entry_number) = new_entry_number {
        u_info.entry_number = u32::from(new_entry_number);
        virtual_memory.write(u_info_pointer, u_info)?;
    }

    Ok(0)
}

#[syscall(i386 = 254, amd64 = 213)]
fn epoll_create(
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    #[state] no_file_limit: CurrentNoFileLimit,
    size: i32,
) -> SyscallResult {
    ensure!(size > 0, Inval);
    epoll_create1(fdtable, ctx, no_file_limit, EpollCreate1Flags::empty())
}

#[syscall(i386 = 220, amd64 = 217)]
fn getdents64(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    fd: FdNum,
    dirent: Pointer<[DirEntry]>,
    count: u64,
) -> SyscallResult {
    let capacity = usize_from(count);
    let fd = fdtable.get(fd)?;
    let entries = fd.getdents64(capacity, &mut ctx)?;

    let len = virtual_memory.write(dirent, &*entries)?;
    let len = u64::from_usize(len);
    Ok(len)
}

#[syscall(i386 = 258, amd64 = 218)]
fn set_tid_address(thread: &mut ThreadGuard, tidptr: Pointer<u32>) -> SyscallResult {
    thread.clear_child_tid = tidptr;
    Ok(u64::from(thread.tid()))
}

#[syscall(i386 = 264, amd64 = 227)]
fn clock_settime(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    clock_id: ClockId,
    tp: Pointer<Timespec>,
) -> SyscallResult {
    let time = virtual_memory.read_with_abi(tp, abi)?;
    time::set(clock_id, time)?;
    Ok(0)
}

#[syscall(i386 = 265, amd64 = 228)]
fn clock_gettime(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    clock_id: ClockId,
    tp: Pointer<Timespec>,
) -> SyscallResult {
    let time = time::now(clock_id);
    virtual_memory.write_with_abi(tp, time, abi)?;
    Ok(0)
}

#[syscall(i386 = 406, amd64 = 229)]
fn clock_getres(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    clock_id: ClockId,
    res: Pointer<Timespec>,
) -> SyscallResult {
    if !res.is_null() {
        virtual_memory.write_with_abi(
            res,
            Timespec {
                tv_sec: 0,
                tv_nsec: 1,
            },
            abi,
        )?;
    }
    Ok(0)
}

#[syscall(i386 = 407, amd64 = 230)]
async fn clock_nanosleep(
    abi: Abi,
    thread: Arc<Thread>,
    #[state] virtual_memory: Arc<VirtualMemory>,
    clock_id: ClockId,
    flags: ClockNanosleepFlags,
    request: Pointer<Timespec>,
    remain: Pointer<Timespec>,
) -> SyscallResult {
    let request = virtual_memory.read_with_abi(request, abi)?;

    let deadline = if flags.contains(ClockNanosleepFlags::TIMER_ABSTIME) {
        request
    } else {
        time::now(clock_id) + request
    };

    let res = thread
        .interruptable(
            async {
                sleep_until(deadline, clock_id).await;
                Ok(())
            },
            false,
        )
        .await;

    if res.is_err() && !remain.is_null() && !flags.contains(ClockNanosleepFlags::TIMER_ABSTIME) {
        let difference = deadline.saturating_sub(time::now(clock_id));
        virtual_memory.write_with_abi(remain, difference, abi)?;
    }

    res?;

    Ok(0)
}

#[syscall(i386 = 252, amd64 = 231)]
async fn exit_group(thread: Arc<Thread>, status: u64) -> SyscallResult {
    let process = thread.process();
    process.exit_group(WStatus::exit(status as u8));
    core::future::pending().await
}

#[syscall(i386 = 256, amd64 = 232, interruptable)]
async fn epoll_wait(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    epfd: FdNum,
    event: Pointer<[EpollEvent]>,
    maxevents: i32,
    timeout: i32,
) -> SyscallResult {
    let maxevents = usize::try_from(maxevents)?;

    let epoll = fdtable.get(epfd)?;
    let epoll_wait_fut = async move {
        let events = epoll.epoll_wait(maxevents).await?;
        assert!(events.len() <= maxevents);

        virtual_memory.write(event, &*events)?;

        let len = events.len();
        Ok(len.try_into()?)
    }
    .fuse();

    let timeout_fut = if timeout != -1 {
        let timeout = u32::try_from(timeout)?;
        let timeout = Timespec::from_ms(timeout.into());
        let deadline = now(ClockId::Monotonic) + timeout;
        sleep_until(deadline, ClockId::Monotonic).fuse()
    } else {
        Fuse::terminated()
    };

    let mut epoll_wait_fut = pin!(epoll_wait_fut);
    let mut timeout_fut = pin!(timeout_fut);
    select_biased! {
        res = epoll_wait_fut => res,
        _ = timeout_fut => Ok(0),
    }
}

#[syscall(i386 = 255, amd64 = 233)]
fn epoll_ctl(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    epfd: FdNum,
    op: EpollCtlOp,
    fd: FdNum,
    event: Pointer<EpollEvent>,
) -> SyscallResult {
    let event = if !event.is_null() {
        let event = virtual_memory.read(event)?;
        Some(event)
    } else {
        None
    };

    let epoll = fdtable.get(epfd)?;
    let fd = fdtable.get(fd)?;

    match op {
        EpollCtlOp::Add => {
            // Poll the fd once to check if it supports epoll.
            let _ = fd.epoll_ready(Events::empty())?;

            let event = event.ok_or(err!(Inval))?;
            epoll.epoll_add(fd, event)?
        }
        EpollCtlOp::Del => epoll.epoll_del(&**fd)?,
        EpollCtlOp::Mod => {
            let event = event.ok_or(err!(Inval))?;
            epoll.epoll_mod(&**fd, event)?
        }
    }

    Ok(0)
}

#[syscall(i386 = 270, amd64 = 234)]
fn tgkill(tgid: u32, pid: u32, signal: Signal) -> SyscallResult {
    let process = Process::find_by_pid(tgid).ok_or(err!(Srch))?;
    let threads = process.threads.lock();
    let thread = threads
        .iter()
        .filter_map(Weak::upgrade)
        .find(|t| t.tid() == pid)
        .ok_or(err!(Srch))?;
    thread.queue_signal(SigInfo {
        signal,
        code: SigInfoCode::USER,
        fields: SigFields::None,
    });
    Ok(0)
}

#[syscall(i386 = 291, amd64 = 253)]
fn inotify_init(
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] no_file_limit: CurrentNoFileLimit,
    #[state] ctx: FileAccessContext,
) -> SyscallResult {
    inotify_init1(fdtable, no_file_limit, ctx, InotifyInit1Flags::empty())
}

#[syscall(i386 = 292, amd64 = 254)]
fn inotify_add_watch(
    #[state] thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    fd: FdNum,
    pathname: Pointer<Path>,
    mask: InotifyMask,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let path = virtual_memory.read(pathname)?;
    let link = lookup_and_resolve_link(thread.process().cwd(), &path, &mut ctx)?;
    let wd = fd.add_watch(link.node, mask)?;
    Ok(u64::from(wd))
}

#[syscall(i386 = 293, amd64 = 255)]
fn inotify_rm_watch(
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    wd: u32,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    fd.rm_watch(wd)?;
    Ok(0)
}

/// Find the start directory for resolving `path`.
fn start_dir_for_path(
    thread: &ThreadGuard,
    fdtable: &FileDescriptorTable,
    dfd: FdNum,
    path: &Path,
    ctx: &mut FileAccessContext,
) -> Result<Link> {
    if path.is_absolute() {
        // Completly ignore `dfd` if path is absolute.
        Ok(Link::root())
    } else if dfd == FdNum::CWD {
        Ok(thread.process().cwd())
    } else {
        let fd = fdtable.get(dfd)?;
        fd.as_dir(ctx)
    }
}

#[syscall(i386 = 295, amd64 = 257, interruptable, restartable)]
async fn openat(
    thread: Arc<Thread>,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    #[state] no_file_limit: CurrentNoFileLimit,
    dfd: FdNum,
    filename: Pointer<Path>,
    flags: OpenFlags,
    mode: u64,
) -> SyscallResult {
    let filename = virtual_memory.read(filename)?;
    let start_dir = start_dir_for_path(&thread.lock(), &fdtable, dfd, &filename, &mut ctx)?;

    let fd = if flags.contains(OpenFlags::PATH) {
        let link = if flags.contains(OpenFlags::NOFOLLOW) {
            lookup_link(start_dir, &filename, &mut ctx)?
        } else {
            lookup_and_resolve_link(start_dir, &filename, &mut ctx)?
        };

        if flags.contains(OpenFlags::DIRECTORY) {
            ensure!(link.node.ty()? == FileType::Dir, NotDir);
        }

        let path_fd = PathFd::new(link);
        StrongFileDescriptor::from(path_fd)
    } else {
        let link = if flags.contains(OpenFlags::CREAT) {
            let mut mode = FileMode::from_bits_truncate(mode);
            mode &= !*thread.process().umask.lock();
            create_file(start_dir, filename.clone(), mode, flags, &mut ctx)?
        } else {
            let link = if flags.contains(OpenFlags::NOFOLLOW) {
                lookup_link(start_dir, &filename, &mut ctx)?
            } else {
                lookup_and_resolve_link(start_dir, &filename, &mut ctx)?
            };

            let stat = link.node.stat()?;
            if flags.contains(OpenFlags::WRONLY) {
                ctx.check_permissions(&stat, Permission::Write)?;
            } else if flags.contains(OpenFlags::RDWR) {
                ctx.check_permissions(&stat, Permission::Read)?;
                ctx.check_permissions(&stat, Permission::Write)?;
            } else {
                ctx.check_permissions(&stat, Permission::Read)?;
            }

            link
        };

        let fd = link
            .node
            .clone()
            .async_open(link.location.clone(), flags, &ctx)
            .await?;

        if !flags.contains(OpenFlags::NOCTTY) {
            let session = thread.process().process_group().session();
            // Check if the session still needs a controlling terminal.
            if session.controlling_terminal.get().is_none() {
                // Check if the process is the group leader.
                if thread.process().pid() == session.sid {
                    // Try to open the fd as a terminal.
                    if let Some(tty) = fd.as_tty() {
                        // Set the controlling terminal.
                        session.controlling_terminal.call_once(|| tty);
                    }
                }
            }
        }

        link.node
            .watchers()
            .send_event(InotifyMask::OPEN, None, None);
        if let Some(file_name) = link.location.file_name() {
            link.parent()
                .node
                .watchers()
                .send_event(InotifyMask::OPEN, None, Some(file_name));
        }

        fd
    };

    let fd = fdtable.insert(fd, flags, no_file_limit)?;
    Ok(fd.get() as u64)
}

#[syscall(i386 = 296, amd64 = 258)]
fn mkdirat(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    dfd: FdNum,
    pathname: Pointer<Path>,
    mode: u64,
) -> SyscallResult {
    let pathname = virtual_memory.read(pathname)?;
    let start_dir = start_dir_for_path(thread, &fdtable, dfd, &pathname, &mut ctx)?;

    let mut mode = FileMode::from_bits_truncate(mode);
    mode &= !*thread.process().umask.lock();
    create_directory(start_dir, &pathname, mode, &mut ctx)?;
    Ok(0)
}

#[syscall(i386 = 297, amd64 = 259)]
fn mknodat(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    dirfd: FdNum,
    pathname: Pointer<Path>,
    mode: u64,
    dev: u32,
) -> SyscallResult {
    let ty: FileType = checked::try_cast((mode >> 12) as u32)?;

    let pathname = virtual_memory.read(pathname)?;
    let start_dir = start_dir_for_path(thread, &fdtable, dirfd, &pathname, &mut ctx)?;

    let mut mode = FileMode::from_bits_truncate(mode);
    mode &= !*thread.process().umask.lock();

    match ty {
        FileType::Unknown | FileType::File => {
            create_file(
                start_dir,
                pathname,
                mode,
                OpenFlags::NOFOLLOW | OpenFlags::EXCL,
                &mut ctx,
            )?;
        }
        FileType::Fifo => create_fifo(start_dir, &pathname, mode, &mut ctx)?,
        FileType::Char => {
            ensure!(ctx.is_user(Uid::SUPER_USER), Perm);
            create_char_dev(
                start_dir,
                &pathname,
                (dev >> 8) as u16,
                dev as u8,
                mode,
                &mut ctx,
            )?
        }
        FileType::Block => {
            ensure!(ctx.is_user(Uid::SUPER_USER), Perm);
            todo!()
        }
        FileType::Socket => todo!(),
        FileType::Dir | FileType::Link => bail!(Inval),
    }

    Ok(0)
}

#[syscall(i386 = 298, amd64 = 260)]
fn fchownat(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    dfd: FdNum,
    pathname: Pointer<Path>,
    uid: Uid,
    gid: Gid,
    flags: FchownatFlags,
) -> SyscallResult {
    let path = virtual_memory.read(pathname)?;
    let start_dir = start_dir_for_path(thread, &fdtable, dfd, &path, &mut ctx)?;

    let link = if flags.contains(FchownatFlags::SYMLINK_NOFOLLOW) {
        lookup_link(start_dir, &path, &mut ctx)?
    } else {
        lookup_and_resolve_link(start_dir, &path, &mut ctx)?
    };

    link.node.chown(uid, gid, &ctx)?;
    Ok(0)
}

#[syscall(i386 = 299, amd64 = 261)]
fn futimesat(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    abi: Abi,
    dfd: FdNum,
    pathname: Pointer<Path>,
    times: Pointer<[Timeval; 2]>,
) -> SyscallResult {
    let path = virtual_memory.read(pathname)?;
    let start_dir = start_dir_for_path(thread, &fdtable, dfd, &path, &mut ctx)?;

    let now = now(ClockId::Realtime);

    let times = if !times.is_null() {
        let [atime, mtime] = virtual_memory.read_with_abi(times, abi)?;
        [atime.into(), mtime.into()]
    } else {
        [now; 2]
    };

    let ctime = now;
    let atime = Some(times[0]);
    let mtime = Some(times[1]);

    let link = lookup_and_resolve_link(start_dir, &path, &mut ctx)?;
    link.node.update_times(ctime, atime, mtime);

    Ok(0)
}

#[syscall(amd64 = 262)]
fn newfstatat(
    thread: &mut ThreadGuard,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    dfd: FdNum,
    pathname: Pointer<Path>,
    statbuf: Pointer<Stat>,
    flags: AtFlags,
) -> SyscallResult {
    if flags.contains(AtFlags::AT_EMPTY_PATH) {
        // Check if the path is empty by checking if the first character is the
        // null-terminator.
        let pathname = virtual_memory.read(pathname.cast::<u8>())?;
        if pathname == 0 {
            let stat = if dfd == FdNum::CWD {
                thread.process().cwd().node.stat()?
            } else {
                let fd = fdtable.get(dfd)?;
                fd.stat()?
            };

            virtual_memory.write_with_abi(statbuf, stat, abi)?;

            return Ok(0);
        }
    }

    let pathname = virtual_memory.read(pathname)?;
    let start_dir = start_dir_for_path(thread, &fdtable, dfd, &pathname, &mut ctx)?;

    let link = if flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW) {
        lookup_link(start_dir, &pathname, &mut ctx)?
    } else {
        lookup_and_resolve_link(start_dir, &pathname, &mut ctx)?
    };
    let stat = link.node.stat()?;

    virtual_memory.write_with_abi(statbuf, stat, abi)?;

    Ok(0)
}

#[syscall(i386 = 301, amd64 = 263)]
fn unlinkat(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    dfd: FdNum,
    pathname: Pointer<Path>,
    flags: UnlinkOptions,
) -> SyscallResult {
    let pathname = virtual_memory.read(pathname)?;
    let start_dir = start_dir_for_path(thread, &fdtable, dfd, &pathname, &mut ctx)?;

    if flags.contains(UnlinkOptions::REMOVEDIR) {
        unlink_dir(start_dir, &pathname, &mut ctx)?;
    } else {
        unlink_file(start_dir, &pathname, &mut ctx)?;
    }

    Ok(0)
}

#[syscall(i386 = 302, amd64 = 264)]
fn renameat(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    olddfd: FdNum,
    oldname: Pointer<Path>,
    newdfd: FdNum,
    newname: Pointer<Path>,
) -> SyscallResult {
    renameat2(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        olddfd,
        oldname,
        newdfd,
        newname,
        Renameat2Flags::empty(),
    )
}

#[syscall(i386 = 303, amd64 = 265)]
fn linkat(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    olddirfd: FdNum,
    oldpath: Pointer<Path>,
    newdirfd: FdNum,
    newpath: Pointer<Path>,
    flags: LinkOptions,
) -> SyscallResult {
    let oldpath = virtual_memory.read(oldpath)?;
    let newpath = virtual_memory.read(newpath)?;
    let olddir = start_dir_for_path(thread, &fdtable, olddirfd, &oldpath, &mut ctx)?;
    let newdir = start_dir_for_path(thread, &fdtable, newdirfd, &newpath, &mut ctx)?;

    hard_link(
        newdir,
        &newpath,
        olddir,
        oldpath,
        flags.contains(LinkOptions::SYMLINK_FOLLOW),
        &mut ctx,
    )?;

    Ok(0)
}

#[syscall(i386 = 304, amd64 = 266)]
fn symlinkat(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    oldname: Pointer<Path>,
    newdfd: FdNum,
    newname: Pointer<Path>,
) -> SyscallResult {
    let oldname = virtual_memory.read(oldname)?;
    let newname = virtual_memory.read(newname)?;
    let newdfd = start_dir_for_path(thread, &fdtable, newdfd, &newname, &mut ctx)?;

    create_link(newdfd, &newname, oldname, &mut ctx)?;

    Ok(0)
}

#[syscall(i386 = 305, amd64 = 267)]
fn readlinkat(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    dfd: FdNum,
    pathname: Pointer<Path>,
    buf: Pointer<[u8]>,
    bufsiz: u64,
) -> SyscallResult {
    let bufsiz = usize_from(bufsiz);

    let pathname = virtual_memory.read(pathname)?;
    let dfd = start_dir_for_path(thread, &fdtable, dfd, &pathname, &mut ctx)?;

    let target = read_soft_link(dfd, &pathname, &mut ctx)?;

    let bytes = target.as_bytes();
    // Truncate to `bufsiz`.
    let len = cmp::min(bytes.len(), bufsiz);
    let bytes = &bytes[..len];

    virtual_memory.write_bytes(buf.get(), bytes)?;

    let len = u64::from_usize(len);
    Ok(len)
}

#[syscall(i386 = 306, amd64 = 268)]
fn fchmodat(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    dfd: FdNum,
    filename: Pointer<Path>,
    mode: u64,
) -> SyscallResult {
    fchmodat2(
        thread,
        virtual_memory,
        fdtable,
        ctx,
        dfd,
        filename,
        mode,
        Fchmodat2Flags::empty(),
    )
}

#[syscall(i386 = 307, amd64 = 269)]
fn faccessat(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    dfd: FdNum,
    pathname: Pointer<Path>,
    mode: AccessMode,
    flags: FaccessatFlags,
) -> SyscallResult {
    let pathname = virtual_memory.read(pathname)?;
    let start_dir = start_dir_for_path(thread, &fdtable, dfd, &pathname, &mut ctx)?;

    let link = if flags.contains(FaccessatFlags::SYMLINK_NOFOLLOW) {
        lookup_link(start_dir, &pathname, &mut ctx)?
    } else {
        lookup_and_resolve_link(start_dir, &pathname, &mut ctx)?
    };

    if !flags.contains(FaccessatFlags::EACCESS) {
        let credentials = thread.process().credentials.lock();
        ctx.filesystem_user_id = credentials.real_user_id;
        ctx.filesystem_group_id = credentials.real_group_id;
    }

    let stat = link.node.stat()?;
    if mode.contains(AccessMode::READ) {
        ctx.check_permissions(&stat, Permission::Read)?;
    }
    if mode.contains(AccessMode::WRITE) {
        ctx.check_permissions(&stat, Permission::Write)?;
    }
    if mode.contains(AccessMode::EXECUTE) {
        ctx.check_permissions(&stat, Permission::Execute)?;
    }

    Ok(0)
}

#[syscall(i386 = 308, amd64 = 270)]
async fn pselect6(
    thread: Arc<Thread>,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    numfds: i32,
    readfds: Pointer<FdSet>,
    writefds: Pointer<FdSet>,
    exceptfds: Pointer<FdSet>,
    timeout: Pointer<Timespec>,
    sigmask: Pointer<PSelectSigsetArg>,
) -> SyscallResult {
    let mut sigmask = if !sigmask.is_null() {
        let sigmask = virtual_memory.read_with_abi(sigmask, abi)?;
        if !sigmask.ss.is_null() {
            Some(virtual_memory.read_with_abi(sigmask.ss, abi)?)
        } else {
            None
        }
    } else {
        None
    };

    // Update the signal mask.
    if let Some(sigmask) = sigmask.as_mut() {
        let mut guard = thread.lock();
        core::mem::swap(sigmask, &mut guard.sigmask);
    }

    let timeout = if !timeout.is_null() {
        let timeout = virtual_memory.read_with_abi(timeout, abi)?;
        Some(timeout)
    } else {
        None
    };

    let res = thread
        .interruptable(
            select_impl(
                virtual_memory,
                fdtable,
                numfds,
                readfds,
                writefds,
                exceptfds,
                timeout,
            ),
            false,
        )
        .await;

    // Restore the signal mask.
    if let Some(sigmask) = sigmask.as_mut() {
        let mut guard = thread.lock();
        core::mem::swap(sigmask, &mut guard.sigmask);
    }

    res
}

#[syscall(i386 = 309, amd64 = 271)]
async fn ppoll(
    thread: Arc<Thread>,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fds: Pointer<Pollfd>,
    nfds: u64,
    timeout: Pointer<Timespec>,
    sigmask: Pointer<Sigset>,
    sigsetsize: u64,
) -> SyscallResult {
    let mut sigmask = if !sigmask.is_null() {
        let sigmask = virtual_memory.read_with_abi(sigmask, abi)?;
        Some(sigmask)
    } else {
        None
    };

    // Update the signal mask.
    if let Some(sigmask) = sigmask.as_mut() {
        let mut guard = thread.lock();
        core::mem::swap(sigmask, &mut guard.sigmask);
    }

    let deadline = if !timeout.is_null() {
        Some(Some(virtual_memory.read_with_abi(timeout, abi)?))
    } else {
        Some(None)
    };

    let res = thread
        .interruptable(
            poll_impl(virtual_memory, fdtable, fds, nfds, deadline),
            false,
        )
        .await;

    // Restore the signal mask.
    if let Some(sigmask) = sigmask.as_mut() {
        let mut guard = thread.lock();
        core::mem::swap(sigmask, &mut guard.sigmask);
    }

    res
}

#[syscall(i386 = 313, amd64 = 275)]
async fn splice(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd_in: FdNum,
    off_in: Pointer<LongOffset>,
    fd_out: FdNum,
    off_out: Pointer<LongOffset>,
    len: u64,
    flags: SpliceFlags,
) -> SyscallResult {
    let len = usize_from(len);

    let fd_in = fdtable.get(fd_in)?;
    let fd_out = fdtable.get(fd_out)?;

    let read_nonblock = fd_in.flags().contains(OpenFlags::NONBLOCK);
    let pipe_read_nonblock = read_nonblock || flags.contains(SpliceFlags::NONBLOCK);
    let write_nonblock = fd_out.flags().contains(OpenFlags::NONBLOCK);
    let pipe_write_nonblock = write_nonblock || flags.contains(SpliceFlags::NONBLOCK);

    let read_half = fd_in.as_pipe_read_half();
    let write_half = fd_out.as_pipe_write_half();
    match (read_half, write_half) {
        (Some(read_half), Some(write_half)) => {
            ensure!(off_in.is_null(), SPipe);
            ensure!(off_out.is_null(), SPipe);

            loop {
                // Start wait operations on both halves.
                let read_half_wait = read_half.wait();
                let write_half_wait = write_half.wait();

                match stream_buffer::splice(read_half, write_half, len) {
                    Ok(len) => return Ok(u64::from_usize(len)),
                    Err(err) => {
                        // If the operation can't be completed right now, wait and try again.
                        match err {
                            SpliceBlockedError::Read => {
                                ensure!(!pipe_read_nonblock, Again);
                                read_half_wait.await
                            }
                            SpliceBlockedError::Write => {
                                ensure!(!pipe_write_nonblock, Again);
                                write_half_wait.await
                            }
                        }
                        continue;
                    }
                }
            }
        }
        (Some(read_half), None) => {
            ensure!(off_in.is_null(), SPipe);

            let offset = if off_out.is_null() {
                let offset = virtual_memory.read(off_out)?;
                Some(usize::try_from(offset.0)?)
            } else {
                None
            };

            loop {
                // Start a wait operation on the read half.
                let wait = read_half.wait();

                let res = fd_in.splice_from(read_half, offset, len);

                // If the operation can't be completed right now, wait and try again.
                if res
                    .as_ref()
                    .is_err_and(|err| err.kind() == ErrorKind::Again)
                {
                    ensure!(!write_nonblock, Again);
                    fd_out.ready_for_write(1).await;
                    continue;
                }

                // If the pipe wasn't ready, wait for it to be ready and try again.
                let Ok(len) = res? else {
                    ensure!(!pipe_read_nonblock, Again);
                    wait.await;
                    continue;
                };

                // Otherwise, write back the new offset and return the result.
                if let Some(offset) = offset {
                    let new_offset = offset + len;
                    virtual_memory.write(off_out, LongOffset(i64::try_from(new_offset)?))?;
                }
                return Ok(u64::from_usize(len));
            }
        }
        (None, Some(write_half)) => {
            ensure!(off_out.is_null(), SPipe);

            let offset = if off_in.is_null() {
                let offset = virtual_memory.read(off_in)?;
                Some(usize::try_from(offset.0)?)
            } else {
                None
            };

            loop {
                // Start a wait operation on the write half.
                let wait = write_half.wait();

                let res = fd_in.splice_to(write_half, offset, len);

                // If the operation can't be completed right now, wait and try again.
                if res
                    .as_ref()
                    .is_err_and(|err| err.kind() == ErrorKind::Again)
                {
                    ensure!(!read_nonblock, Again);
                    fd_in.ready(Events::READ).await;
                    continue;
                }

                // If the pipe wasn't ready, wait for it to be ready and try again.
                let Ok(len) = res? else {
                    ensure!(!pipe_write_nonblock, Again);
                    wait.await;
                    continue;
                };

                // Otherwise, write back the new offset and return the result.
                if let Some(offset) = offset {
                    let new_offset = offset + len;
                    virtual_memory.write(off_in, LongOffset(i64::try_from(new_offset)?))?;
                }
                return Ok(u64::from_usize(len));
            }
        }
        (None, None) => bail!(Inval),
    }
}

#[syscall(i386 = 320, amd64 = 280)]
fn utimensat(
    thread: &mut ThreadGuard,
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    dfd: FdNum,
    pathname: Pointer<Path>,
    times: Pointer<[Timespec; 2]>,
    flags: AtFlags,
) -> SyscallResult {
    let now = now(ClockId::Realtime);

    let path = if !pathname.is_null() {
        Some(virtual_memory.read(pathname)?)
    } else {
        None
    };
    let times = if !times.is_null() {
        virtual_memory.read_with_abi(times, abi)?
    } else {
        [now; 2]
    };

    let ctime = now;
    let atime = match times[0].tv_nsec {
        Timespec::UTIME_NOW => Some(now),
        Timespec::UTIME_OMIT => None,
        _ => Some(times[0]),
    };
    let mtime = match times[1].tv_nsec {
        Timespec::UTIME_NOW => Some(now),
        Timespec::UTIME_OMIT => None,
        _ => Some(times[1]),
    };

    if let Some(path) = path {
        let start_dir = start_dir_for_path(thread, &fdtable, dfd, &path, &mut ctx)?;
        let link = if !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW) {
            lookup_and_resolve_link(start_dir, &path, &mut ctx)?
        } else {
            lookup_link(start_dir, &path, &mut ctx)?
        };

        let stat = link.node.stat()?;
        ensure!(
            ctx.is_user(stat.uid) || ctx.check_permissions(&stat, Permission::Write).is_ok(),
            Acces
        );

        link.node.update_times(ctime, atime, mtime);
    } else {
        let fd = fdtable.get(dfd)?;

        let stat = fd.stat()?;
        ensure!(
            ctx.is_user(stat.uid) || ctx.check_permissions(&stat, Permission::Write).is_ok(),
            Acces
        );

        fd.update_times(ctime, atime, mtime);
    }

    Ok(0)
}

#[syscall(i386 = 319, amd64 = 281)]
async fn epoll_pwait(
    abi: Abi,
    thread: Arc<Thread>,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    epfd: FdNum,
    event: Pointer<[EpollEvent]>,
    maxevents: i32,
    timeout: i32,
    sigmask: Pointer<Sigset>,
    sigsetsize: u64,
) -> SyscallResult {
    let mut old_mask = None;

    // If the sigmask parameter is not null, replace the signal mask.
    if !sigmask.is_null() {
        let sigmask = virtual_memory.read_with_abi(sigmask, abi)?;

        // Replace the signal mask.
        let mut guard = thread.lock();
        old_mask = Some(core::mem::replace(&mut guard.sigmask, sigmask));
        drop(guard);
    }

    // Execute epoll_wait.
    let res = thread
        .interruptable(
            epoll_wait(virtual_memory, fdtable, epfd, event, maxevents, timeout),
            false,
        )
        .await;

    // If the signal mask was changed, restore the old one.
    if let Some(old_mask) = old_mask {
        // Restore the signal mask.
        let mut guard = thread.lock();
        guard.sigmask = old_mask;
    }

    res
}

#[syscall(i386 = 364, amd64 = 288, interruptable, restartable)]
async fn accept4(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] no_file_limit: CurrentNoFileLimit,
    fd: FdNum,
    upeer_sockaddr: Pointer<SocketAddr>,
    upeer_addrlen: Pointer<u32>,
    flags: Accept4Flags,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;
    let (socket, mut addr) = do_io(&**fd, Events::READ, || fd.accept(flags)).await?;
    let fd_num = fdtable.insert(socket, flags, no_file_limit)?;

    if !upeer_sockaddr.is_null() {
        let addr_len = virtual_memory.read(upeer_addrlen)?;
        let addr_len = usize_from(addr_len);
        if addr_len != addr.len() {
            virtual_memory.write(upeer_addrlen, addr_len as u32)?;
        }

        addr.truncate(addr_len);
        virtual_memory.write_bytes(upeer_sockaddr.get(), &addr)?;
    }

    Ok(fd_num.get() as u64)
}

#[syscall(i386 = 323, amd64 = 290)]
fn eventfd(
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    #[state] no_file_limit: CurrentNoFileLimit,
    initval: u32,
    flags: EventFdFlags,
) -> SyscallResult {
    let fd_num = fdtable.insert(
        EventFd::new(initval, ctx.filesystem_user_id, ctx.filesystem_group_id),
        flags,
        no_file_limit,
    )?;
    Ok(fd_num.get().try_into().unwrap())
}

#[syscall(i386 = 329, amd64 = 291)]
fn epoll_create1(
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    #[state] no_file_limit: CurrentNoFileLimit,
    flags: EpollCreate1Flags,
) -> SyscallResult {
    let fd_num = fdtable.insert(
        Epoll::new(ctx.filesystem_user_id, ctx.filesystem_group_id),
        flags,
        no_file_limit,
    )?;
    Ok(fd_num.get().try_into().unwrap())
}

#[syscall(i386 = 330, amd64 = 292)]
fn dup3(
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] no_file_limit: CurrentNoFileLimit,
    oldfd: FdNum,
    newfd: FdNum,
    flags: Dup3Flags,
) -> SyscallResult {
    ensure!(oldfd != newfd, Inval);
    let fd = fdtable.get_strong(oldfd)?;
    fdtable.replace(newfd, fd, flags, no_file_limit)?;
    Ok(newfd.get() as u64)
}

#[syscall(i386 = 331, amd64 = 293)]
fn pipe2(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] ctx: FileAccessContext,
    #[state] no_file_limit: CurrentNoFileLimit,
    pipefd: Pointer<[FdNum; 2]>,
    flags: Pipe2Flags,
) -> SyscallResult {
    let (read_half, write_half) =
        pipe::anon::new(flags, ctx.filesystem_user_id, ctx.filesystem_group_id);

    // Insert the first read half.
    let read_half = fdtable.insert(read_half, flags, no_file_limit)?;
    // Insert the second write half.
    let res = fdtable.insert(write_half, flags, no_file_limit);
    // Ensure that we close the first fd, if inserting the second failed.
    if res.is_err() {
        let _ = fdtable.close(read_half);
    }
    let write_half = res?;

    virtual_memory.write(pipefd, [read_half, write_half])?;

    Ok(0)
}

#[syscall(i386 = 332, amd64 = 294)]
fn inotify_init1(
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] no_file_limit: CurrentNoFileLimit,
    #[state] ctx: FileAccessContext,
    flags: InotifyInit1Flags,
) -> SyscallResult {
    let fd = fdtable.insert(
        Inotify::new(
            flags.into(),
            ctx.filesystem_user_id,
            ctx.filesystem_group_id,
        ),
        flags,
        no_file_limit,
    )?;
    Ok(fd.get() as u64)
}

#[syscall(i386 = 333, amd64 = 295)]
async fn preadv(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    vec: Pointer<Iovec>,
    vlen: u64,
    pos_l: u32,
    pos_h: u32,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;

    let mut vectored_buf = VectoredUserBuf::new(&virtual_memory, vec, vlen, abi)?;
    let pos = usize_from(pos_h) << 32 | usize_from(pos_l);
    let len = do_io(&**fd, Events::READ, || fd.pread(pos, &mut vectored_buf)).await?;
    let len = u64::from_usize(len);
    Ok(len)
}

#[syscall(i386 = 334, amd64 = 296)]
async fn pwritev(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    vec: Pointer<Iovec>,
    vlen: u32,
    pos_l: u32,
    pos_h: u32,
) -> SyscallResult {
    let fd = fdtable.get(fd)?;

    let vectored_buf = VectoredUserBuf::new(&virtual_memory, vec, vlen, abi)?;
    let pos = usize_from(pos_h) << 32 | usize_from(pos_l);
    let len = do_write_io(&**fd, vectored_buf.buffer_len(), || {
        fd.pwrite(pos, &vectored_buf)
    })
    .await?;
    let len = u64::from_usize(len);
    Ok(len)
}

#[syscall(i386 = 337, amd64 = 299)]
async fn recvmmsg(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] no_file_limit: CurrentNoFileLimit,
    fd: FdNum,
    msgvec: Pointer<MMsgHdr>,
    n: u32,
    flags: RecvMMsgFlags,
    timeout: Pointer<Timespec>,
) -> SyscallResult {
    let socket = fdtable.get(fd)?;

    let timeout_fut = if !timeout.is_null() {
        let timeout = virtual_memory.read_with_abi(timeout, abi)?;
        sleep_until(
            now(ClockId::Monotonic).saturating_add(timeout),
            ClockId::Monotonic,
        )
        .fuse()
    } else {
        Fuse::terminated()
    };
    let mut timeout_fut = pin!(timeout_fut);

    let mut msgvec = msgvec;
    let n = usize_from(n);
    let mut i = 0;
    let n = loop {
        if i >= n {
            break i;
        }

        let (offset, mut msg_header) = virtual_memory.read_sized_with_abi(msgvec, abi)?;

        let res = {
            let recv_fut = do_io(&**socket, Events::READ, || {
                socket.recv_msg(
                    &virtual_memory,
                    abi,
                    &mut msg_header.hdr,
                    &fdtable,
                    no_file_limit,
                )
            });
            let recv_fut = pin!(recv_fut);
            let Either::Left((res, _)) = future::select(recv_fut, &mut timeout_fut).await else {
                break i;
            };
            res
        };

        match res {
            Ok(len) => {
                msg_header.len = len as u32;
                virtual_memory.write_with_abi(msgvec, msg_header, abi)?;
                msgvec = msgvec.bytes_offset(offset);
                i += 1;
            }
            Err(err) => break i.checked_sub(1).ok_or(err)?,
        }
    };
    Ok(u64::from_usize(n))
}

#[syscall(i386 = 340, amd64 = 302)]
fn prlimit64(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    pid: u32,
    resource: Resource,
    new_rlim: Pointer<RLimit64>,
    old_rlim: Pointer<RLimit64>,
) -> SyscallResult {
    let process = if pid != 0 {
        Process::find_by_pid(pid).ok_or(err!(Srch))?
    } else {
        thread.process().clone()
    };

    let mut guard = process.limits.write();

    if !old_rlim.is_null() {
        let value = guard[resource];
        let value = RLimit64::from(value);
        virtual_memory.write(old_rlim, value)?;
    }

    if !new_rlim.is_null() {
        let value = virtual_memory.read(new_rlim)?;
        let value = RLimit::try_from(value)?;
        let limit = &mut guard[resource];

        // Make sure that the limit is well-formed.
        ensure!(value.rlim_cur <= value.rlim_max, Inval);

        // Make sure that the user can set the hard limit.
        if thread.process().credentials.lock().effective_user_id != Uid::SUPER_USER {
            ensure!(value.rlim_max <= limit.rlim_max, Perm);
        }

        *limit = value;
    }

    Ok(0)
}

#[syscall(i386 = 345, amd64 = 307)]
async fn sendmmsg(
    abi: Abi,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd: FdNum,
    msgvec: Pointer<MMsgHdr>,
    n: u32,
    flags: SendMsgFlags,
) -> SyscallResult {
    let socket = fdtable.get(fd)?;

    let mut msgvec = msgvec;
    let n = usize_from(n);
    let mut i = 0;
    let n = loop {
        if i >= n {
            break i;
        }

        let (offset, mut msg_header) = virtual_memory.read_sized_with_abi(msgvec, abi)?;

        let res = do_io(&**socket, Events::WRITE, || {
            socket.send_msg(&virtual_memory, abi, &mut msg_header.hdr, &fdtable)
        })
        .await;
        match res {
            Ok(len) => {
                msg_header.len = len as u32;
                virtual_memory.write_with_abi(msgvec, msg_header, abi)?;
                msgvec = msgvec.bytes_offset(offset);
                i += 1;
            }
            Err(err) => break i.checked_sub(1).ok_or(err)?,
        }
    };
    Ok(u64::from_usize(n))
}

#[syscall(amd64 = 309)]
fn getcpu(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    cpu: Pointer<u32>,
    node: Pointer<u32>,
) -> SyscallResult {
    if !cpu.is_null() {
        // TODO: Get the real value.
        let idx = thread.thread.affinity.get_all().into_iter().next().unwrap();
        virtual_memory.write(cpu, u32::from(idx.as_u8()))?;
    }
    if !node.is_null() {
        virtual_memory.write(cpu, 0)?;
    }
    Ok(0)
}

#[syscall(amd64 = 316)]
fn renameat2(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    olddfd: FdNum,
    oldname: Pointer<Path>,
    newdfd: FdNum,
    newname: Pointer<Path>,
    flags: Renameat2Flags,
) -> SyscallResult {
    let oldname = virtual_memory.read(oldname)?;
    let newname = virtual_memory.read(newname)?;
    let oldd = start_dir_for_path(thread, &fdtable, olddfd, &oldname, &mut ctx)?;
    let newd = start_dir_for_path(thread, &fdtable, newdfd, &newname, &mut ctx)?;

    if flags.contains(Renameat2Flags::EXCHANGE) {
        node::exchange(oldd, &oldname, newd, &newname, &mut ctx)?;
    } else {
        node::rename(
            oldd,
            &oldname,
            newd,
            &newname,
            flags.contains(Renameat2Flags::NOREPLACE),
            &mut ctx,
        )?;
    }

    Ok(0)
}

#[syscall(i386 = 355, amd64 = 318)]
fn getrandom(
    #[state] virtual_memory: Arc<VirtualMemory>,
    buf: Pointer<u8>,
    buflen: u64,
    flags: GetRandomFlags,
) -> SyscallResult {
    let mut buf = buf;

    let mut total_len = 0;
    for (_, random) in (0..buflen).zip(random_bytes()) {
        let len = virtual_memory.write(buf, random)?;
        buf = buf.bytes_offset(len);
        total_len += len;
    }
    Ok(total_len.try_into()?)
}

#[syscall(i386 = 377, amd64 = 326)]
fn copy_file_range(
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    fd_in: FdNum,
    off_in: Pointer<LongOffset>,
    fd_out: FdNum,
    off_out: Pointer<LongOffset>,
    len: u64,
    flags: CopyFileRangeFlags,
) -> SyscallResult {
    let fd_in = fdtable.get(fd_in)?;
    let fd_out = fdtable.get(fd_out)?;

    // Read the offset.
    let off_in_val = if !off_in.is_null() {
        let off_in_val = virtual_memory.read(off_in)?;
        Some(usize::try_from(off_in_val.0)?)
    } else {
        None
    };
    let off_out_val = if !off_out.is_null() {
        let off_out_val = virtual_memory.read(off_out)?;
        Some(usize::try_from(off_out_val.0)?)
    } else {
        None
    };
    let len = usize::try_from(len)?;

    // Do the copy operations.
    let len = fd_in.copy_file_range(off_in_val, &**fd_out, off_out_val, len)?;

    // Write the offset back.
    if let Some(off_in_val) = off_in_val {
        let new_offset = off_in_val + len;
        virtual_memory.write(off_in, LongOffset(i64::try_from(new_offset)?))?;
    }
    if let Some(off_out_val) = off_out_val {
        let new_offset = off_out_val + len;
        virtual_memory.write(off_out, LongOffset(i64::try_from(new_offset)?))?;
    }

    Ok(u64::from_usize(len))
}

#[syscall(i386 = 452, amd64 = 452)]
fn fchmodat2(
    thread: &mut ThreadGuard,
    #[state] virtual_memory: Arc<VirtualMemory>,
    #[state] fdtable: Arc<FileDescriptorTable>,
    #[state] mut ctx: FileAccessContext,
    dfd: FdNum,
    filename: Pointer<Path>,
    mode: u64,
    flags: Fchmodat2Flags,
) -> SyscallResult {
    let mode = FileMode::from_bits_truncate(mode);

    let path = virtual_memory.read(filename)?;
    let newdfd = start_dir_for_path(thread, &fdtable, dfd, &path, &mut ctx)?;

    let link = if flags.contains(Fchmodat2Flags::SYMLINK_NOFOLLOW) {
        lookup_link(newdfd, &path, &mut ctx)?
    } else {
        lookup_and_resolve_link(newdfd, &path, &mut ctx)?
    };
    link.node.chmod(mode, &ctx)?;
    link.node.update_times(now(ClockId::Realtime), None, None);

    Ok(0)
}
