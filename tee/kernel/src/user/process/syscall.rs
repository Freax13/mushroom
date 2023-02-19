use core::cmp;

use bitflags::bitflags;
use bytemuck::{bytes_of, bytes_of_mut, Pod, Zeroable};
use log::{debug, trace, warn};
use x86_64::VirtAddr;

use crate::{
    error::{Error, Result},
    user::process::memory::MemoryPermissions,
};

use self::traits::{Syscall1, Syscall2, Syscall3, Syscall4, Syscall6, SyscallHandlers};

use super::thread::{Sigset, Stack, StackFlags, Thread, UserspaceRegisters};

mod traits;

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
        trace!("syscall_{syscall_no}({arg0}, {arg1}, {arg2}, {arg3}, {arg4}, {arg5}) = {result:?}");

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
    handlers.register(SysPoll);
    handlers.register(SysMmap);
    handlers.register(SysMprotect);
    handlers.register(SysBrk);
    handlers.register(SysRtSigaction);
    handlers.register(SysRtSigprocmask);
    handlers.register(SysSigaltstack);
    handlers.register(SysArchPrctl);
    handlers.register(SysSetTidAddress);
    handlers.register(SysExitGroup);

    handlers
};

struct SysWrite;

impl Syscall3 for SysWrite {
    const NO: usize = 1;

    fn execute(thread: &mut Thread, _fd: u64, buf: u64, count: u64) -> Result<u64> {
        let buf = VirtAddr::new(buf);
        let count = usize::try_from(count).unwrap();

        let mut chunk = [0xffu8; 128];
        let max_chunk_len = chunk.len();
        let len = cmp::min(max_chunk_len, count);
        let chunk = &mut chunk[..len];
        thread.process().read(buf, chunk)?;

        let chunk = core::str::from_utf8(chunk);
        debug!("{chunk:02x?}");

        Ok(u64::try_from(count).unwrap())
    }
}

struct SysPoll;

impl Syscall3 for SysPoll {
    const NO: usize = 7;

    fn execute(thread: &mut Thread, fds: u64, nfds: u64, timeout: u64) -> Result<u64> {
        let process = thread.process();
        for i in 0..nfds {
            let mut pollfd = Pollfd::zeroed();
            process.read(VirtAddr::new(fds + i * 8), bytes_of_mut(&mut pollfd))?;
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

    fn execute(
        thread: &mut Thread,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: u64,
        off: u64,
    ) -> Result<u64> {
        bitflags! {
            pub struct MmapFlags: u64 {
                const SHARED = 1 << 0;
                const PRIVATE = 1 << 1;
                const SHARED_VALIDATE = 1 << 0 | 1 << 1;
                const ANONYMOUS = 1 << 5;
                const STACK = 1 << 17;
            }
        }

        // todo!("{addr} {len} {prot} {flags:x} {fd} {off}");

        let prot = ProtFlags::from_bits(prot).ok_or(Error::Inval)?;
        let flags = MmapFlags::from_bits(flags).ok_or(Error::Inval)?;

        if flags.contains(MmapFlags::SHARED_VALIDATE) {
            todo!("{addr} {len} {prot:?} {flags:?} {fd} {off}");
        } else if flags.contains(MmapFlags::SHARED) {
            todo!("{addr} {len} {prot:?} {flags:?} {fd} {off}");
        } else if flags.contains(MmapFlags::PRIVATE) {
            if flags.contains(MmapFlags::STACK) {
                assert!(flags.contains(MmapFlags::ANONYMOUS));
                assert_eq!(prot, ProtFlags::READ | ProtFlags::WRITE);

                warn!("FIXME: generate stack address dynamically");
                assert_eq!(addr, 0);
                let addr = VirtAddr::new(0x7fff_ffd0_0000);
                thread.process().allocate_stack(addr, len);
                let stack = addr + len;

                Ok(stack.as_u64())
            } else if flags.contains(MmapFlags::ANONYMOUS) {
                warn!("FIXME: generate anonymous mapping address dynamically");
                assert_eq!(addr, 0);
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

    fn execute(_thread: &mut Thread, start: u64, len: u64, prot: u64) -> Result<u64> {
        let prot = ProtFlags::from_bits(prot).ok_or(Error::Inval)?;
        warn!("FIXME: implement mprotect({start:#x}, {len:#x}, {prot:?})");
        Ok(0)
    }
}

struct SysBrk;

impl Syscall1 for SysBrk {
    const NO: usize = 12;

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

    fn execute(
        thread: &mut Thread,
        signum: u64,
        act: u64,
        oldact: u64,
        _sigsetsize: u64,
    ) -> Result<u64> {
        let signum = usize::try_from(signum).unwrap();

        // FIXME: SIGKILL and SIGSTOP are special
        // FIXME: sigsetsize

        let process = thread.process().clone();

        if oldact != 0 {
            let sigaction = thread.sigaction.get(signum).ok_or(Error::Inval)?;
            process.write(VirtAddr::new(oldact), bytes_of(sigaction))?;
        }
        if act != 0 {
            let sigaction = thread.sigaction.get_mut(signum).ok_or(Error::Inval)?;
            process.read(VirtAddr::new(act), bytes_of_mut(sigaction))?;
        }

        Ok(0)
    }
}

struct SysRtSigprocmask;

impl Syscall3 for SysRtSigprocmask {
    const NO: usize = 14;

    fn execute(thread: &mut Thread, how: u64, set: u64, oldset: u64) -> Result<u64> {
        let process = thread.process().clone();

        if oldset != 0 {
            process.write(VirtAddr::new(oldset), bytes_of(&thread.sigmask))?;
        }

        if set != 0 {
            let mut set_value = Sigset::zeroed();
            process.read(VirtAddr::new(set), bytes_of_mut(&mut set_value))?;

            match how {
                0 => {
                    // SIG_BLOCK
                    thread.sigmask |= set_value;
                }
                1 => {
                    // SIG_UNBLOCK
                    thread.sigmask &= !set_value;
                }
                2 => {
                    // SIG_SETMASK
                    thread.sigmask = set_value;
                }
                _ => {
                    warn!("unsupported how: {how}");
                    return Err(Error::Inval);
                }
            }
        }

        Ok(0)
    }
}

struct SysSigaltstack;

impl Syscall2 for SysSigaltstack {
    const NO: usize = 131;

    fn execute(thread: &mut Thread, ss: u64, old_ss: u64) -> Result<u64> {
        let process = thread.process().clone();

        if old_ss != 0 {
            let old_ss_value = thread.sigaltstack.unwrap_or_else(|| {
                let mut stack = Stack::zeroed();
                stack.flags |= StackFlags::DISABLE;
                stack
            });
            process.write(VirtAddr::new(old_ss), bytes_of(&old_ss_value));
        }

        if ss != 0 {
            let mut ss_value = Stack::zeroed();
            process.read(VirtAddr::new(ss), bytes_of_mut(&mut ss_value))?;

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

    fn execute(thread: &mut Thread, code: u64, addr: u64) -> Result<u64> {
        match code {
            0x1002 => {
                // ARCH_SET_FS
                thread.registers.fs_base = addr;
                Ok(0)
            }
            _ => {
                warn!("unsupported arch_ptctl code: {code}");
                Err(Error::Inval)
            }
        }
    }
}

struct SysSetTidAddress;

impl Syscall1 for SysSetTidAddress {
    const NO: usize = 218;

    fn execute(thread: &mut Thread, tidptr: u64) -> Result<u64> {
        thread.clear_child_tid = tidptr;
        Ok(u64::from(thread.tid))
    }
}

struct SysExitGroup;

impl Syscall1 for SysExitGroup {
    const NO: usize = 231;

    fn execute(_thread: &mut Thread, error_code: u64) -> Result<u64> {
        todo!("exit: {error_code}")
    }
}

bitflags! {
    pub struct ProtFlags: u64 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC = 1 << 2;
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct Pollfd {
    fd: i32,
    events: u16,
    revents: u16,
}
