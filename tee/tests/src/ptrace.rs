use std::{
    mem::MaybeUninit,
    process::exit,
    time::{Duration, Instant},
};

use nix::{
    Result,
    errno::Errno,
    libc::{
        self, PTRACE_GET_SYSCALL_INFO, PTRACE_SYSCALL_INFO_ENTRY, PTRACE_SYSCALL_INFO_EXIT,
        PTRACE_SYSCALL_INFO_NONE, SYS_getpid, SYS_restart_syscall, c_long, ptrace_syscall_info,
        syscall,
    },
    sys::{
        ptrace::{self, Options},
        signal::{
            Signal::{self, SIGSTOP},
            kill,
        },
        time::TimeSpec,
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    time::{ClockId, ClockNanosleepFlags, clock_nanosleep},
    unistd::{ForkResult, Pid, fork, gettid, sleep},
};

#[test]
fn seize_self() {
    let pid = gettid();
    assert_eq!(ptrace::seize(pid, Options::empty()), Err(Errno::EPERM));
}

#[test]
fn seize_while_sleeping() {
    let child = match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            sleep(1);
            exit(0);
        }
    };

    std::thread::sleep(Duration::from_millis(100));

    assert_eq!(ptrace::seize(child, Options::empty()), Ok(()));
    assert_eq!(
        waitpid(None, Some(WaitPidFlag::WNOHANG)),
        Ok(WaitStatus::StillAlive)
    );

    assert_eq!(kill(child, Signal::SIGKILL), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Signaled(child, Signal::SIGKILL, false)),
    );
}

#[test]
fn interrupt_while_sleeping() {
    let child = match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            sleep(1);
            exit(0);
        }
    };

    let start = Instant::now();

    assert_eq!(ptrace::seize(child, Options::empty()), Ok(()));
    assert_eq!(
        waitpid(None, Some(WaitPidFlag::WNOHANG)),
        Ok(WaitStatus::StillAlive)
    );

    // Wait for the child to start executing the sleep syscall.
    std::thread::sleep(Duration::from_millis(100));

    assert_eq!(ptrace::interrupt(child), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::PtraceEvent(child, Signal::SIGTRAP, 0x80)),
    );

    // Make sure that the sleep syscall was interrupted and didn't complete.
    assert!(start.elapsed() < Duration::from_secs(1));

    assert_eq!(kill(child, Signal::SIGKILL), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Signaled(child, Signal::SIGKILL, false)),
    );
}

#[test]
fn interrupt_while_sleeping_cont() {
    let child = match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            sleep(1);
            exit(0);
        }
    };

    let start = Instant::now();

    assert_eq!(ptrace::seize(child, Options::empty()), Ok(()));
    assert_eq!(
        waitpid(None, Some(WaitPidFlag::WNOHANG)),
        Ok(WaitStatus::StillAlive)
    );

    // Wait for the child to start executing the sleep syscall.
    std::thread::sleep(Duration::from_millis(100));

    assert_eq!(ptrace::interrupt(child), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::PtraceEvent(child, Signal::SIGTRAP, 0x80)),
    );

    // Make sure that the sleep syscall was interrupted and didn't complete.
    assert!(start.elapsed() < Duration::from_secs(1));

    assert_eq!(ptrace::cont(child, None), Ok(()));

    assert_eq!(kill(child, Signal::SIGKILL), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Signaled(child, Signal::SIGKILL, false)),
    );
}

#[test]
fn interrupt_while_sleeping_sysgood() {
    let child = match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            sleep(1);
            exit(0);
        }
    };

    let start = Instant::now();

    assert_eq!(ptrace::seize(child, Options::PTRACE_O_TRACESYSGOOD), Ok(()));
    assert_eq!(
        waitpid(None, Some(WaitPidFlag::WNOHANG)),
        Ok(WaitStatus::StillAlive)
    );

    // Wait for the child to start executing the sleep syscall.
    std::thread::sleep(Duration::from_millis(100));

    assert_eq!(ptrace::interrupt(child), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::PtraceEvent(child, Signal::SIGTRAP, 0x80)),
    );

    // Make sure that the sleep syscall was interrupted and didn't complete.
    assert!(start.elapsed() < Duration::from_secs(1));

    assert_eq!(kill(child, Signal::SIGKILL), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Signaled(child, Signal::SIGKILL, false)),
    );
}

#[test]
fn attach() {
    let child = match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            sleep(1);
            exit(0);
        }
    };

    assert_eq!(ptrace::attach(child), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Stopped(child, Signal::SIGSTOP)),
    );

    assert_eq!(kill(child, Signal::SIGKILL), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Signaled(child, Signal::SIGKILL, false)),
    );
}

#[test]
fn attach_syscall() {
    let child = match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            sleep(1);
            exit(0);
        }
    };

    assert_eq!(ptrace::attach(child), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Stopped(child, Signal::SIGSTOP)),
    );

    assert_eq!(ptrace::syscall(child, None), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Stopped(child, Signal::SIGTRAP)),
    );

    assert_eq!(kill(child, Signal::SIGKILL), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Signaled(child, Signal::SIGKILL, false)),
    );
}

#[test]
fn attach_syscall_sysgood() {
    let child = match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            sleep(1);
            exit(0);
        }
    };

    assert_eq!(ptrace::attach(child), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Stopped(child, Signal::SIGSTOP)),
    );

    assert_eq!(
        ptrace::setoptions(child, Options::PTRACE_O_TRACESYSGOOD),
        Ok(())
    );

    assert_eq!(ptrace::syscall(child, None), Ok(()));
    assert_eq!(waitpid(None, None), Ok(WaitStatus::PtraceSyscall(child)));

    assert_eq!(kill(child, Signal::SIGKILL), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Signaled(child, Signal::SIGKILL, false)),
    );
}

pub fn get_syscall_info(pid: Pid) -> Result<ptrace_syscall_info> {
    let mut info = MaybeUninit::uninit();
    let err = unsafe {
        libc::ptrace(
            PTRACE_GET_SYSCALL_INFO,
            pid.as_raw(),
            size_of::<ptrace_syscall_info>(),
            info.as_mut_ptr(),
        )
    };
    Errno::result(err)?;
    Ok(unsafe { info.assume_init() })
}

#[test]
fn seize_clock_nanosleep() {
    let sleep_duration = Duration::from_millis(1000);
    let start = Instant::now();

    let child = match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            clock_nanosleep(
                ClockId::CLOCK_MONOTONIC,
                ClockNanosleepFlags::empty(),
                &TimeSpec::from_duration(sleep_duration),
            )
            .unwrap();
            exit(0);
        }
    };

    std::thread::sleep(sleep_duration / 2);

    assert_eq!(ptrace::seize(child, Options::PTRACE_O_TRACESYSGOOD), Ok(()));

    assert_eq!(kill(child, SIGSTOP), Ok(()));

    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Stopped(child, Signal::SIGSTOP)),
    );

    let info = get_syscall_info(child).unwrap();
    assert_eq!(info.op, PTRACE_SYSCALL_INFO_NONE);

    assert_eq!(ptrace::syscall(child, None), Ok(()));
    assert_eq!(waitpid(None, None), Ok(WaitStatus::PtraceSyscall(child)));

    let info = get_syscall_info(child).unwrap();
    assert_eq!(info.op, PTRACE_SYSCALL_INFO_ENTRY);
    let entry = unsafe { info.u.entry };
    assert_eq!(entry.nr, SYS_restart_syscall as u64);

    assert_eq!(ptrace::syscall(child, None), Ok(()));
    assert_eq!(waitpid(None, None), Ok(WaitStatus::PtraceSyscall(child)));

    assert_eq!(kill(child, Signal::SIGKILL), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Signaled(child, Signal::SIGKILL, false)),
    );

    assert!(start.elapsed() >= sleep_duration);
}

const ERESTART_RESTARTBLOCK: c_long = 516;

#[test]
fn seize_clock_nanosleep_syscall_stop() {
    #![allow(clippy::useless_conversion)]

    let sleep_duration = Duration::from_millis(1000);

    let child = match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            clock_nanosleep(
                ClockId::CLOCK_MONOTONIC,
                ClockNanosleepFlags::empty(),
                &TimeSpec::from_duration(sleep_duration),
            )
            .unwrap();
            exit(0);
        }
    };

    std::thread::sleep(sleep_duration / 2);

    assert_eq!(ptrace::seize(child, Options::PTRACE_O_TRACESYSGOOD), Ok(()));

    assert_eq!(kill(child, SIGSTOP), Ok(()));

    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Stopped(child, Signal::SIGSTOP)),
    );

    let info = get_syscall_info(child).unwrap();
    assert_eq!(info.op, PTRACE_SYSCALL_INFO_NONE);

    assert_eq!(ptrace::syscall(child, None), Ok(()));
    assert_eq!(waitpid(None, None), Ok(WaitStatus::PtraceSyscall(child)));

    let info = get_syscall_info(child).unwrap();
    assert_eq!(info.op, PTRACE_SYSCALL_INFO_ENTRY);
    let entry = unsafe { info.u.entry };
    assert_eq!(entry.nr, SYS_restart_syscall as u64);

    std::thread::sleep(sleep_duration / 4);

    assert_eq!(kill(child, SIGSTOP), Ok(()));

    assert_eq!(ptrace::syscall(child, None), Ok(()));
    assert_eq!(waitpid(None, None), Ok(WaitStatus::PtraceSyscall(child)));

    let info = get_syscall_info(child).unwrap();
    assert_eq!(info.op, PTRACE_SYSCALL_INFO_EXIT);
    let exit = unsafe { info.u.exit };
    assert_eq!(exit.is_error, 1);
    assert_eq!(exit.sval, i64::from(-ERESTART_RESTARTBLOCK));

    assert_eq!(kill(child, Signal::SIGKILL), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Signaled(child, Signal::SIGKILL, false)),
    );
}

/// restart_syscall still works even when interrupted by another syscall.
#[test]
fn seize_clock_nanosleep_get_pid_restart_syscall() {
    let sleep_duration = Duration::from_millis(1000);
    let start = Instant::now();

    let child = match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            clock_nanosleep(
                ClockId::CLOCK_MONOTONIC,
                ClockNanosleepFlags::empty(),
                &TimeSpec::from_duration(sleep_duration),
            )
            .unwrap();
            exit(0);
        }
    };

    std::thread::sleep(sleep_duration / 2);

    assert_eq!(ptrace::seize(child, Options::PTRACE_O_TRACESYSGOOD), Ok(()));

    assert_eq!(kill(child, SIGSTOP), Ok(()));

    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Stopped(child, Signal::SIGSTOP)),
    );

    let info = get_syscall_info(child).unwrap();
    assert_eq!(info.op, PTRACE_SYSCALL_INFO_NONE);

    assert_eq!(ptrace::syscall(child, None), Ok(()));
    assert_eq!(waitpid(None, None), Ok(WaitStatus::PtraceSyscall(child)));

    let info = get_syscall_info(child).unwrap();
    assert_eq!(info.op, PTRACE_SYSCALL_INFO_ENTRY);
    let entry = unsafe { info.u.entry };
    assert_eq!(entry.nr, SYS_restart_syscall as u64);

    let old_regs = ptrace::getregs(child).unwrap();
    let mut regs = old_regs;
    #[cfg(target_pointer_width = "32")]
    {
        regs.orig_eax = SYS_getpid;
    }
    #[cfg(target_pointer_width = "64")]
    {
        regs.orig_rax = SYS_getpid as u64;
    }
    assert_eq!(ptrace::setregs(child, regs), Ok(()));

    assert_eq!(ptrace::syscall(child, None), Ok(()));
    assert_eq!(waitpid(None, None), Ok(WaitStatus::PtraceSyscall(child)));

    assert_eq!(ptrace::syscall(child, None), Ok(()));
    assert_eq!(waitpid(None, None), Ok(WaitStatus::PtraceSyscall(child)));

    assert_eq!(ptrace::setregs(child, old_regs), Ok(()));

    assert_eq!(ptrace::syscall(child, None), Ok(()));
    assert_eq!(waitpid(None, None), Ok(WaitStatus::PtraceSyscall(child)));

    assert_eq!(kill(child, Signal::SIGKILL), Ok(()));
    assert_eq!(
        waitpid(None, None),
        Ok(WaitStatus::Signaled(child, Signal::SIGKILL, false)),
    );

    assert!(start.elapsed() >= sleep_duration);
}

#[test]
fn restart_syscall() {
    assert_eq!(unsafe { syscall(SYS_restart_syscall) }, -1);
    assert_eq!(Errno::last(), Errno::EINTR);
}
