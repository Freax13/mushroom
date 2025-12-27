use std::{
    process::exit,
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    sys::{
        ptrace::{self, Options},
        signal::{Signal, kill},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{ForkResult, fork, getpid, sleep},
};

#[test]
fn seize_self() {
    let pid = getpid();
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
