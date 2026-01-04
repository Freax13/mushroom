use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use nix::{
    errno::Errno,
    fcntl::{OFlag, open},
    libc::{self, F_RDLCK, F_UNLCK, F_WRLCK, SEEK_SET, c_short, pid_t, syscall},
    sys::{eventfd::EventFd, stat::Mode, wait::waitpid},
    unistd::{ForkResult, Pid, fork},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg(target_pointer_width = "32")]
struct flock {
    l_type: c_short,
    l_whence: c_short,
    l_start: i32,
    l_len: i32,
    l_pid: pid_t,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg(target_pointer_width = "64")]
struct flock {
    l_type: c_short,
    l_whence: c_short,
    l_start: i64,
    l_len: i64,
    l_pid: pid_t,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct flock64 {
    l_type: c_short,
    l_whence: c_short,
    l_start: i64,
    l_len: i64,
    l_pid: pid_t,
}

const RDLCK: flock = flock {
    l_type: F_RDLCK as i16,
    l_whence: SEEK_SET as i16,
    l_start: 100,
    l_len: 200,
    l_pid: 0,
};

const WRLCK: flock = flock {
    l_type: F_WRLCK as i16,
    l_whence: SEEK_SET as i16,
    l_start: 100,
    l_len: 200,
    l_pid: 0,
};

const RDLCK64: flock64 = flock64 {
    l_type: F_RDLCK as i16,
    l_whence: SEEK_SET as i16,
    l_start: 100,
    l_len: 200,
    l_pid: 0,
};

const WRLCK64: flock64 = flock64 {
    l_type: F_WRLCK as i16,
    l_whence: SEEK_SET as i16,
    l_start: 100,
    l_len: 200,
    l_pid: 0,
};

#[derive(Debug, Clone, Copy)]
enum LockOp {
    GetLk,
    SetLk,
    SetLkW,
}

fn fcntl_lk(fd: &OwnedFd, op: LockOp, flock: &mut flock) -> nix::Result<()> {
    let op = match op {
        LockOp::GetLk => 5,
        LockOp::SetLk => 6,
        LockOp::SetLkW => 7,
    };
    let res = unsafe { syscall(libc::SYS_fcntl, fd.as_fd().as_raw_fd(), op, flock) };
    Errno::result(res).map(drop)
}

fn fcntl_lk64(fd: &OwnedFd, op: LockOp, flock: &mut flock64) -> nix::Result<()> {
    let op = match op {
        LockOp::GetLk => 12,
        LockOp::SetLk => 13,
        LockOp::SetLkW => 14,
    };
    let res = unsafe { syscall(libc::SYS_fcntl, fd.as_fd().as_raw_fd(), op, flock) };
    Errno::result(res).map(drop)
}

fn fcntl64_lk(fd: &OwnedFd, op: LockOp, flock: &mut flock) -> nix::Result<()> {
    #[cfg(not(target_pointer_width = "32"))]
    {
        let _ = fd;
        let _ = op;
        let _ = flock;
        unimplemented!()
    }
    #[cfg(target_pointer_width = "32")]
    {
        let op = match op {
            LockOp::GetLk => 5,
            LockOp::SetLk => 6,
            LockOp::SetLkW => 7,
        };
        let res = unsafe { syscall(libc::SYS_fcntl64, fd.as_fd().as_raw_fd(), op, flock) };
        Errno::result(res).map(drop)
    }
}

fn fcntl64_lk64(fd: &OwnedFd, op: LockOp, flock: &mut flock64) -> nix::Result<()> {
    #[cfg(not(target_pointer_width = "32"))]
    {
        let _ = fd;
        let _ = op;
        let _ = flock;
        unimplemented!()
    }
    #[cfg(target_pointer_width = "32")]
    {
        let op = match op {
            LockOp::GetLk => 12,
            LockOp::SetLk => 13,
            LockOp::SetLkW => 14,
        };
        let res = unsafe { syscall(libc::SYS_fcntl64, fd.as_fd().as_raw_fd(), op, flock) };
        Errno::result(res).map(drop)
    }
}

fn setlk_getlk<T, U>(
    setlk_fn: fn(fd: &OwnedFd, op: LockOp, flock: &mut T) -> nix::Result<()>,
    setlk: T,
    getlk_fn: fn(fd: &OwnedFd, op: LockOp, flock: &mut U) -> nix::Result<()>,
    getlk: U,
) -> (Pid, U) {
    let fd = open(
        ".",
        OFlag::O_RDWR | OFlag::O_TMPFILE,
        Mode::from_bits(0o644).unwrap(),
    )
    .unwrap();

    let wake_parent = EventFd::new().unwrap();
    let wake_child = EventFd::new().unwrap();

    match unsafe { fork() }.unwrap() {
        ForkResult::Parent { child } => {
            assert_eq!(wake_parent.read(), Ok(1));

            let mut flock = getlk;
            assert_eq!(getlk_fn(&fd, LockOp::GetLk, &mut flock), Ok(()));

            wake_child.write(1).unwrap();
            waitpid(child, None).unwrap();

            (child, flock)
        }
        ForkResult::Child => {
            let mut flock = setlk;
            assert_eq!(setlk_fn(&fd, LockOp::SetLk, &mut flock), Ok(()));

            wake_parent.write(1).unwrap();

            assert_eq!(wake_child.read(), Ok(1));

            std::process::exit(0);
        }
    }
}

#[test]
fn fcntl_setlk_rd_fcntl_getlk_rd() {
    let (_child, flock) = setlk_getlk(fcntl_lk, RDLCK, fcntl_lk, RDLCK);
    assert_eq!(
        flock,
        flock {
            l_type: F_UNLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: 0,
        }
    );
}

#[test]
fn fcntl_setlk_rd_fcntl_getlk_wr() {
    let (child, flock) = setlk_getlk(fcntl_lk, RDLCK, fcntl_lk, WRLCK);
    assert_eq!(
        flock,
        flock {
            l_type: F_RDLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: child.as_raw(),
        }
    );
}

#[test]
fn fcntl_setlk_wr_fcntl_getlk_rd() {
    let (child, flock) = setlk_getlk(fcntl_lk, WRLCK, fcntl_lk, RDLCK);
    assert_eq!(
        flock,
        flock {
            l_type: F_WRLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: child.as_raw(),
        }
    );
}

#[test]
fn fcntl_setlk_wr_fcntl_getlk_wr() {
    let (child, flock) = setlk_getlk(fcntl_lk, WRLCK, fcntl_lk, WRLCK);
    assert_eq!(
        flock,
        flock {
            l_type: F_WRLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: child.as_raw(),
        }
    );
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn fcntl_setlk64_rd_fcntl_getlk64_rd() {
    let (_child, flock) = setlk_getlk(fcntl_lk64, RDLCK64, fcntl_lk64, RDLCK64);
    assert_eq!(
        flock,
        flock64 {
            l_type: F_UNLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: 0,
        }
    );
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn fcntl_setlk64_rd_fcntl_getlk64_wr() {
    let (child, flock) = setlk_getlk(fcntl_lk64, RDLCK64, fcntl_lk64, WRLCK64);
    assert_eq!(
        flock,
        flock64 {
            l_type: F_RDLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: child.as_raw(),
        }
    );
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn fcntl_setlk64_wr_fcntl_getlk64_rd() {
    let (child, flock) = setlk_getlk(fcntl_lk64, WRLCK64, fcntl_lk64, RDLCK64);
    assert_eq!(
        flock,
        flock64 {
            l_type: F_WRLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: child.as_raw(),
        }
    );
}

#[test]
#[cfg_attr(not(target_pointer_width = "64"), ignore = "64-bit only")]
fn fcntl_lk64_on_64_bit() {
    let fd = open(
        ".",
        OFlag::O_RDWR | OFlag::O_TMPFILE,
        Mode::from_bits(0o644).unwrap(),
    )
    .unwrap();

    let mut flock = RDLCK64;
    assert_eq!(
        fcntl_lk64(&fd, LockOp::GetLk, &mut flock),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        fcntl_lk64(&fd, LockOp::SetLk, &mut flock),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        fcntl_lk64(&fd, LockOp::SetLkW, &mut flock),
        Err(Errno::EINVAL)
    );
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn fcntl_setlk64_wr_fcntl_getlk64_wr() {
    let (child, flock) = setlk_getlk(fcntl_lk64, WRLCK64, fcntl_lk64, WRLCK64);
    assert_eq!(
        flock,
        flock64 {
            l_type: F_WRLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: child.as_raw(),
        }
    );
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn fcntl64_setlk_rd_fcntl64_getlk_rd() {
    let (_child, flock) = setlk_getlk(fcntl64_lk, RDLCK, fcntl64_lk, RDLCK);
    assert_eq!(
        flock,
        flock {
            l_type: F_UNLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: 0,
        }
    );
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn fcntl64_setlk_rd_fcntl64_getlk_wr() {
    let (child, flock) = setlk_getlk(fcntl64_lk, RDLCK, fcntl64_lk, WRLCK);
    assert_eq!(
        flock,
        flock {
            l_type: F_RDLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: child.as_raw(),
        }
    );
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn fcntl64_setlk_wr_fcntl64_getlk_rd() {
    let (child, flock) = setlk_getlk(fcntl64_lk, WRLCK, fcntl64_lk, RDLCK);
    assert_eq!(
        flock,
        flock {
            l_type: F_WRLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: child.as_raw(),
        }
    );
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn fcntl64_setlk_wr_fcntl64_getlk_wr() {
    let (child, flock) = setlk_getlk(fcntl64_lk, WRLCK, fcntl64_lk, WRLCK);
    assert_eq!(
        flock,
        flock {
            l_type: F_WRLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: child.as_raw(),
        }
    );
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn fcntl64_setlk64_rd_fcntl64_getlk64_rd() {
    let (_child, flock) = setlk_getlk(fcntl64_lk64, RDLCK64, fcntl64_lk64, RDLCK64);
    assert_eq!(
        flock,
        flock64 {
            l_type: F_UNLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: 0,
        }
    );
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn fcntl64_setlk64_rd_fcntl64_getlk64_wr() {
    let (child, flock) = setlk_getlk(fcntl64_lk64, RDLCK64, fcntl64_lk64, WRLCK64);
    assert_eq!(
        flock,
        flock64 {
            l_type: F_RDLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: child.as_raw(),
        }
    );
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn fcntl64_setlk64_wr_fcntl64_getlk64_rd() {
    let (child, flock) = setlk_getlk(fcntl64_lk64, WRLCK64, fcntl64_lk64, RDLCK64);
    assert_eq!(
        flock,
        flock64 {
            l_type: F_WRLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: child.as_raw(),
        }
    );
}

#[test]
#[cfg_attr(not(target_pointer_width = "32"), ignore = "32-bit only")]
fn fcntl64_setlk64_wr_fcntl64_getlk64_wr() {
    let (child, flock) = setlk_getlk(fcntl64_lk64, WRLCK64, fcntl64_lk64, WRLCK64);
    assert_eq!(
        flock,
        flock64 {
            l_type: F_WRLCK as i16,
            l_whence: SEEK_SET as i16,
            l_start: 100,
            l_len: 200,
            l_pid: child.as_raw(),
        }
    );
}
