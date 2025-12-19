use std::os::fd::{AsRawFd, OwnedFd};

use nix::{
    Result,
    errno::Errno,
    fcntl::{OFlag, open},
    libc::{Ioctl, TCFLSH, TCIFLUSH, TCIOFLUSH, TCOFLUSH, TIOCGPTN, TIOCSPTLCK, c_int, ioctl},
    sys::stat::Mode,
    unistd::{read, write},
};

use crate::mount_dev;

// Returns a tuple of (pty master, pty slave)
fn make_pty_pair() -> (OwnedFd, OwnedFd) {
    mount_dev();

    let master = open("/dev/ptmx", OFlag::O_RDWR, Mode::empty()).unwrap();

    let idx = tiocgptn(&master);

    // Unlock the pseudo terminal.
    let res = unsafe { ioctl(master.as_raw_fd(), TIOCSPTLCK, &0u32) };
    Errno::result(res).unwrap();

    // Now we can open the slave.
    let slave = open(&*format!("/dev/pts/{idx}"), OFlag::O_RDWR, Mode::empty()).unwrap();

    (master, slave)
}

/// Query the index for the terminal.
fn tiocgptn(master: &OwnedFd) -> u32 {
    let mut idx = 0u32;
    let res = unsafe { ioctl(master.as_raw_fd(), TIOCGPTN, &mut idx) };
    Errno::result(res).unwrap();
    idx
}

/// Flush the input and/or output buffers.
fn tcflsh(fd: &OwnedFd, mode: c_int) -> Result<()> {
    let res = unsafe { ioctl(fd.as_raw_fd(), TCFLSH as Ioctl, mode) };
    Errno::result(res)?;
    Ok(())
}

#[test]
fn flush_input_master() {
    let (master, slave) = make_pty_pair();

    assert_eq!(write(&slave, b"ABC\n"), Ok(4));

    assert_eq!(tcflsh(&master, TCIFLUSH), Ok(()));

    assert_eq!(write(&slave, b"DEF\n"), Ok(4));

    let mut buf = [0; 16];
    assert_eq!(read(&master, &mut buf), Ok(5));
    assert_eq!(buf[..5], *b"DEF\r\n");
}

#[test]
fn flush_output_master() {
    let (master, slave) = make_pty_pair();

    assert_eq!(write(&master, b"ABC\n"), Ok(4));

    assert_eq!(tcflsh(&master, TCOFLUSH), Ok(()));

    assert_eq!(write(&master, b"DEF\n"), Ok(4));

    let mut buf = [0; 16];
    assert_eq!(read(&slave, &mut buf), Ok(4));
    assert_eq!(buf[..4], *b"DEF\n");
}

#[test]
fn flush_input_output_master_input() {
    let (master, slave) = make_pty_pair();

    assert_eq!(write(&slave, b"ABC\n"), Ok(4));

    assert_eq!(tcflsh(&master, TCIOFLUSH), Ok(()));

    assert_eq!(write(&slave, b"DEF\n"), Ok(4));

    let mut buf = [0; 16];
    assert_eq!(read(&master, &mut buf), Ok(5));
    assert_eq!(buf[..5], *b"DEF\r\n");
}

#[test]
fn flush_input_output_master_output() {
    let (master, slave) = make_pty_pair();

    assert_eq!(write(&master, b"ABC\n"), Ok(4));

    assert_eq!(tcflsh(&master, TCIOFLUSH), Ok(()));

    assert_eq!(write(&master, b"DEF\n"), Ok(4));

    let mut buf = [0; 16];
    assert_eq!(read(&slave, &mut buf), Ok(4));
    assert_eq!(buf[..4], *b"DEF\n");
}

#[test]
fn flush_input_slave() {
    let (master, slave) = make_pty_pair();

    assert_eq!(write(&master, b"ABC\n"), Ok(4));

    assert_eq!(tcflsh(&slave, TCIFLUSH), Ok(()));

    assert_eq!(write(&master, b"DEF\n"), Ok(4));

    let mut buf = [0; 16];
    assert_eq!(read(&slave, &mut buf), Ok(4));
    assert_eq!(buf[..4], *b"DEF\n");
}

#[test]
fn flush_output_slave() {
    let (master, slave) = make_pty_pair();

    assert_eq!(write(&slave, b"ABC\n"), Ok(4));

    assert_eq!(tcflsh(&slave, TCOFLUSH), Ok(()));

    assert_eq!(write(&slave, b"DEF\n"), Ok(4));

    let mut buf = [0; 16];
    assert_eq!(read(&master, &mut buf), Ok(5));
    assert_eq!(buf[..5], *b"DEF\r\n");
}

#[test]
fn flush_input_output_slave_input() {
    let (master, slave) = make_pty_pair();

    assert_eq!(write(&master, b"ABC\n"), Ok(4));

    assert_eq!(tcflsh(&slave, TCIOFLUSH), Ok(()));

    assert_eq!(write(&master, b"DEF\n"), Ok(4));

    let mut buf = [0; 16];
    assert_eq!(read(&slave, &mut buf), Ok(4));
    assert_eq!(buf[..4], *b"DEF\n");
}

#[test]
fn flush_input_output_slave_output() {
    let (master, slave) = make_pty_pair();

    assert_eq!(write(&slave, b"ABC\n"), Ok(4));

    assert_eq!(tcflsh(&slave, TCIOFLUSH), Ok(()));

    assert_eq!(write(&slave, b"DEF\n"), Ok(4));

    let mut buf = [0; 16];
    assert_eq!(read(&master, &mut buf), Ok(5));
    assert_eq!(buf[..5], *b"DEF\r\n");
}
