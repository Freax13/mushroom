use std::os::fd::{AsRawFd, OwnedFd};

use nix::{
    Result,
    errno::Errno,
    fcntl::{OFlag, open},
    libc::{
        Ioctl, TCFLSH, TCIFLUSH, TCIOFLUSH, TCOFLUSH, TIOCEXCL, TIOCGEXCL, TIOCGPTN, TIOCNXCL,
        TIOCSPTLCK, c_int, ioctl,
    },
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

/// Enable exclusive mode.
fn tiocexcl(fd: &OwnedFd) -> Result<()> {
    let res = unsafe { ioctl(fd.as_raw_fd(), TIOCEXCL as Ioctl) };
    Errno::result(res)?;
    Ok(())
}

/// Query whether exclusive mode is enabled.
fn tiocgexcl(fd: &OwnedFd) -> Result<bool> {
    let mut enabled = 0i32;
    let res = unsafe { ioctl(fd.as_raw_fd(), TIOCGEXCL as Ioctl, &mut enabled) };
    Errno::result(res)?;
    Ok(enabled != 0)
}

/// Disable exclusive mode.
fn tiocnxcl(fd: &OwnedFd) -> Result<()> {
    let res = unsafe { ioctl(fd.as_raw_fd(), TIOCNXCL as Ioctl) };
    Errno::result(res)?;
    Ok(())
}

#[test]
fn enable_exclusive_mode_master() {
    let (master, slave) = make_pty_pair();

    // Both sides start out as unlocked.
    assert_eq!(tiocgexcl(&master), Ok(false));
    assert_eq!(tiocgexcl(&slave), Ok(false));

    // Enable exclusive mode for the master.
    assert_eq!(tiocexcl(&master), Ok(()));

    // The master is locked.
    assert_eq!(tiocgexcl(&master), Ok(true));
    // But this doesn't do much because the master can't be opened again
    // anyway.

    // The slave is not locked.
    assert_eq!(tiocgexcl(&slave), Ok(false));
    // So it can be opened.
    let idx = tiocgptn(&master);
    assert!(open(&*format!("/dev/pts/{idx}"), OFlag::O_RDWR, Mode::empty()).is_ok());

    // Disable exclusive mode for the master.
    assert_eq!(tiocnxcl(&master), Ok(()));

    // Now, both sides are unlocked again.
    assert_eq!(tiocgexcl(&master), Ok(false));
    assert_eq!(tiocgexcl(&slave), Ok(false));
}

#[test]
fn enable_exclusive_mode_slave() {
    let (master, slave) = make_pty_pair();

    // Both sides start out as unlocked.
    assert_eq!(tiocgexcl(&master), Ok(false));
    assert_eq!(tiocgexcl(&slave), Ok(false));

    // Enable exlusive mode for the slave.
    assert_eq!(tiocexcl(&slave), Ok(()));

    // The master is not locked.
    assert_eq!(tiocgexcl(&master), Ok(false));

    // The slave is locked.
    assert_eq!(tiocgexcl(&slave), Ok(true));
    // So it can't be opened.
    let idx = tiocgptn(&master);
    assert_eq!(
        open(&*format!("/dev/pts/{idx}"), OFlag::O_RDWR, Mode::empty()).unwrap_err(),
        Errno::EBUSY
    );

    // Disable exclusive mode for the slave.
    assert_eq!(tiocnxcl(&slave), Ok(()));

    // Now, both sides are unlocked again.
    assert_eq!(tiocgexcl(&master), Ok(false));
    assert_eq!(tiocgexcl(&slave), Ok(false));

    // And now the slave can be opened again.
    assert!(open(&*format!("/dev/pts/{idx}"), OFlag::O_RDWR, Mode::empty()).is_ok());
}
