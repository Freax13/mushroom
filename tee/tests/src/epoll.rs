use std::{
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    time::Duration,
};

use nix::{
    errno::Errno,
    fcntl::{OFlag, open},
    libc::{TIOCGPTN, TIOCSPTLCK, ioctl},
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::{
        epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags},
        eventfd::{EfdFlags, EventFd},
        socket::{
            AddressFamily, MsgFlags, SockFlag, SockProtocol, SockType, recv, send, socketpair,
        },
        stat::Mode,
        time::TimeSpec,
        timer::{Expiration, TimerSetTimeFlags},
        timerfd::{TimerFd, TimerFlags},
    },
    unistd::{mkfifo, pipe, pipe2, read, unlink, write},
};

use crate::mount_dev;

struct TestFd {
    socket1: OwnedFd,
    socket2: OwnedFd,
}

impl TestFd {
    fn new() -> Self {
        let (socket1, socket2) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            Option::<SockProtocol>::None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )
        .unwrap();
        // setsockopt(&socket1, SndBuf, &0).unwrap();
        let this = Self { socket1, socket2 };
        this.clear_readable();
        this.clear_writeable();
        this
    }

    fn clear_readable(&self) {
        let mut buf = [0; 0x4000];
        while read(&self.socket1, &mut buf).is_ok_and(|n| n > 0) {}
    }

    fn set_readable(&self) {
        let _ = write(&self.socket2, &[0]);
    }

    fn clear_writeable(&self) {
        let buf = [0; 0x4000];
        while write(&self.socket1, &buf).is_ok_and(|n| n > 0) {}
    }

    fn set_writable(&self) {
        let mut buf = [0; 0x4000];
        let mut poll_fd = PollFd::new(self.socket1.as_fd(), PollFlags::POLLOUT);
        while poll(std::slice::from_mut(&mut poll_fd), PollTimeout::ZERO).unwrap() == 0 {
            let _ = read(&self.socket2, &mut buf).unwrap();
        }
    }
}

impl AsFd for TestFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket1.as_fd()
    }
}

#[test]
fn epoll() {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();

    let fd1 = TestFd::new();
    let fd2 = TestFd::new();

    epoll
        .add(
            &fd1,
            EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1),
        )
        .unwrap();
    epoll
        .add(
            &fd2,
            EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 2),
        )
        .unwrap();

    let mut events = [EpollEvent::empty(), EpollEvent::empty()];
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    fd1.set_readable();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));

    fd2.set_readable();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(2));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));
    assert_eq!(events[1], EpollEvent::new(EpollFlags::EPOLLIN, 2));

    fd1.clear_readable();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 2));

    fd2.clear_readable();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    fd2.set_readable();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 2));

    fd1.set_readable();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(2));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 2));
    assert_eq!(events[1], EpollEvent::new(EpollFlags::EPOLLIN, 1));

    fd2.set_readable();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(2));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 2));
    assert_eq!(events[1], EpollEvent::new(EpollFlags::EPOLLIN, 1));

    fd2.set_writable();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(2));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 2)
    );
    assert_eq!(events[1], EpollEvent::new(EpollFlags::EPOLLIN, 1));

    fd2.clear_readable();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(2));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 2));
    assert_eq!(events[1], EpollEvent::new(EpollFlags::EPOLLIN, 1));

    fd1.set_writable();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(2));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 2));
    assert_eq!(
        events[1],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
}

#[test]
fn level_triggered() {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();

    let fd1 = TestFd::new();

    let mut event = EpollEvent::new(
        EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT | EpollFlags::EPOLLET,
        1,
    );
    epoll.add(&fd1, event).unwrap();

    let mut events = [EpollEvent::empty(), EpollEvent::empty()];
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    fd1.set_readable();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    // Modifying the entry resets level triggered events.

    epoll.modify(&fd1, &mut event).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));
}

#[test]
fn maxevents() {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();

    let fd1 = TestFd::new();
    let fd2 = TestFd::new();

    epoll
        .add(
            &fd1,
            EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1),
        )
        .unwrap();
    epoll
        .add(
            &fd2,
            EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 2),
        )
        .unwrap();

    let mut events = [EpollEvent::empty()];
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    fd1.set_readable();
    fd2.set_readable();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 2));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));
}

#[test]
fn fifo() {
    let _ = unlink("test.epoll.fifo");
    mkfifo("test.epoll.fifo", Mode::S_IRWXU).unwrap();

    let fd1 = open("test.epoll.fifo", OFlag::O_RDWR, Mode::empty()).unwrap();
    let fd2 = open("test.epoll.fifo", OFlag::O_RDWR, Mode::empty()).unwrap();

    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();

    epoll
        .add(
            &fd1,
            EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1),
        )
        .unwrap();
    epoll
        .add(
            &fd2,
            EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 2),
        )
        .unwrap();

    let mut events = [EpollEvent::empty(), EpollEvent::empty()];
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(2));
}

#[test]
fn eventfd_edge_in_out() {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();

    let efd = EventFd::from_flags(EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK).unwrap();

    let event = EpollEvent::new(
        EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT | EpollFlags::EPOLLET,
        1,
    );
    epoll.add(&efd, event).unwrap();

    let mut events = [EpollEvent::empty()];
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.write(1).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.write(1).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.write(0).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));
}

#[test]
fn eventfd_edge_in() {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();

    let efd = EventFd::from_flags(EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK).unwrap();

    let event = EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLET, 1);
    epoll.add(&efd, event).unwrap();

    let mut events = [EpollEvent::empty()];
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.write(0).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.write(1).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.write(1).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.write(0).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));
}

#[test]
fn eventfd_edge_out() {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();

    let efd = EventFd::from_flags(EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK).unwrap();

    let event = EpollEvent::new(EpollFlags::EPOLLOUT | EpollFlags::EPOLLET, 1);
    epoll.add(&efd, event).unwrap();

    let mut events = [EpollEvent::empty()];
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.write(1).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.write(u64::MAX - 2).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.read().unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));
}

#[test]
fn pipe_edge_in() {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();

    let (rfd, wfd) = pipe().unwrap();
    write(&wfd, &[0]).unwrap();

    let event = EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLET, 1);
    epoll.add(&rfd, event).unwrap();

    let mut events = [EpollEvent::empty()];
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    write(&wfd, &[0]).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    write(&wfd, &[0]).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    drop(wfd);
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLHUP, 1)
    );
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));
}

#[test]
fn pipe_edge_out() {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();

    let (rfd, wfd) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).unwrap();

    let event = EpollEvent::new(EpollFlags::EPOLLOUT | EpollFlags::EPOLLET, 1);
    epoll.add(&wfd, event).unwrap();

    let mut events = [EpollEvent::empty()];
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    write(&wfd, &[0]).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    read(&rfd, &mut [0]).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buf = [0; 0x4000];
    while write(&wfd, &buf).is_ok() {}
    while read(&rfd, &mut buf).is_ok() {}
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    drop(rfd);
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLOUT | EpollFlags::EPOLLERR, 1)
    );
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));
}

#[test]
fn recursive_edge() {
    let epoll1 = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();
    let epoll2 = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();
    let efd = EventFd::from_flags(EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK).unwrap();

    let event = EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLET, 1);
    epoll1.add(&efd, event).unwrap();

    let event = EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLET, 2);
    epoll2.add(&epoll1.0, event).unwrap();

    let mut events = [EpollEvent::empty()];
    assert_eq!(epoll1.wait(&mut events, PollTimeout::ZERO), Ok(0));
    assert_eq!(epoll2.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.write(1).unwrap();
    assert_eq!(epoll1.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));
    assert_eq!(epoll2.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.write(1).unwrap();
    assert_eq!(epoll2.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 2));
    assert_eq!(epoll2.wait(&mut events, PollTimeout::ZERO), Ok(0));
    assert_eq!(epoll1.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));

    efd.write(1).unwrap();
    assert_eq!(epoll2.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 2));
    assert_eq!(epoll2.wait(&mut events, PollTimeout::ZERO), Ok(0));
    assert_eq!(epoll1.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));

    efd.write(1).unwrap();
    assert_eq!(epoll2.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 2));
    assert_eq!(epoll2.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.write(1).unwrap();
    assert_eq!(epoll2.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 2));
    assert_eq!(epoll2.wait(&mut events, PollTimeout::ZERO), Ok(0));
}

#[test]
fn pty_edge() {
    mount_dev();

    let master = open("/dev/ptmx", OFlag::O_RDWR, Mode::empty()).unwrap();

    let mut idx = 0u32;
    let res = unsafe { ioctl(master.as_raw_fd(), TIOCGPTN, &mut idx) };
    Errno::result(res).unwrap();

    // The slave cannot be opened yet (it's still locked).
    assert_eq!(
        open(&*format!("/dev/pts/{idx}"), OFlag::O_RDWR, Mode::empty()).unwrap_err(),
        Errno::EIO
    );

    // Unlock the pseudo terminal.
    let res = unsafe { ioctl(master.as_raw_fd(), TIOCSPTLCK, &0u32) };
    Errno::result(res).unwrap();

    // Now we can open the slave.
    let slave = open(&*format!("/dev/pts/{idx}"), OFlag::O_RDWR, Mode::empty()).unwrap();

    let epoll_master = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();
    epoll_master
        .add(
            &master,
            EpollEvent::new(
                EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT | EpollFlags::EPOLLET,
                1,
            ),
        )
        .unwrap();
    let epoll_slave = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();
    epoll_slave
        .add(
            &slave,
            EpollEvent::new(
                EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT | EpollFlags::EPOLLET,
                2,
            ),
        )
        .unwrap();

    let mut events = [EpollEvent::empty()];

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 1));
    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 2));
    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(write(&master, b"ABC"), Ok(3));

    // Wait for the terminal to settle.
    std::thread::sleep(Duration::from_millis(1));

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(write(&master, b"DEF"), Ok(3));
    std::thread::sleep(Duration::from_millis(1));

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(write(&master, b"GHI\n"), Ok(4));
    std::thread::sleep(Duration::from_millis(1));

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 2)
    );
    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(write(&master, b"123"), Ok(3));
    std::thread::sleep(Duration::from_millis(1));

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buffer = [0; 3];
    assert_eq!(read(&slave, &mut buffer), Ok(3));
    assert_eq!(buffer, *b"ABC");

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buffer = [0; 16];
    assert_eq!(read(&slave, &mut buffer), Ok(7));
    assert_eq!(buffer[..7], *b"DEFGHI\n");

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buffer = [0; 3];
    assert_eq!(read(&master, &mut buffer), Ok(3));
    assert_eq!(buffer, *b"ABC");

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 2));
    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buffer = [0; 16];
    assert_eq!(read(&master, &mut buffer), Ok(11));
    assert_eq!(buffer[..11], *b"DEFGHI\r\n123");

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 2));
    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(write(&slave, b"abc"), Ok(3));
    std::thread::sleep(Duration::from_millis(1));

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 2));
    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(write(&slave, b"def"), Ok(3));
    std::thread::sleep(Duration::from_millis(1));

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 2));
    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(write(&slave, b"ghi\n"), Ok(4));
    std::thread::sleep(Duration::from_millis(1));

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(write(&slave, b"123"), Ok(3));
    std::thread::sleep(Duration::from_millis(1));

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 2));
    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buffer = [0; 3];
    assert_eq!(read(&master, &mut buffer), Ok(3));
    assert_eq!(buffer, *b"abc");

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 2));
    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buffer = [0; 16];
    assert_eq!(read(&master, &mut buffer), Ok(11));
    assert_eq!(buffer[..11], *b"defghi\r\n123");

    assert_eq!(epoll_master.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 2));
    assert_eq!(epoll_slave.wait(&mut events, PollTimeout::ZERO), Ok(0));
}

#[test]
fn timerfd_edge_triggered() {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();

    let timer = TimerFd::new(
        nix::sys::timerfd::ClockId::CLOCK_MONOTONIC,
        TimerFlags::TFD_NONBLOCK | TimerFlags::TFD_CLOEXEC,
    )
    .unwrap();
    let interval = Duration::from_millis(500);
    timer
        .set(
            Expiration::Interval(TimeSpec::from_duration(interval)),
            TimerSetTimeFlags::empty(),
        )
        .unwrap();

    epoll
        .add(
            &timer,
            EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLET, 1),
        )
        .unwrap();

    std::thread::sleep(interval / 2);

    let mut events = [EpollEvent::empty()];
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buf = [0; 8];
    assert_eq!(read(&timer, &mut buf), Err(Errno::EAGAIN));

    std::thread::sleep(interval);

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buf = [0; 8];
    assert_eq!(read(&timer, &mut buf), Ok(8));
    assert_eq!(u64::from_ne_bytes(buf), 1);

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    std::thread::sleep(interval * 3);

    let mut buf = [0; 8];
    assert_eq!(read(&timer, &mut buf), Ok(8));
    assert_eq!(u64::from_ne_bytes(buf), 3);

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    std::thread::sleep(interval);

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLIN, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    std::thread::sleep(interval);

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    assert_eq!(read(&timer, &mut buf), Ok(8));
    assert_eq!(u64::from_ne_bytes(buf), 2);
}

#[test]
fn unix_dgram_edge_triggered() {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();

    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
    )
    .unwrap();

    epoll
        .add(
            &sock1,
            EpollEvent::new(
                EpollFlags::EPOLLIN
                    | EpollFlags::EPOLLOUT
                    | EpollFlags::EPOLLERR
                    | EpollFlags::EPOLLHUP
                    | EpollFlags::EPOLLET,
                1,
            ),
        )
        .unwrap();

    let mut events = [EpollEvent::empty()];
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    send(sock1.as_raw_fd(), b"foo", MsgFlags::empty()).unwrap();

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    send(sock2.as_raw_fd(), b"bar", MsgFlags::empty()).unwrap();

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    send(sock2.as_raw_fd(), b"baz", MsgFlags::empty()).unwrap();

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buf = [0; 16];
    assert_eq!(recv(sock2.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(3));
    assert_eq!(buf[..3], *b"foo");

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buf = [0; 16];
    assert_eq!(recv(sock1.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(3));
    assert_eq!(buf[..3], *b"bar");

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buf = [0; 16];
    assert_eq!(recv(sock1.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(3));
    assert_eq!(buf[..3], *b"baz");

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    drop(sock2);

    let mut buf = [0; 16];
    assert_eq!(
        recv(sock1.as_raw_fd(), &mut buf, MsgFlags::empty()),
        Err(Errno::EAGAIN)
    );

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));
}

#[test]
fn unix_seqpacket_edge_triggered() {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();

    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None::<SockProtocol>,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
    )
    .unwrap();

    epoll
        .add(
            &sock1,
            EpollEvent::new(
                EpollFlags::EPOLLIN
                    | EpollFlags::EPOLLOUT
                    | EpollFlags::EPOLLERR
                    | EpollFlags::EPOLLHUP
                    | EpollFlags::EPOLLET,
                1,
            ),
        )
        .unwrap();

    let mut events = [EpollEvent::empty()];
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    send(sock1.as_raw_fd(), b"foo", MsgFlags::empty()).unwrap();

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    send(sock2.as_raw_fd(), b"bar", MsgFlags::empty()).unwrap();

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    send(sock2.as_raw_fd(), b"baz", MsgFlags::empty()).unwrap();

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buf = [0; 16];
    assert_eq!(recv(sock2.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(3));
    assert_eq!(buf[..3], *b"foo");

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT, 1)
    );
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buf = [0; 16];
    assert_eq!(recv(sock1.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(3));
    assert_eq!(buf[..3], *b"bar");

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    let mut buf = [0; 16];
    assert_eq!(recv(sock1.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(3));
    assert_eq!(buf[..3], *b"baz");

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    drop(sock2);

    let mut buf = [0; 16];
    assert_eq!(recv(sock1.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(0));

    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(
        events[0],
        EpollEvent::new(
            EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT | EpollFlags::EPOLLHUP,
            1
        )
    );
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));
}
