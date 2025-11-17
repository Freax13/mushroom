use std::{
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    pin::pin,
    u64,
};

use nix::{
    fcntl::{OFlag, open},
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::{
        epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags},
        eventfd::{EfdFlags, EventFd},
        socket::{
            AddressFamily, SockFlag, SockProtocol, SockType, setsockopt, shutdown, socketpair,
            sockopt::SndBuf,
        },
        stat::Mode,
    },
    unistd::{mkfifo, pipe, pipe2, read, unlink, write},
};

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
        let mut this = Self { socket1, socket2 };
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
        let mut buf = [0; 0x4000];
        while write(&self.socket1, &mut buf).is_ok_and(|n| n > 0) {}
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

    let mut event = EpollEvent::new(
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

    let mut event = EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLET, 1);
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

    let mut event = EpollEvent::new(EpollFlags::EPOLLOUT | EpollFlags::EPOLLET, 1);
    epoll.add(&efd, event).unwrap();

    let mut events = [EpollEvent::empty()];
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.write(1).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.write(u64::MAX - 2).unwrap();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));

    efd.read();
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(1));
    assert_eq!(events[0], EpollEvent::new(EpollFlags::EPOLLOUT, 1));
    assert_eq!(epoll.wait(&mut events, PollTimeout::ZERO), Ok(0));
}

#[test]
fn pipe_edge_in() {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();

    let (rfd, wfd) = pipe().unwrap();
    write(&wfd, &[0]).unwrap();

    let mut event = EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLET, 1);
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

    let mut event = EpollEvent::new(EpollFlags::EPOLLOUT | EpollFlags::EPOLLET, 1);
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

    let mut event = EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLET, 1);
    epoll1.add(&efd, event).unwrap();

    let mut event = EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLET, 2);
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
