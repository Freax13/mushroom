use std::{
    fs::File,
    io::{IoSlice, IoSliceMut},
    os::fd::{AsRawFd, RawFd},
    sync::LazyLock,
    time::Duration,
};

use nix::{
    cmsg_space,
    errno::Errno,
    fcntl::OFlag,
    libc::{AF_UNSPEC, sockaddr},
    sys::{
        eventfd::EventFd,
        socket::{
            AddressFamily, Backlog, ControlMessage, ControlMessageOwned, MsgFlags, Shutdown,
            SockFlag, SockProtocol, SockType, SockaddrIn, SockaddrLike, SockaddrStorage, UnixAddr,
            bind, connect, getpeername, getsockname, listen, recv, recvfrom, recvmsg, send,
            sendmsg, sendto, shutdown, socket, socketpair,
        },
        stat::fstat,
    },
    unistd::{pipe2, read, unlink, write},
};

#[test]
fn path_server_stat() {
    let socket = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .unwrap();
    let unbound_stat = fstat(&socket).unwrap();

    let path = "socket-stat";
    bind(socket.as_raw_fd(), &UnixAddr::new(path).unwrap()).unwrap();

    let bound_stat = fstat(&socket).unwrap();

    assert_eq!(unbound_stat, bound_stat);

    unlink(path).unwrap();
}

#[test]
fn path_double_bind() {
    let sock = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .unwrap();

    // Sockets start out as unnamed sockets.
    let addr = getsockname::<UnixAddr>(sock.as_raw_fd()).unwrap();
    assert!(addr.is_unnamed());

    // Bind the socket to a path.
    let path = "socket-double-bind";
    bind(sock.as_raw_fd(), &UnixAddr::new(path).unwrap()).unwrap();

    // The socketname should now reflect the path.
    let addr = getsockname::<UnixAddr>(sock.as_raw_fd()).unwrap();
    assert!(addr.path().is_some_and(|p| p.as_os_str() == path));

    // Binding the same address should fail.
    assert_eq!(
        bind(sock.as_raw_fd(), &UnixAddr::new(path).unwrap()),
        Err(Errno::EADDRINUSE)
    );

    // Binding again to another address should fail.
    let path2 = "socket-double-bind2";
    assert_eq!(
        bind(sock.as_raw_fd(), &UnixAddr::new(path2).unwrap()),
        Err(Errno::EINVAL)
    );

    // Create another socket.
    let sock2 = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .unwrap();

    // Binding the same address should fail.
    assert_eq!(
        bind(sock2.as_raw_fd(), &UnixAddr::new(path).unwrap()),
        Err(Errno::EADDRINUSE)
    );

    // Close the socket.
    drop(sock);

    // Binding should still fail.
    assert_eq!(
        bind(sock2.as_raw_fd(), &UnixAddr::new(path).unwrap()),
        Err(Errno::EADDRINUSE)
    );

    unlink(path).unwrap();
}

#[test]
fn sendmsg_rights() {
    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )
    .unwrap();

    let efd1 = EventFd::new().unwrap();

    assert_eq!(
        sendmsg::<()>(
            sock1.as_raw_fd(),
            &[IoSlice::new(b"1234")],
            &[ControlMessage::ScmRights(&[efd1.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap(),
        4
    );

    let mut cmsg_buffer = cmsg_space!([RawFd; 2]);
    let mut buffer = [0; 4];
    let mut slice_mut = IoSliceMut::new(&mut buffer);
    let msg = recvmsg::<()>(
        sock2.as_raw_fd(),
        core::slice::from_mut(&mut slice_mut),
        Some(&mut cmsg_buffer),
        MsgFlags::empty(),
    )
    .unwrap();
    assert_eq!(msg.bytes, 4);

    let mut cmsgs_iter = msg.cmsgs().unwrap();
    let cmsg = cmsgs_iter.next().unwrap();
    let ControlMessageOwned::ScmRights(creds) = cmsg else {
        unreachable!()
    };
    assert!(creds.len() == 1);
    let efd2 = unsafe { std::mem::transmute::<i32, EventFd>(creds[0]) };

    efd1.write(5).unwrap();
    assert_eq!(efd2.read().unwrap(), 5);

    assert_eq!(buffer, *b"1234");
}

#[test]
fn sendmsg_boundary() {
    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )
    .unwrap();

    let efd1 = EventFd::new().unwrap();

    assert_eq!(
        sendmsg::<()>(
            sock1.as_raw_fd(),
            &[IoSlice::new(b"1234")],
            &[ControlMessage::ScmRights(&[efd1.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap(),
        4
    );

    assert_eq!(
        send(sock1.as_raw_fd(), b"5678", MsgFlags::empty()).unwrap(),
        4
    );

    assert_eq!(
        sendmsg::<()>(
            sock1.as_raw_fd(),
            &[IoSlice::new(b"1234")],
            &[ControlMessage::ScmRights(&[efd1.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap(),
        4
    );

    assert_eq!(
        send(sock1.as_raw_fd(), b"5678", MsgFlags::empty()).unwrap(),
        4
    );

    assert_eq!(
        sendmsg::<()>(
            sock1.as_raw_fd(),
            &[IoSlice::new(b"1234")],
            &[ControlMessage::ScmRights(&[efd1.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap(),
        4
    );

    assert_eq!(
        send(sock1.as_raw_fd(), b"5678", MsgFlags::empty()).unwrap(),
        4
    );

    let mut cmsg_buffer = cmsg_space!([RawFd; 1]);
    let mut buffer = [0; 8];
    let mut slice_mut = IoSliceMut::new(&mut buffer);
    let msg = recvmsg::<()>(
        sock2.as_raw_fd(),
        core::slice::from_mut(&mut slice_mut),
        Some(&mut cmsg_buffer),
        MsgFlags::empty(),
    )
    .unwrap();
    assert_eq!(msg.bytes, 4);

    let mut cmsgs_iter = msg.cmsgs().unwrap();
    let cmsg = cmsgs_iter.next().unwrap();
    let ControlMessageOwned::ScmRights(creds) = cmsg else {
        unreachable!()
    };
    assert!(creds.len() == 1);
    let efd2 = unsafe { std::mem::transmute::<i32, EventFd>(creds[0]) };

    efd1.write(5).unwrap();
    assert_eq!(efd2.read().unwrap(), 5);

    assert_eq!(buffer[..4], *b"1234");

    let mut cmsg_buffer = cmsg_space!([RawFd; 1]);
    let mut buffer = [0; 16];
    let mut slice_mut = IoSliceMut::new(&mut buffer);
    let msg = recvmsg::<()>(
        sock2.as_raw_fd(),
        core::slice::from_mut(&mut slice_mut),
        Some(&mut cmsg_buffer),
        MsgFlags::empty(),
    )
    .unwrap();
    assert_eq!(msg.bytes, 8);

    let mut cmsgs_iter = msg.cmsgs().unwrap();
    let cmsg = cmsgs_iter.next().unwrap();
    let ControlMessageOwned::ScmRights(creds) = cmsg else {
        unreachable!()
    };
    assert!(creds.len() == 1);
    let efd2 = unsafe { std::mem::transmute::<i32, EventFd>(creds[0]) };

    efd1.write(5).unwrap();
    assert_eq!(efd2.read().unwrap(), 5);

    assert_eq!(buffer[..8], *b"56781234");

    let mut cmsg_buffer = cmsg_space!([RawFd; 1]);
    let mut buffer = [0; 4];
    let mut slice_mut = IoSliceMut::new(&mut buffer);
    let msg = recvmsg::<()>(
        sock2.as_raw_fd(),
        core::slice::from_mut(&mut slice_mut),
        Some(&mut cmsg_buffer),
        MsgFlags::empty(),
    )
    .unwrap();
    assert_eq!(msg.bytes, 4);
    assert_eq!(buffer[..4], *b"5678");

    let mut cmsg_buffer = cmsg_space!([RawFd; 1]);
    let mut buffer = [0; 2];
    let mut slice_mut = IoSliceMut::new(&mut buffer);
    let msg = recvmsg::<()>(
        sock2.as_raw_fd(),
        core::slice::from_mut(&mut slice_mut),
        Some(&mut cmsg_buffer),
        MsgFlags::empty(),
    )
    .unwrap();
    assert_eq!(msg.bytes, 2);

    let mut cmsgs_iter = msg.cmsgs().unwrap();
    let cmsg = cmsgs_iter.next().unwrap();
    let ControlMessageOwned::ScmRights(creds) = cmsg else {
        unreachable!()
    };
    assert!(creds.len() == 1);
    let efd2 = unsafe { std::mem::transmute::<i32, EventFd>(creds[0]) };

    efd1.write(5).unwrap();
    assert_eq!(efd2.read().unwrap(), 5);

    assert_eq!(buffer[..2], *b"12");

    let mut cmsg_buffer = cmsg_space!([RawFd; 1]);
    let mut buffer = [0; 8];
    let mut slice_mut = IoSliceMut::new(&mut buffer);
    let msg = recvmsg::<()>(
        sock2.as_raw_fd(),
        core::slice::from_mut(&mut slice_mut),
        Some(&mut cmsg_buffer),
        MsgFlags::empty(),
    )
    .unwrap();
    assert_eq!(msg.bytes, 6);

    let mut cmsgs_iter = msg.cmsgs().unwrap();
    assert!(cmsgs_iter.next().is_none());
    assert_eq!(buffer[..6], *b"345678");
}

#[test]
fn sendmsg_recv() {
    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )
    .unwrap();

    let (read_half, write_half) = pipe2(OFlag::O_NONBLOCK).unwrap();

    // Make sure that reading the pipe blocks.
    let mut buf = [0; 8];
    assert_eq!(read(&read_half, &mut buf), Err(Errno::EAGAIN));

    // Send the write half over the socket.
    assert_eq!(
        sendmsg::<()>(
            sock1.as_raw_fd(),
            &[IoSlice::new(b"1234")],
            &[ControlMessage::ScmRights(&[write_half.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap(),
        4
    );
    drop(write_half);

    // Make sure that reading the pipe still blocks.
    assert_eq!(read(&read_half, &mut buf), Err(Errno::EAGAIN));

    // Receive the data. This implicitely closes the fd.
    assert_eq!(
        recv(sock2.as_raw_fd(), &mut buf, MsgFlags::empty()).unwrap(),
        4
    );

    // Make sure that the pipe is blocked.
    assert_eq!(read(&read_half, &mut buf).unwrap(), 0);
}

#[test]
fn sendmsg_empty() {
    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )
    .unwrap();

    let efd1 = EventFd::new().unwrap();

    // Send the fd over the socket.
    assert_eq!(
        sendmsg::<()>(
            sock1.as_raw_fd(),
            &[IoSlice::new(b"")],
            &[ControlMessage::ScmRights(&[efd1.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap(),
        0
    );

    // Send some more data.
    send(sock1.as_raw_fd(), b"1234", MsgFlags::empty()).unwrap();

    let mut cmsg_buffer = cmsg_space!([RawFd; 2]);
    let mut buffer = [0; 8];
    let mut slice_mut = IoSliceMut::new(&mut buffer);
    let msg = recvmsg::<()>(
        sock2.as_raw_fd(),
        core::slice::from_mut(&mut slice_mut),
        Some(&mut cmsg_buffer),
        MsgFlags::empty(),
    )
    .unwrap();
    assert_eq!(msg.bytes, 4);

    let mut cmsgs_iter = msg.cmsgs().unwrap();
    assert!(cmsgs_iter.next().is_none());

    assert_eq!(buffer[..4], *b"1234");
}

#[test]
fn shutdown_read_write() {
    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )
    .unwrap();

    let buffer = &mut [0; 4];

    assert_eq!(write(&sock1, b"1111"), Ok(4));
    assert_eq!(read(&sock2, buffer), Ok(4));
    assert_eq!(buffer, b"1111");

    assert_eq!(write(&sock2, b"2222"), Ok(4));
    assert_eq!(read(&sock1, buffer), Ok(4));
    assert_eq!(buffer, b"2222");

    shutdown(sock1.as_raw_fd(), Shutdown::Write).unwrap();

    assert_eq!(write(&sock1, b"3333"), Err(Errno::EPIPE));
    assert_eq!(read(&sock2, buffer), Ok(0));

    assert_eq!(write(&sock2, b"4444"), Ok(4));
    assert_eq!(read(&sock1, buffer), Ok(4));
    assert_eq!(buffer, b"4444");

    assert_eq!(write(&sock2, b"5555"), Ok(4));

    shutdown(sock1.as_raw_fd(), Shutdown::Read).unwrap();

    assert_eq!(write(&sock2, b"6666"), Err(Errno::EPIPE));
    assert_eq!(read(&sock1, buffer), Ok(4));
    assert_eq!(buffer, b"5555");
    assert_eq!(read(&sock1, buffer), Ok(0));
    assert_eq!(buffer, b"5555");
}

#[test]
fn connect_to_file() {
    let client = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .unwrap();

    // Connecting to a regular, non-socket file fails.
    let path = "regular-file";
    File::create(path).unwrap();
    let addr = UnixAddr::new(path).unwrap();
    assert_eq!(connect(client.as_raw_fd(), &addr), Err(Errno::ECONNREFUSED));
    unlink(path).unwrap();

    let server = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .unwrap();
    let path = "socket-connect";
    let addr = UnixAddr::new(path).unwrap();
    bind(server.as_raw_fd(), &addr).unwrap();

    // Connecting to a socket that's not yet listening should fail.
    assert_eq!(connect(client.as_raw_fd(), &addr), Err(Errno::ECONNREFUSED));

    listen(&server, Backlog::MAXALLOWABLE).unwrap();

    // Connecting to a listening socket should succeed.
    assert_eq!(connect(client.as_raw_fd(), &addr), Ok(()));

    let client = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .unwrap();

    // Connecting to a closed socket should fail.
    drop(server);
    assert_eq!(connect(client.as_raw_fd(), &addr), Err(Errno::ECONNREFUSED));

    unlink(path).unwrap();
}

#[test]
fn close_empty() {
    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None::<SockProtocol>,
        SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    let mut buf = [0; 16];
    assert_eq!(read(&sock1, &mut buf), Err(Errno::EAGAIN));

    drop(sock2);

    assert_eq!(read(&sock1, &mut buf), Ok(0));

    assert_eq!(write(&sock1, b"FOO"), Err(Errno::EPIPE));
}

#[test]
fn close_empty_after_write() {
    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None::<SockProtocol>,
        SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    write(&sock1, b"FOO").unwrap();

    let mut buf = [0; 16];
    assert_eq!(read(&sock2, &mut buf), Ok(3));

    drop(sock2);

    assert_eq!(read(&sock1, &mut buf), Ok(0));

    assert_eq!(write(&sock1, b"FOO"), Err(Errno::EPIPE));
}

#[test]
fn close_with_data() {
    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None::<SockProtocol>,
        SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    write(&sock1, b"FOO").unwrap();

    drop(sock2);

    let mut buf = [0; 16];
    assert_eq!(read(&sock1, &mut buf), Err(Errno::ECONNRESET));

    assert_eq!(write(&sock1, b"FOO"), Err(Errno::EPIPE));
}

#[test]
fn shutdown_with_data() {
    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None::<SockProtocol>,
        SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    write(&sock1, b"FOO").unwrap();

    shutdown(sock2.as_raw_fd(), Shutdown::Both).unwrap();

    let mut buf = [0; 16];
    assert_eq!(read(&sock1, &mut buf), Ok(0));

    drop(sock2);

    assert_eq!(read(&sock1, &mut buf), Err(Errno::ECONNRESET));

    assert_eq!(write(&sock1, b"FOO"), Err(Errno::EPIPE));
}

#[test]
fn shutdown_then_read() {
    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None::<SockProtocol>,
        SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    write(&sock1, b"FOO").unwrap();

    shutdown(sock2.as_raw_fd(), Shutdown::Both).unwrap();

    let mut buf = [0; 16];
    assert_eq!(read(&sock1, &mut buf), Ok(0));
    assert_eq!(read(&sock2, &mut buf), Ok(3));

    drop(sock2);

    assert_eq!(read(&sock1, &mut buf), Ok(0));

    assert_eq!(write(&sock1, b"FOO"), Err(Errno::EPIPE));
}

/// WAITALL has no effect when used with non-blocking a socket.
#[test]
fn waitall_nonblock() {
    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None::<SockProtocol>,
        SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    let mut buf = [0; 16];
    assert_eq!(
        recv(sock1.as_raw_fd(), &mut buf, MsgFlags::MSG_WAITALL),
        Err(Errno::EAGAIN)
    );

    assert_eq!(
        send(sock2.as_raw_fd(), b"12345678", MsgFlags::empty()),
        Ok(8)
    );

    let mut buf = [0; 16];
    assert_eq!(
        recv(sock1.as_raw_fd(), &mut buf, MsgFlags::MSG_WAITALL),
        Ok(8)
    );
}

/// WAITALL has no effect when used with DONTWAIT a socket.
#[test]
fn waitall_dontwait() {
    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None::<SockProtocol>,
        SockFlag::empty(),
    )
    .unwrap();

    let mut buf = [0; 16];
    assert_eq!(
        recv(
            sock1.as_raw_fd(),
            &mut buf,
            MsgFlags::MSG_WAITALL | MsgFlags::MSG_DONTWAIT
        ),
        Err(Errno::EAGAIN)
    );

    assert_eq!(
        send(sock2.as_raw_fd(), b"12345678", MsgFlags::empty()),
        Ok(8)
    );

    let mut buf = [0; 16];
    assert_eq!(
        recv(
            sock1.as_raw_fd(),
            &mut buf,
            MsgFlags::MSG_WAITALL | MsgFlags::MSG_DONTWAIT
        ),
        Ok(8)
    );
}

/// WAITALL has no effect when used with DONTWAIT a socket.
#[test]
fn waitall() {
    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None::<SockProtocol>,
        SockFlag::empty(),
    )
    .unwrap();

    // Send the first half of the message.
    assert_eq!(
        send(sock2.as_raw_fd(), b"12345678", MsgFlags::empty()),
        Ok(8)
    );

    // Delay sending more bytes.
    std::thread::spawn(move || {
        // Wait for half a second.
        std::thread::sleep(Duration::from_millis(500));
        // Send the second half of the message.
        assert_eq!(
            send(sock2.as_raw_fd(), b"90abcdef", MsgFlags::empty()),
            Ok(8)
        );
    });

    // Make sure that all 16 bytes are received.
    let mut buf = [0; 16];
    assert_eq!(
        recv(sock1.as_raw_fd(), &mut buf, MsgFlags::MSG_WAITALL),
        Ok(16)
    );
}

#[test]
fn dgram_pair_addrs() {
    let (a, b) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    // The local address is unnamed.
    let addr = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert!(addr.is_unnamed());
    let addr = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();
    assert!(addr.is_unnamed());

    // The remote address is unnamed.
    let addr = getpeername::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert!(addr.is_unnamed());
    let addr = getpeername::<UnixAddr>(b.as_raw_fd()).unwrap();
    assert!(addr.is_unnamed());
}

pub fn unspecified_addr() -> &'static dyn SockaddrLike {
    static ADDR: LazyLock<SockaddrStorage> = LazyLock::new(|| {
        let unspec = sockaddr {
            sa_family: AF_UNSPEC as u16,
            sa_data: [0; 14],
        };
        unsafe { SockaddrStorage::from_raw(&raw const unspec, Some(size_of::<sockaddr>() as u32)) }
            .unwrap()
    });
    &*ADDR
}

#[test]
fn dgram_pair_disconnect_getpeername() {
    let (a, _b) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    // Disconnect one half.
    assert_eq!(connect(a.as_raw_fd(), unspecified_addr()), Ok(()));

    // The remote address can no longer be queried.
    assert_eq!(getpeername::<UnixAddr>(a.as_raw_fd()), Err(Errno::ENOTCONN));
}

#[test]
fn dgram_pair_disconnect_send() {
    let (a, _b) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    // Disconnect one half.
    assert_eq!(connect(a.as_raw_fd(), unspecified_addr()), Ok(()));

    // Sending a packet from the socket no longer works.
    assert_eq!(
        send(a.as_raw_fd(), b"1234", MsgFlags::empty()),
        Err(Errno::ENOTCONN)
    );
}

#[test]
fn dgram_pair_disconnect_recv() {
    let (a, b) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    // Disconnect one half.
    assert_eq!(connect(a.as_raw_fd(), unspecified_addr()), Ok(()));

    // Sending a packet from the other socket still works.
    assert_eq!(send(b.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));
    let mut buf = [0; 16];
    let (n, addr) = recvfrom::<UnixAddr>(a.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(buf[..4], *b"1234");
    assert!(addr.is_none());
}

#[test]
fn dgram_pair_close_send() {
    let (a, b) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    // Close one of the sockets.
    drop(a);

    // Sending a packet from the other socket fails.
    assert_eq!(
        send(b.as_raw_fd(), b"1234", MsgFlags::empty()),
        Err(Errno::ECONNREFUSED)
    );
}

#[test]
fn dgram_pair_connect() {
    let (a, _b) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    // Auto-bind the socket to a unix address.
    bind(c.as_raw_fd(), &UnixAddr::new_unnamed()).unwrap();
    let addr = getsockname::<UnixAddr>(c.as_raw_fd()).unwrap();

    // Connecting one of the pair sockets fails.
    assert_eq!(connect(a.as_raw_fd(), &addr), Ok(()));
}

#[test]
fn dgram_pair_bind() {
    let (a, _b) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    // Binding the socket works.
    bind(a.as_raw_fd(), &UnixAddr::new_unnamed()).unwrap();
}

#[test]
fn dgram_pair_bind_connect_to() {
    let (a, _b) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Binding the socket works.
    bind(a.as_raw_fd(), &UnixAddr::new_unnamed()).unwrap();
    let addr = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();

    // Connecting to the socket fails because it's still part of the pair.
    assert_eq!(connect(c.as_raw_fd(), &addr), Err(Errno::EPERM));
}

#[test]
fn dgram_pair_bind_disconnect_connect_to() {
    let (a, _b) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Binding the socket works.
    bind(a.as_raw_fd(), &UnixAddr::new_unnamed()).unwrap();
    let addr = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();

    // Disconnect the socket from the pair.
    assert_eq!(connect(a.as_raw_fd(), unspecified_addr()), Ok(()));

    // Connecting to the socket succeeds because it's no longer part of the pair.
    assert_eq!(connect(c.as_raw_fd(), &addr), Ok(()));
}

#[test]
fn dgram_pair_bind_disconnect_other_connect_to() {
    let (a, b) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Binding the socket works.
    bind(a.as_raw_fd(), &UnixAddr::new_unnamed()).unwrap();
    let addr = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();

    // Disconnect the *other* socket from the pair.
    assert_eq!(connect(b.as_raw_fd(), unspecified_addr()), Ok(()));

    // Connecting to the socket fails because it's still part of the pair.
    assert_eq!(connect(c.as_raw_fd(), &addr), Err(Errno::EPERM));
}

#[test]
fn dgram_pair_bind_connect() {
    let (a, _b) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Binding the socket works.
    bind(c.as_raw_fd(), &UnixAddr::new_unnamed()).unwrap();
    let addr = getsockname::<UnixAddr>(c.as_raw_fd()).unwrap();

    // Connecting the socket succeeds.
    assert_eq!(connect(a.as_raw_fd(), &addr), Ok(()));
}

#[test]
fn dgram_pair_bind_connect_send() {
    let (a, _b) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Binding the socket works.
    bind(c.as_raw_fd(), &UnixAddr::new_unnamed()).unwrap();
    let addr = getsockname::<UnixAddr>(c.as_raw_fd()).unwrap();

    // Connecting the socket succeeds.
    assert_eq!(connect(a.as_raw_fd(), &addr), Ok(()));

    assert_eq!(send(a.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));
    let mut buf = [0; 16];
    let (n, addr) = recvfrom::<UnixAddr>(c.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(buf[..4], *b"1234");
    assert!(addr.is_none());
}

#[test]
fn dgram_pair_bind_bind_connect_send() {
    let (a, _b) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Binding the sockets works.
    bind(a.as_raw_fd(), &UnixAddr::new_unnamed()).unwrap();
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    bind(c.as_raw_fd(), &UnixAddr::new_unnamed()).unwrap();
    let addr_c = getsockname::<UnixAddr>(c.as_raw_fd()).unwrap();

    // Connecting the socket succeeds.
    assert_eq!(connect(a.as_raw_fd(), &addr_c), Ok(()));

    assert_eq!(send(a.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));
    let mut buf = [0; 16];
    let (n, addr) = recvfrom::<UnixAddr>(c.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(buf[..4], *b"1234");
    assert_eq!(addr, Some(addr_a));
}

#[test]
fn dgram_pair_bind_connect_send_to() {
    let (a, b) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None::<SockProtocol>,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();

    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Binding the socket works.
    bind(c.as_raw_fd(), &UnixAddr::new_unnamed()).unwrap();
    let addr = getsockname::<UnixAddr>(c.as_raw_fd()).unwrap();

    // Connecting the socket succeeds.
    assert_eq!(connect(a.as_raw_fd(), &addr), Ok(()));

    // Sending from the other half of the pair no longer works.
    assert_eq!(
        send(b.as_raw_fd(), b"1234", MsgFlags::empty()),
        Err(Errno::EPERM)
    );
}

#[test]
fn dgram_rebind_send_to() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Auto-bind the socket.
    bind(a.as_raw_fd(), &UnixAddr::new_unnamed()).unwrap();
    let addr = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert!(addr.as_abstract().is_some());

    assert_eq!(bind(b.as_raw_fd(), &addr), Err(Errno::EADDRINUSE));

    connect(c.as_raw_fd(), &addr).unwrap();

    // Test that sending and receiving works.
    send(c.as_raw_fd(), b"1234", MsgFlags::empty()).unwrap();
    let mut buf = [0; 16];
    assert_eq!(recv(a.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(4));
    assert_eq!(buf[..4], *b"1234");

    // Bind a new socket to the same address.
    drop(a);
    assert_eq!(bind(b.as_raw_fd(), &addr), Ok(()));

    // Test that sending not longer works.
    assert_eq!(
        send(c.as_raw_fd(), b"1234", MsgFlags::empty()),
        Err(Errno::ECONNREFUSED)
    );

    // Connect (again)
    connect(c.as_raw_fd(), &addr).unwrap();

    // Test that sending now works again.
    assert_eq!(send(c.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));
    let mut buf = [0; 16];
    assert_eq!(recv(b.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(4));
    assert_eq!(buf[..4], *b"1234");
}

#[test]
fn dgram_connect_to_sendto() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Auto-bind the socket.
    bind(a.as_raw_fd(), &UnixAddr::new_unnamed()).unwrap();
    let addr = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert!(addr.as_abstract().is_some());

    connect(b.as_raw_fd(), &addr).unwrap();

    // Test that sending and receiving works.
    send(b.as_raw_fd(), b"1234", MsgFlags::empty()).unwrap();
    let mut buf = [0; 16];
    assert_eq!(recv(a.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(4));
    assert_eq!(buf[..4], *b"1234");

    // Test that sending works.
    assert_eq!(
        sendto(c.as_raw_fd(), b"5678", &addr, MsgFlags::empty()),
        Ok(4)
    );
    assert_eq!(recv(a.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(4));
    assert_eq!(buf[..4], *b"5678");
}

#[test]
fn dgram_connect_sendto() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Auto-bind the socket.
    bind(a.as_raw_fd(), &UnixAddr::new_unnamed()).unwrap();
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert!(addr_a.as_abstract().is_some());
    bind(b.as_raw_fd(), &UnixAddr::new_unnamed()).unwrap();
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();
    assert!(addr_b.as_abstract().is_some());

    connect(b.as_raw_fd(), &addr_a).unwrap();

    // Test that sending doesn't work.
    assert_eq!(
        sendto(c.as_raw_fd(), b"5678", &addr_b, MsgFlags::empty()),
        Err(Errno::EPERM)
    );
}

#[test]
fn dgram_bind_bind() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(addr_a, addr_b);
}

#[test]
fn dgram_bind_bind_again() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(a.as_raw_fd(), &addr_a), Err(Errno::EINVAL));
    let addr_b = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(addr_a, addr_b);
}

#[test]
fn dgram_bind_direct() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let addr = b"my-address-1";
    let addr = UnixAddr::new_abstract(addr).unwrap();

    // Binding works.
    assert_eq!(bind(a.as_raw_fd(), &addr), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(addr, addr_a);
}

#[test]
fn dgram_bind_direct_again() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let addr = b"my-address-2";
    let addr = UnixAddr::new_abstract(addr).unwrap();

    // Binding works.
    assert_eq!(bind(a.as_raw_fd(), &addr), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(addr, addr_a);

    // Binding the same address again fails.
    assert_eq!(bind(a.as_raw_fd(), &addr), Err(Errno::EINVAL));
    let addr_b = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(addr, addr_b);
}

#[test]
fn dgram_bind_direct_bind_unnamed() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let addr = b"my-address-3";
    let addr = UnixAddr::new_abstract(addr).unwrap();

    // Binding works.
    assert_eq!(bind(a.as_raw_fd(), &addr), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(addr, addr_a);

    // Binding an unnamed address works and doesn't do anything.
    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(addr, addr_b);
}

#[test]
fn dgram_connect_getsockname() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Auto-bind one of the sockets.
    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();

    // Connect the other socket to the first.
    assert_eq!(connect(b.as_raw_fd(), &addr), Ok(()));

    // This doesn't cause the socket to be bound.
    let addr = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();
    assert_eq!(addr, UnixAddr::new_unnamed());
}

#[test]
fn dgram_connect_send_disconnect_recv() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Auto-bind one of the sockets.
    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();

    connect(b.as_raw_fd(), &addr).unwrap();

    assert_eq!(send(b.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));

    connect(b.as_raw_fd(), unspecified_addr()).unwrap();

    let mut buf = [0; 16];
    assert_eq!(recv(a.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(4));
}

#[test]
fn dgram_connect_connect_send_disconnect_recv() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Auto-bind one of the sockets.
    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();

    connect(a.as_raw_fd(), &addr_b).unwrap();
    connect(b.as_raw_fd(), &addr_a).unwrap();

    assert_eq!(send(b.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));

    connect(a.as_raw_fd(), unspecified_addr()).unwrap();

    let mut buf = [0; 16];
    assert_eq!(
        recv(a.as_raw_fd(), &mut buf, MsgFlags::empty()),
        Err(Errno::EAGAIN)
    );
}

#[test]
fn dgram_connect_send_to_disconnect_recv() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Auto-bind one of the sockets.
    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();

    connect(a.as_raw_fd(), &addr_b).unwrap();

    assert_eq!(
        sendto(b.as_raw_fd(), b"1234", &addr_a, MsgFlags::empty()),
        Ok(4)
    );

    connect(a.as_raw_fd(), unspecified_addr()).unwrap();

    let mut buf = [0; 16];
    assert_eq!(
        recv(a.as_raw_fd(), &mut buf, MsgFlags::empty()),
        Err(Errno::EAGAIN)
    );
}

#[test]
fn dgram_send_to_disconnect_recv() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Auto-bind one of the sockets.
    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();

    assert_eq!(
        sendto(b.as_raw_fd(), b"1234", &addr_a, MsgFlags::empty()),
        Ok(4)
    );

    connect(a.as_raw_fd(), unspecified_addr()).unwrap();

    let mut buf = [0; 16];
    assert_eq!(recv(a.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(4));
    assert_eq!(buf[..4], *b"1234");
}

#[test]
fn dgram_send_to_connect_recv() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    // Auto-bind one of the sockets.
    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();

    assert_eq!(
        sendto(b.as_raw_fd(), b"1234", &addr_a, MsgFlags::empty()),
        Ok(4)
    );

    connect(a.as_raw_fd(), &addr_b).unwrap();

    let mut buf = [0; 16];
    assert_eq!(recv(a.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(4));
    assert_eq!(buf[..4], *b"1234");
}

#[test]
fn dgram_bind_connect_connect() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();

    assert_eq!(connect(b.as_raw_fd(), &addr), Ok(()));
    assert_eq!(connect(c.as_raw_fd(), &addr), Ok(()));
}

#[test]
fn dgram_connect_connect_send_disconnect_send_recv() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();

    connect(a.as_raw_fd(), &addr_b).unwrap();
    connect(b.as_raw_fd(), &addr_a).unwrap();

    assert_eq!(send(b.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));

    connect(a.as_raw_fd(), unspecified_addr()).unwrap();

    assert_eq!(
        send(b.as_raw_fd(), b"1234", MsgFlags::empty()),
        Err(Errno::ECONNRESET)
    );
    let mut buf = [0; 16];
    assert_eq!(
        recv(b.as_raw_fd(), &mut buf, MsgFlags::empty()),
        Err(Errno::EAGAIN)
    );
}

#[test]
fn dgram_connect_connect_send_recv_disconnect_send() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();

    connect(a.as_raw_fd(), &addr_b).unwrap();
    connect(b.as_raw_fd(), &addr_a).unwrap();

    assert_eq!(send(b.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));
    let mut buf = [0; 16];
    assert_eq!(recv(a.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(4));
    assert_eq!(buf[..4], *b"1234");

    connect(a.as_raw_fd(), unspecified_addr()).unwrap();

    assert_eq!(send(b.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));
}

#[test]
fn dgram_connect_send_connect_disconnect_send() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();

    connect(b.as_raw_fd(), &addr_a).unwrap();

    assert_eq!(send(b.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));

    connect(a.as_raw_fd(), &addr_b).unwrap();
    connect(a.as_raw_fd(), unspecified_addr()).unwrap();

    assert_eq!(
        send(b.as_raw_fd(), b"1234", MsgFlags::empty()),
        Err(Errno::ECONNRESET)
    );
}

#[test]
fn dgram_connect_connect_send_connect_disconnect_send_send() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();

    connect(b.as_raw_fd(), &addr_a).unwrap();
    connect(c.as_raw_fd(), &addr_a).unwrap();

    assert_eq!(send(b.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));

    connect(a.as_raw_fd(), &addr_b).unwrap();
    connect(a.as_raw_fd(), unspecified_addr()).unwrap();

    assert_eq!(
        send(b.as_raw_fd(), b"1234", MsgFlags::empty()),
        Err(Errno::ECONNRESET)
    );
    assert_eq!(send(c.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));
}

#[test]
fn dgram_connect_connect_send_other_connect_disconnect_send_send() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();

    connect(b.as_raw_fd(), &addr_a).unwrap();
    connect(c.as_raw_fd(), &addr_a).unwrap();

    assert_eq!(send(c.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));

    connect(a.as_raw_fd(), &addr_b).unwrap();
    connect(a.as_raw_fd(), unspecified_addr()).unwrap();

    assert_eq!(
        send(b.as_raw_fd(), b"1234", MsgFlags::empty()),
        Err(Errno::ECONNRESET)
    );
    assert_eq!(send(c.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));
}

#[test]
fn dgram_connect_connect_sendto_connect_disconnect_send() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();

    connect(b.as_raw_fd(), &addr_a).unwrap();

    assert_eq!(
        sendto(c.as_raw_fd(), b"1234", &addr_a, MsgFlags::empty()),
        Ok(4)
    );

    connect(a.as_raw_fd(), &addr_b).unwrap();
    connect(a.as_raw_fd(), unspecified_addr()).unwrap();

    assert_eq!(
        send(b.as_raw_fd(), b"1234", MsgFlags::empty()),
        Err(Errno::ECONNRESET)
    );
}
#[test]
fn dgram_connect_connect_send_connect_again_send() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();

    connect(a.as_raw_fd(), &addr_b).unwrap();
    connect(b.as_raw_fd(), &addr_a).unwrap();

    assert_eq!(send(b.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));

    connect(a.as_raw_fd(), &addr_b).unwrap();

    assert_eq!(send(b.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));
}

#[test]
fn dgram_connect_sendto_connect_connect_send() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();
    assert_eq!(bind(c.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_c = getsockname::<UnixAddr>(c.as_raw_fd()).unwrap();

    connect(b.as_raw_fd(), &addr_a).unwrap();

    assert_eq!(
        sendto(c.as_raw_fd(), b"1234", &addr_a, MsgFlags::empty()),
        Ok(4)
    );

    connect(a.as_raw_fd(), &addr_b).unwrap();
    connect(a.as_raw_fd(), &addr_c).unwrap();

    assert_eq!(
        send(b.as_raw_fd(), b"1234", MsgFlags::empty()),
        Err(Errno::ECONNRESET)
    );
}

#[test]
fn dgram_connect_sendto_connect_connect_send_connect_send() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();
    assert_eq!(bind(c.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_c = getsockname::<UnixAddr>(c.as_raw_fd()).unwrap();

    connect(b.as_raw_fd(), &addr_a).unwrap();

    assert_eq!(
        sendto(c.as_raw_fd(), b"1234", &addr_a, MsgFlags::empty()),
        Ok(4)
    );

    connect(a.as_raw_fd(), &addr_b).unwrap();
    connect(a.as_raw_fd(), &addr_c).unwrap();

    assert_eq!(
        send(b.as_raw_fd(), b"1234", MsgFlags::empty()),
        Err(Errno::ECONNRESET)
    );

    connect(a.as_raw_fd(), &addr_b).unwrap();

    assert_eq!(send(b.as_raw_fd(), b"1234", MsgFlags::empty()), Ok(4));
}

#[test]
fn dgram_connect_connect_sendto_connect_send() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(c.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_c = getsockname::<UnixAddr>(c.as_raw_fd()).unwrap();

    connect(b.as_raw_fd(), &addr_a).unwrap();

    assert_eq!(
        sendto(c.as_raw_fd(), b"1234", &addr_a, MsgFlags::empty()),
        Ok(4)
    );

    connect(a.as_raw_fd(), &addr_c).unwrap();

    assert_eq!(
        send(b.as_raw_fd(), b"1234", MsgFlags::empty()),
        Err(Errno::EPERM)
    );
}

#[test]
fn dgram_connect_connect_sendto_connect_recv() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(c.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_c = getsockname::<UnixAddr>(c.as_raw_fd()).unwrap();

    connect(b.as_raw_fd(), &addr_a).unwrap();

    assert_eq!(
        sendto(c.as_raw_fd(), b"1234", &addr_a, MsgFlags::empty()),
        Ok(4)
    );

    connect(b.as_raw_fd(), &addr_c).unwrap();

    let mut buf = [0; 16];
    assert_eq!(
        recv(b.as_raw_fd(), &mut buf, MsgFlags::empty()),
        Err(Errno::EAGAIN)
    );
}

#[test]
fn dgram_connect_connect_sendto_connect_again_recv() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();

    connect(b.as_raw_fd(), &addr_a).unwrap();

    assert_eq!(
        sendto(c.as_raw_fd(), b"1234", &addr_a, MsgFlags::empty()),
        Ok(4)
    );

    connect(b.as_raw_fd(), &addr_a).unwrap();

    let mut buf = [0; 16];
    assert_eq!(
        recv(b.as_raw_fd(), &mut buf, MsgFlags::empty()),
        Err(Errno::EAGAIN)
    );
}

#[test]
fn dgram_bind_sendto_bind_recv_from() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();

    sendto(b.as_raw_fd(), b"1234", &addr_a, MsgFlags::empty()).unwrap();

    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();
    assert!(addr_b.is_unnamed());

    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();
    assert!(addr_b.as_abstract().is_some());

    let mut buf = [0; 16];
    let (n, addr) = recvfrom::<UnixAddr>(a.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(buf[..4], *b"1234");
    assert_eq!(addr, Some(addr_b));
}

#[test]
fn dgram_bind_sendto_bind_close_recv_from() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();

    sendto(b.as_raw_fd(), b"1234", &addr_a, MsgFlags::empty()).unwrap();

    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();
    assert!(addr_b.is_unnamed());

    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();
    assert!(addr_b.as_abstract().is_some());

    drop(b);

    let mut buf = [0; 16];
    let (n, addr) = recvfrom::<UnixAddr>(a.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(buf[..4], *b"1234");
    assert_eq!(addr, Some(addr_b));
}

#[test]
fn dgram_bind_inet() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(
        bind(a.as_raw_fd(), &SockaddrIn::new(0, 0, 0, 0, 0)),
        Err(Errno::EINVAL)
    );
}

#[test]
fn dgram_sendto_inet() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(
        sendto(
            a.as_raw_fd(),
            b"1234",
            &SockaddrIn::new(0, 0, 0, 0, 0),
            MsgFlags::empty()
        ),
        Err(Errno::EINVAL)
    );
}

#[test]
fn dgram_sendto_unnamed() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(
        sendto(
            a.as_raw_fd(),
            b"1234",
            &UnixAddr::new_unnamed(),
            MsgFlags::empty()
        ),
        Err(Errno::EINVAL)
    );
}

#[test]
fn dgram_bind_connect_close_getpeername() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();

    connect(b.as_raw_fd(), &addr_a).unwrap();

    let addr = getpeername::<UnixAddr>(b.as_raw_fd()).unwrap();
    assert_eq!(addr, addr_a);

    drop(a);

    let addr = getpeername::<UnixAddr>(b.as_raw_fd()).unwrap();
    assert_eq!(addr, addr_a);
}

#[test]
fn dgram_bind_bind_connect_sendto_sendto_recv_recv() {
    let a = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let c = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();

    assert_eq!(bind(a.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_a = getsockname::<UnixAddr>(a.as_raw_fd()).unwrap();
    assert_eq!(bind(b.as_raw_fd(), &UnixAddr::new_unnamed()), Ok(()));
    let addr_b = getsockname::<UnixAddr>(b.as_raw_fd()).unwrap();

    connect(c.as_raw_fd(), &addr_a).unwrap();
    connect(c.as_raw_fd(), &addr_b).unwrap();

    assert_eq!(
        sendto(c.as_raw_fd(), b"1234", &addr_a, MsgFlags::empty()),
        Ok(4)
    );
    assert_eq!(
        sendto(c.as_raw_fd(), b"5678", &addr_b, MsgFlags::empty()),
        Ok(4)
    );

    let mut buf = [0; 16];
    assert_eq!(recv(a.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(4));
    assert_eq!(buf[..4], *b"1234");
    assert_eq!(recv(b.as_raw_fd(), &mut buf, MsgFlags::empty()), Ok(4));
    assert_eq!(buf[..4], *b"5678");
}
