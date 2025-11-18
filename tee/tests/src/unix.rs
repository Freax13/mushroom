use std::{
    fs::File,
    io::{IoSlice, IoSliceMut},
    os::fd::{AsRawFd, RawFd},
};

use nix::{
    cmsg_space,
    errno::Errno,
    fcntl::OFlag,
    sys::{
        eventfd::EventFd,
        socket::{
            AddressFamily, Backlog, ControlMessage, ControlMessageOwned, MsgFlags, Shutdown,
            SockFlag, SockType, UnixAddr, bind, connect, getsockname, listen, recv, recvmsg, send,
            sendmsg, shutdown, socket, socketpair,
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
