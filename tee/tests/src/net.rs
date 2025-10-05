use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicU16, Ordering},
};

use nix::{
    Result,
    errno::Errno,
    libc::{Ioctl, ioctl},
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::socket::{
        self, AddressFamily, Backlog, MsgFlags, SockFlag, SockType, SockaddrIn, SockaddrIn6,
        getpeername, getsockname, setsockopt, shutdown,
        sockopt::{Ipv6V6Only, ReuseAddr, ReusePort},
    },
    unistd::close,
};

fn bind(addr: Ipv4Addr, port: u16, reuse_addr: bool, reuse_port: bool) -> Result<OwnedFd> {
    let sock = socket::socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .unwrap();
    setsockopt(&sock, ReuseAddr, &reuse_addr).unwrap();
    setsockopt(&sock, ReusePort, &reuse_port).unwrap();
    socket::bind(
        sock.as_raw_fd(),
        &SockaddrIn::new(
            addr.octets()[0],
            addr.octets()[1],
            addr.octets()[2],
            addr.octets()[3],
            port,
        ),
    )?;
    Ok(sock)
}

fn get_port() -> u16 {
    static PORT_COUNTER: AtomicU16 = AtomicU16::new(20000);
    PORT_COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketAOp {
    ListenEarly,
    ListenLate,
    ConnectEarly(Ipv4Addr),
    ConnectLate(Ipv4Addr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketBOp {
    Listen,
    Connect(Ipv4Addr),
}

const TEST_IPS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(127, 0, 0, 1),
    Ipv4Addr::new(127, 0, 0, 2),
    Ipv4Addr::UNSPECIFIED,
];
const SOCKET_A_OPS: [Option<SocketAOp>; 9] = [
    None,
    Some(SocketAOp::ListenEarly),
    Some(SocketAOp::ListenLate),
    Some(SocketAOp::ConnectEarly(Ipv4Addr::new(127, 0, 0, 1))),
    Some(SocketAOp::ConnectEarly(Ipv4Addr::new(127, 0, 0, 2))),
    Some(SocketAOp::ConnectEarly(Ipv4Addr::UNSPECIFIED)),
    Some(SocketAOp::ConnectLate(Ipv4Addr::new(127, 0, 0, 1))),
    Some(SocketAOp::ConnectLate(Ipv4Addr::new(127, 0, 0, 2))),
    Some(SocketAOp::ConnectLate(Ipv4Addr::UNSPECIFIED)),
];
const SOCKET_B_OPS: [SocketBOp; 4] = [
    SocketBOp::Listen,
    SocketBOp::Connect(Ipv4Addr::new(127, 0, 0, 1)),
    SocketBOp::Connect(Ipv4Addr::new(127, 0, 0, 2)),
    SocketBOp::Connect(Ipv4Addr::UNSPECIFIED),
];

#[test]
fn test_bind() {
    // Create a socket that we can connect to.
    let connect_port = get_port();
    let sock = bind(Ipv4Addr::UNSPECIFIED, connect_port, false, false).unwrap();
    socket::listen(&sock, Backlog::MAXALLOWABLE).unwrap();
    // Spawn a thread that accepts connections.
    let sockfd = sock.as_raw_fd();
    std::thread::spawn(move || -> Result<()> {
        loop {
            close(socket::accept(sockfd)?).unwrap();
        }
    });

    let mut counter = 0;

    for ip_a in TEST_IPS {
        for reuse_addr_a in [false, true] {
            for reuse_port_a in [false, true] {
                for socket_a_op in SOCKET_A_OPS {
                    for ip_b in TEST_IPS {
                        for reuse_addr_b in [false, true] {
                            for reuse_port_b in [false, true] {
                                for socket_b_op in SOCKET_B_OPS {
                                    counter += 1;
                                    println!("---------------------------------------");
                                    println!("test case {counter}");
                                    test_case(
                                        connect_port,
                                        ip_a,
                                        reuse_addr_a,
                                        reuse_port_a,
                                        socket_a_op,
                                        ip_b,
                                        reuse_addr_b,
                                        reuse_port_b,
                                        socket_b_op,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn test_case(
        connect_port: u16,
        mut ip_a: Ipv4Addr,
        reuse_addr_a: bool,
        reuse_port_a: bool,
        socket_a_op: Option<SocketAOp>,
        ip_b: Ipv4Addr,
        reuse_addr_b: bool,
        reuse_port_b: bool,
        socket_b_op: SocketBOp,
    ) {
        let port = get_port();

        let reuse_port_both = reuse_port_a && reuse_port_b;

        // Bind the first socket.
        println!(
            "Binding socket A to {ip_a}:{port} with reuse_addr={reuse_addr_a} and reuse_port={reuse_port_a}"
        );
        let a = bind(ip_a, port, reuse_addr_a, reuse_port_a).unwrap();

        // Optionally make the first socket into a passive socket before binding
        // the other socket.
        if socket_a_op == Some(SocketAOp::ListenEarly) {
            println!("Starting to listen on socket A");
            socket::listen(&a, Backlog::MAXALLOWABLE).unwrap();
        }
        // Optionally make the first socket into an active socket before binding
        // the other socket.
        if let Some(SocketAOp::ConnectEarly(ip)) = socket_a_op {
            println!("Connecting socket A to {ip}:{connect_port}");
            socket::connect(
                a.as_raw_fd(),
                &SockaddrIn::new(
                    ip.octets()[0],
                    ip.octets()[1],
                    ip.octets()[2],
                    ip.octets()[3],
                    connect_port,
                ),
            )
            .unwrap();

            // Connecting the socket might have changed its ip, so update the IP.
            let sockname = getsockname::<SockaddrIn>(a.as_raw_fd()).unwrap();
            if ip_a.is_unspecified() {
                assert_eq!(sockname.ip(), Ipv4Addr::LOCALHOST);
            } else {
                assert_eq!(sockname.ip(), ip_a);
            }
            ip_a = sockname.ip();

            // Check the IP of the peer.
            let peername = getpeername::<SockaddrIn>(a.as_raw_fd()).unwrap();
            if !ip.is_unspecified() {
                assert_eq!(peername.ip(), ip);
            } else {
                assert_eq!(sockname.ip(), ip_a);
            }
        }

        let non_overlapping_ip = !ip_a.is_unspecified() && !ip_b.is_unspecified() && ip_a != ip_b;

        // Make sure that binding works when we expect it to.
        let bind_expect_success = non_overlapping_ip
            || (socket_a_op != Some(SocketAOp::ListenEarly) && reuse_addr_a && reuse_addr_b)
            || reuse_port_both;
        println!(
            "Binding socket B to {ip_b}:{port} with reuse_addr={reuse_addr_b} and reuse_port={reuse_port_b}"
        );
        let res = bind(ip_b, port, reuse_addr_b, reuse_port_b);
        assert_eq!(res.is_ok(), bind_expect_success);

        // Stop the test when binding failed.
        let Ok(b) = res else {
            return;
        };

        // Optionally make the first socket into a passive socket after binding the
        // the other socket.
        if socket_a_op == Some(SocketAOp::ListenLate) {
            println!("Starting to listen on socket A");
            socket::listen(&a, Backlog::MAXALLOWABLE).unwrap();
        }
        // Optionally make the first socket into an active socket after binding the
        // other socket.
        if let Some(SocketAOp::ConnectLate(ip)) = socket_a_op {
            println!("Connecting socket A to {ip}:{connect_port}");
            socket::connect(
                a.as_raw_fd(),
                &SockaddrIn::new(
                    ip.octets()[0],
                    ip.octets()[1],
                    ip.octets()[2],
                    ip.octets()[3],
                    connect_port,
                ),
            )
            .unwrap();

            // Connecting the socket might have changed its ip, so update the IP.
            let sockname = getsockname::<SockaddrIn>(a.as_raw_fd()).unwrap();
            if ip_a.is_unspecified() {
                assert_eq!(sockname.ip(), Ipv4Addr::LOCALHOST);
            } else {
                assert_eq!(sockname.ip(), ip_a);
            }
            ip_a = sockname.ip();

            // Check the IP of the peer.
            let peername = getpeername::<SockaddrIn>(a.as_raw_fd()).unwrap();
            if !ip.is_unspecified() {
                assert_eq!(peername.ip(), ip);
            } else {
                assert_eq!(sockname.ip(), ip_a);
            }
        }

        match socket_b_op {
            SocketBOp::Listen => {
                // Make sure that listening works when we expect it to.
                let listen_b_expect_success = non_overlapping_ip
                    || !socket_a_op.is_some_and(|op| {
                        matches!(op, SocketAOp::ListenEarly | SocketAOp::ListenLate)
                    })
                    || reuse_port_both;
                println!("Starting to listen on socket B");
                let res = socket::listen(&b, Backlog::MAXALLOWABLE);
                assert_eq!(res.is_ok(), listen_b_expect_success);
                let res = socket::listen(&b, Backlog::MAXALLOWABLE);
                assert_eq!(res.is_ok(), listen_b_expect_success);
            }
            SocketBOp::Connect(ip_dest_b) => {
                // Make sure that connecting works when we expect it to.
                let connect_b_expect_success = socket_a_op.is_none_or(|op| {
                    match op {
                        SocketAOp::ListenEarly | SocketAOp::ListenLate => true,
                        SocketAOp::ConnectEarly(ip_dest_a) | SocketAOp::ConnectLate(ip_dest_a) => {
                            // Connecting the ip might update the IP, so factor that in
                            // when predicting whether connecting should fail.
                            let ip_b = if ip_b.is_unspecified() {
                                Ipv4Addr::LOCALHOST
                            } else {
                                ip_b
                            };

                            let effective_ip_dest_a = if ip_dest_a.is_unspecified() {
                                ip_a
                            } else {
                                ip_dest_a
                            };
                            let effective_ip_dest_b = if ip_dest_b.is_unspecified() {
                                ip_b
                            } else {
                                ip_dest_b
                            };

                            (ip_a, effective_ip_dest_a) != (ip_b, effective_ip_dest_b)
                        }
                    }
                });
                println!("Connecting socket B to {ip_dest_b}:{connect_port}");
                let res = socket::connect(
                    b.as_raw_fd(),
                    &SockaddrIn::new(
                        ip_dest_b.octets()[0],
                        ip_dest_b.octets()[1],
                        ip_dest_b.octets()[2],
                        ip_dest_b.octets()[3],
                        connect_port,
                    ),
                );
                assert_eq!(res.is_ok(), connect_b_expect_success);
            }
        }
    }
}

fn sockatmark(a: &impl AsFd) -> Result<bool> {
    const SIOCATMARK: Ioctl = 0x8905;
    let mut value = 0u32;
    let res = unsafe { ioctl(a.as_fd().as_raw_fd(), SIOCATMARK, &mut value) };
    Errno::result(res)?;
    Ok(value != 0)
}

#[test]
fn test_oob() -> Result<()> {
    let listener = socket::socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK,
        None,
    )?;

    // The socket is not at the mark if the socket is not yet bound.
    assert!(!sockatmark(&listener)?);

    socket::listen(&listener, Backlog::MAXALLOWABLE)?;
    let sockname = getsockname::<SockaddrIn>(listener.as_raw_fd())?;

    let sock1 = socket::socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    let fd1 = sock1.as_raw_fd();

    // The socket is not at the mark if the socket is not yet connected.
    assert!(!sockatmark(&sock1)?);
    // The same goes for all listening sockets.
    assert!(!sockatmark(&listener)?);

    let _ = socket::connect(fd1, &sockname);

    let fd2 = socket::accept(listener.as_raw_fd())?;
    let sock2 = unsafe { OwnedFd::from_raw_fd(fd2) };

    assert!(!sockatmark(&sock1)?);
    assert!(!sockatmark(&sock2)?);

    let mut buffer = [0u8; 16];

    // Send some OOB data.
    socket::send(fd1, b"1234", MsgFlags::MSG_OOB)?;

    // We expect to be able to read all but the last byte using a normal recv.
    assert!(!sockatmark(&sock2)?);
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::empty())?, 3);
    assert_eq!(buffer[0..3], *b"123");

    // After reading the normal data, we expect to be able to read the OOB
    // data.
    assert!(sockatmark(&sock2)?);
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::MSG_OOB)?, 1);
    assert_eq!(buffer[0..1], *b"4");
    assert!(sockatmark(&sock2)?);

    // This should also work if we read the normal data in multiple chunks:

    // Send some OOB data.
    socket::send(fd1, b"1234", MsgFlags::MSG_OOB)?;

    // We expect to be able to read all but the last byte using a normal recv.
    assert!(!sockatmark(&sock2)?);
    assert_eq!(socket::recv(fd2, &mut buffer[..2], MsgFlags::empty())?, 2);
    assert_eq!(buffer[0..2], *b"12");
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::empty())?, 1);
    assert_eq!(buffer[0..1], *b"3");

    // After reading the normal data, we expect to be able to read the OOB
    // data.
    assert!(sockatmark(&sock2)?);
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::MSG_OOB)?, 1);
    assert_eq!(buffer[0..1], *b"4");
    assert!(sockatmark(&sock2)?);

    // Sending OOB data multiple times results in only the earlier OOB data
    // being treated as normal data:

    // Send some OOB data.
    socket::send(fd1, b"1234", MsgFlags::MSG_OOB)?;
    socket::send(fd1, b"5678", MsgFlags::MSG_OOB)?;

    // We expect to be able to read all but the last byte using a normal recv.
    assert!(!sockatmark(&sock2)?);
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::empty())?, 7);
    assert_eq!(buffer[0..7], *b"1234567");

    // After reading the normal data, we expect to be able to read the OOB
    // data.
    assert!(sockatmark(&sock2)?);
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::MSG_OOB)?, 1);
    assert_eq!(buffer[0..1], *b"8");
    assert!(sockatmark(&sock2)?);

    // Sending OOB data resets the marker flag and silently consumes a pending
    // OOB byte when it's the next byte.

    socket::send(fd1, b"1234", MsgFlags::MSG_OOB)?;

    // We expect to be able to read all but the last byte using a normal recv.
    assert!(!sockatmark(&sock2)?);
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::empty())?, 3);
    assert_eq!(buffer[0..3], *b"123");

    // We're now at the OOB mark.
    assert!(sockatmark(&sock2)?);

    // Sending more data resets this.
    socket::send(fd1, b"5678", MsgFlags::MSG_OOB)?;
    assert!(!sockatmark(&sock2)?);

    // We can now read more normal data, but skip over the previous OOB data.
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::empty())?, 3);
    assert_eq!(buffer[0..3], *b"567");

    // After reading the normal data, we expect to be able to read the OOB
    // data.
    assert!(sockatmark(&sock2)?);
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::MSG_OOB)?, 1);
    assert_eq!(buffer[0..1], *b"8");
    assert!(sockatmark(&sock2)?);

    // Reset the mark flag.
    socket::send(fd1, b"1234", MsgFlags::empty())?;
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::empty())?, 4);
    assert_eq!(buffer[0..4], *b"1234");

    // Sending 0 bytes of OOB data does nothing:

    assert!(!sockatmark(&sock2)?);
    socket::send(fd1, b"", MsgFlags::MSG_OOB)?;
    assert!(!sockatmark(&sock2)?);

    // We can read the OOB data in between reading normal data.

    // Send some OOB data.
    socket::send(fd1, b"1234", MsgFlags::MSG_OOB)?;

    // Read part of the data.
    assert!(!sockatmark(&sock2)?);
    assert_eq!(socket::recv(fd2, &mut buffer[..2], MsgFlags::empty())?, 2);
    assert_eq!(buffer[0..2], *b"12");

    // Read the OOB data even though we're not yet at the mark.
    assert!(!sockatmark(&sock2)?);
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::MSG_OOB)?, 1);
    assert_eq!(buffer[0..1], *b"4");
    assert!(!sockatmark(&sock2)?);

    // Reading the remaining data should set the mark flag.
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::empty())?, 1);
    assert_eq!(buffer[0..1], *b"3");
    assert!(sockatmark(&sock2)?);

    // Receiving OOB doesn't skip over the OOB mark even when there's more
    // normal data available.

    // Send some OOB data and some more normal data.
    socket::send(fd1, b"1234", MsgFlags::MSG_OOB)?;
    socket::send(fd1, b"5678", MsgFlags::empty())?;

    // Reading normal data should stop early.
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::empty())?, 3);
    assert_eq!(buffer[0..3], *b"123");
    assert!(sockatmark(&sock2)?);

    // We don't need to read the OOB data, it will just be skipped over.

    // Only after this can we read the rest of the data.
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::empty())?, 4);
    assert_eq!(buffer[0..4], *b"5678");
    assert!(!sockatmark(&sock2)?);

    // Check that poll returns the PRI flag correctly.

    // If not at the there's no OOB data, PRI is not set.
    let mut fd = PollFd::new(sock2.as_fd(), PollFlags::POLLPRI);
    poll(core::slice::from_mut(&mut fd), PollTimeout::ZERO).unwrap();
    assert!(!fd.revents().unwrap().contains(PollFlags::POLLPRI));

    // Send some OOB data and some more normal data.
    socket::send(fd1, b"1234", MsgFlags::MSG_OOB)?;

    // The PRI flag is now set.
    poll(core::slice::from_mut(&mut fd), PollTimeout::ZERO).unwrap();
    assert!(fd.revents().unwrap().contains(PollFlags::POLLPRI));

    // Read the normal data.
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::empty())?, 3);
    assert_eq!(buffer[0..3], *b"123");
    assert!(sockatmark(&sock2)?);

    // The PRI flag is still set.
    poll(core::slice::from_mut(&mut fd), PollTimeout::ZERO).unwrap();
    assert!(fd.revents().unwrap().contains(PollFlags::POLLPRI));

    // Reading the OOB data resets the PRI flag.
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::MSG_OOB)?, 1);
    poll(core::slice::from_mut(&mut fd), PollTimeout::ZERO).unwrap();
    assert!(!fd.revents().unwrap().contains(PollFlags::POLLPRI));
    // Even though the OOB mark is still set.
    assert!(sockatmark(&sock2)?);

    // Starting a read resets the OOB mark even if no data is read.

    socket::send(fd1, b"1234", MsgFlags::MSG_OOB)?;

    // We expect to be able to read all but the last byte using a normal recv.
    assert!(!sockatmark(&sock2)?);
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::empty())?, 3);
    assert_eq!(buffer[0..3], *b"123");

    // We're now at the OOB mark.
    assert!(sockatmark(&sock2)?);

    // Read no data.
    assert_eq!(
        socket::recv(fd2, &mut buffer, MsgFlags::MSG_DONTWAIT),
        Err(Errno::EAGAIN)
    );

    // The OOB mark is reset.
    assert!(!sockatmark(&sock2)?);

    // Reading data doesn't remove it from the buffer. If another OOB message
    // comes in, we'll read the data again.

    socket::send(fd1, b"1234", MsgFlags::MSG_OOB)?;

    // We expect to be able to read all but the last byte using a normal recv.
    assert!(!sockatmark(&sock2)?);
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::MSG_OOB)?, 1);
    assert_eq!(buffer[0..1], *b"4");

    // We're now at the OOB mark.
    assert!(!sockatmark(&sock2)?);

    socket::send(fd1, b"5678", MsgFlags::MSG_OOB)?;

    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::empty()), Ok(7));
    assert_eq!(buffer[0..7], *b"1234567");

    // The OOB mark is reset.
    assert!(sockatmark(&sock2)?);

    // Read the OOB data.
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::MSG_OOB)?, 1);
    assert_eq!(buffer[0..1], *b"8");
    assert!(sockatmark(&sock2)?);

    // Peeking OOB data doesn't remove it.

    socket::send(fd1, b"1234", MsgFlags::MSG_OOB)?;

    // We expect to be able to read all but the last byte using a normal recv.
    assert!(!sockatmark(&sock2)?);
    assert_eq!(
        socket::recv(fd2, &mut buffer, MsgFlags::MSG_OOB | MsgFlags::MSG_PEEK)?,
        1
    );
    assert_eq!(buffer[0..1], *b"4");

    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::empty()), Ok(3));
    assert_eq!(buffer[0..3], *b"123");

    // The OOB mark is reset.
    assert!(sockatmark(&sock2)?);

    // Read the OOB data.
    assert_eq!(socket::recv(fd2, &mut buffer, MsgFlags::MSG_OOB)?, 1);
    assert_eq!(buffer[0..1], *b"4");
    assert!(sockatmark(&sock2)?);

    Ok(())
}

#[test]
fn socket_shutdown_both() -> Result<()> {
    let listener = socket::socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;

    socket::listen(&listener, Backlog::MAXALLOWABLE)?;
    let sockname = getsockname::<SockaddrIn>(listener.as_raw_fd())?;

    let sock1 = socket::socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;
    let fd1 = sock1.as_raw_fd();

    socket::connect(fd1, &sockname).unwrap();

    let fd2 = socket::accept(listener.as_raw_fd())?;
    let sock2 = unsafe { OwnedFd::from_raw_fd(fd2) };

    // Writes should usually work.
    assert_eq!(nix::unistd::write(&sock1, b"1234")?, 4);
    assert_eq!(nix::unistd::write(&sock2, b"5678")?, 4);

    shutdown(sock2.as_raw_fd(), socket::Shutdown::Both).unwrap();

    // Writes to the other half should continue to work after shutdown.
    assert_eq!(nix::unistd::write(&sock1, b"90ab"), Ok(4));
    // Write to the shutdown socket should fail.
    assert_eq!(nix::unistd::write(&sock2, b"cdef"), Err(Errno::ECONNRESET));

    let mut buffer = [0; 16];
    // Reads from the other half should yield the data written before the
    // shutdown and then return 0.
    assert_eq!(nix::unistd::read(&sock1, &mut buffer), Ok(4));
    assert_eq!(buffer[0..4], *b"5678");
    assert_eq!(nix::unistd::read(&sock1, &mut buffer), Ok(0));
    // Reads from the shutdown half should yield the data written before the
    // shutdown and then return 0. They should not yield the data written after
    // the shutdown.
    assert_eq!(nix::unistd::read(&sock2, &mut buffer), Ok(4));
    assert_eq!(buffer[0..4], *b"1234");
    assert_eq!(nix::unistd::read(&sock2, &mut buffer), Ok(0));

    Ok(())
}

#[test]
fn udp_socketname() {
    let server = socket::socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .unwrap();

    socket::bind(server.as_raw_fd(), &SockaddrIn::new(127, 0, 0, 1, 0)).unwrap();
    let server_name = socket::getsockname::<SockaddrIn>(server.as_raw_fd()).unwrap();
    assert_eq!(server_name.ip(), Ipv4Addr::LOCALHOST);
    assert_ne!(server_name.port(), 0);

    let make_client = || {
        socket::socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .unwrap()
    };

    {
        // By default, the socket's address is unspecified.
        let client = make_client();
        let client_name = socket::getsockname::<SockaddrIn>(client.as_raw_fd()).unwrap();
        assert_eq!(client_name.ip(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(client_name.port(), 0);
    }

    {
        // Sending a packet does not change the address, but it binds the socket to a port.
        let client = make_client();
        socket::sendto(client.as_raw_fd(), b"foo", &server_name, MsgFlags::empty()).unwrap();
        let client_name = socket::getsockname::<SockaddrIn>(client.as_raw_fd()).unwrap();
        assert_eq!(client_name.ip(), Ipv4Addr::UNSPECIFIED);
        assert_ne!(client_name.port(), 0);
    }

    {
        // Connecting the socket binds it to the same interface.
        let client = make_client();
        socket::connect(client.as_raw_fd(), &SockaddrIn::new(127, 0, 0, 1, 0)).unwrap();
        let client_name = socket::getsockname::<SockaddrIn>(client.as_raw_fd()).unwrap();
        assert_eq!(client_name.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(client_name.port(), 0);
    }

    {
        // Connecting the socket binds it to the same interface, but not necessarily the same IP.
        let client = make_client();
        socket::connect(client.as_raw_fd(), &SockaddrIn::new(127, 0, 0, 2, 0)).unwrap();
        let client_name = socket::getsockname::<SockaddrIn>(client.as_raw_fd()).unwrap();
        assert_eq!(client_name.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(client_name.port(), 0);
    }
}

#[test]
fn udp_dual_stack_localhost() {
    let bind_addrv4 = SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let bind_addrv6 = SockaddrIn6::from(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0));

    let sock4 = socket::socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    assert_eq!(
        socket::bind(sock4.as_raw_fd(), &bind_addrv6),
        Err(Errno::EAFNOSUPPORT)
    );
    socket::bind(sock4.as_raw_fd(), &bind_addrv4).unwrap();

    let sock46 = socket::socket(
        AddressFamily::Inet6,
        SockType::Datagram,
        SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    assert_eq!(
        socket::bind(sock46.as_raw_fd(), &bind_addrv4),
        Err(Errno::EINVAL)
    );
    socket::bind(sock46.as_raw_fd(), &bind_addrv6).unwrap();

    let sock6 = socket::socket(
        AddressFamily::Inet6,
        SockType::Datagram,
        SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    socket::setsockopt(&sock6, Ipv6V6Only, &true).unwrap();
    assert_eq!(
        socket::bind(sock6.as_raw_fd(), &bind_addrv4),
        Err(Errno::EINVAL)
    );
    socket::bind(sock6.as_raw_fd(), &bind_addrv6).unwrap();

    let addr4 = socket::getsockname::<SockaddrIn>(sock4.as_raw_fd()).unwrap();
    let addr46 = socket::getsockname::<SockaddrIn6>(sock46.as_raw_fd()).unwrap();
    let addr6 = socket::getsockname::<SockaddrIn6>(sock6.as_raw_fd()).unwrap();

    assert_eq!(addr4.ip(), Ipv4Addr::LOCALHOST);
    assert_eq!(addr46.ip(), Ipv6Addr::LOCALHOST);
    assert_eq!(addr6.ip(), Ipv6Addr::LOCALHOST);

    assert_ne!(addr6.port(), addr46.port());

    let mut addr4 = SocketAddrV4::from(addr4);
    addr4.set_ip(Ipv4Addr::LOCALHOST);
    let addr4 = SockaddrIn::from(addr4);

    let mut addr46 = SocketAddrV6::from(addr46);
    addr46.set_ip(Ipv6Addr::LOCALHOST);
    let addr46 = SockaddrIn6::from(addr46);

    let mut addr6 = SocketAddrV6::from(addr6);
    addr6.set_ip(Ipv6Addr::LOCALHOST);
    let addr6 = SockaddrIn6::from(addr6);

    let addr4_mapped = SocketAddrV6::new(addr4.ip().to_ipv6_mapped(), addr4.port(), 0, 0);
    let addr4_mapped = SockaddrIn6::from(addr4_mapped);
    let addr46_mapped = SocketAddrV4::new(Ipv4Addr::LOCALHOST, addr46.port());
    let addr46_mapped = SockaddrIn::from(addr46_mapped);
    let addr46_double_mapped =
        SocketAddrV6::new(Ipv4Addr::LOCALHOST.to_ipv6_mapped(), addr46.port(), 0, 0);
    let addr46_double_mapped = SockaddrIn6::from(addr46_double_mapped);
    let addr6_mapped = SocketAddrV4::new(Ipv4Addr::LOCALHOST, addr6.port());
    let addr6_mapped = SockaddrIn::from(addr6_mapped);
    let addr6_double_mapped =
        SocketAddrV6::new(Ipv4Addr::LOCALHOST.to_ipv6_mapped(), addr6.port(), 0, 0);
    let addr6_double_mapped = SockaddrIn6::from(addr6_double_mapped);

    assert_eq!(
        socket::sendto(sock4.as_raw_fd(), b"4to4", &addr4, MsgFlags::empty()),
        Ok(4)
    );
    assert_eq!(
        socket::sendto(
            sock4.as_raw_fd(),
            b"4to4m",
            &addr4_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::EAFNOSUPPORT)
    );
    assert_eq!(
        socket::sendto(sock4.as_raw_fd(), b"4to46", &addr46, MsgFlags::empty()),
        Err(Errno::EAFNOSUPPORT)
    );
    assert_eq!(
        socket::sendto(
            sock4.as_raw_fd(),
            b"4to46m",
            &addr46_mapped,
            MsgFlags::empty()
        ),
        Ok(6)
    );
    assert_eq!(
        socket::sendto(
            sock4.as_raw_fd(),
            b"4to46dm",
            &addr46_double_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::EAFNOSUPPORT)
    );
    assert_eq!(
        socket::sendto(sock4.as_raw_fd(), b"4to6", &addr6, MsgFlags::empty()),
        Err(Errno::EAFNOSUPPORT)
    );
    assert_eq!(
        socket::sendto(
            sock4.as_raw_fd(),
            b"4to6m",
            &addr6_mapped,
            MsgFlags::empty()
        ),
        Ok(5)
    );
    assert_eq!(
        socket::sendto(
            sock4.as_raw_fd(),
            b"4to6dm",
            &addr6_double_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::EAFNOSUPPORT)
    );

    assert_eq!(
        socket::sendto(sock46.as_raw_fd(), b"46to4", &addr4, MsgFlags::empty()),
        Err(Errno::ENETUNREACH)
    );
    assert_eq!(
        socket::sendto(
            sock46.as_raw_fd(),
            b"46to4m",
            &addr4_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::ENETUNREACH)
    );
    assert_eq!(
        socket::sendto(sock46.as_raw_fd(), b"46to46", &addr46, MsgFlags::empty()),
        Ok(6)
    );
    assert_eq!(
        socket::sendto(
            sock46.as_raw_fd(),
            b"46to46m",
            &addr46_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::ENETUNREACH)
    );
    assert_eq!(
        socket::sendto(
            sock46.as_raw_fd(),
            b"46to46dm",
            &addr46_double_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::ENETUNREACH)
    );
    assert_eq!(
        socket::sendto(sock46.as_raw_fd(), b"46to6", &addr6, MsgFlags::empty()),
        Ok(5)
    );
    assert_eq!(
        socket::sendto(
            sock46.as_raw_fd(),
            b"46to6m",
            &addr6_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::ENETUNREACH)
    );
    assert_eq!(
        socket::sendto(
            sock46.as_raw_fd(),
            b"46to6dm",
            &addr6_double_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::ENETUNREACH)
    );

    assert_eq!(
        socket::sendto(sock6.as_raw_fd(), b"6to4", &addr4, MsgFlags::empty()),
        Err(Errno::ENETUNREACH)
    );
    assert_eq!(
        socket::sendto(
            sock6.as_raw_fd(),
            b"6to4m",
            &addr4_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::ENETUNREACH)
    );
    assert_eq!(
        socket::sendto(sock6.as_raw_fd(), b"6to46", &addr46, MsgFlags::empty()),
        Ok(5)
    );
    assert_eq!(
        socket::sendto(
            sock6.as_raw_fd(),
            b"6to46m",
            &addr46_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::ENETUNREACH)
    );
    assert_eq!(
        socket::sendto(sock6.as_raw_fd(), b"6to6", &addr6, MsgFlags::empty()),
        Ok(4)
    );
    assert_eq!(
        socket::sendto(
            sock6.as_raw_fd(),
            b"6to6m",
            &addr6_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::ENETUNREACH)
    );

    let addrv4 = SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let addrv6 = SockaddrIn6::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));

    let mut buf = [0; 16];

    let (len, addr) = socket::recvfrom::<SockaddrIn>(sock4.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"4to4");
    assert_eq!(addr.unwrap(), addr4);

    assert_eq!(
        socket::recvfrom::<SockaddrIn>(sock4.as_raw_fd(), &mut buf),
        Err(Errno::EAGAIN)
    );

    let (len, addr) = socket::recvfrom::<SockaddrIn6>(sock46.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"46to46");
    assert_eq!(
        addr.unwrap(),
        SockaddrIn6::from(SocketAddrV6::new(addr46.ip(), addr46.port(), 0, 0))
    );

    let (len, addr) = socket::recvfrom::<SockaddrIn6>(sock46.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"6to46");
    assert_eq!(addr.unwrap(), addr6);

    assert_eq!(
        socket::recvfrom::<SockaddrIn>(sock46.as_raw_fd(), &mut buf),
        Err(Errno::EAGAIN)
    );

    let (len, addr) = socket::recvfrom::<SockaddrIn6>(sock6.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"46to6");
    assert_eq!(addr.unwrap(), addr46);

    let (len, addr) = socket::recvfrom::<SockaddrIn6>(sock6.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"6to6");
    assert_eq!(addr.unwrap(), addr6);

    assert_eq!(
        socket::recvfrom::<SockaddrIn>(sock6.as_raw_fd(), &mut buf),
        Err(Errno::EAGAIN)
    );
}

#[test]
fn udp_dual_stack_unspecified() {
    let bind_addrv4 = SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let bind_addrv6 = SockaddrIn6::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));

    let sock4 = socket::socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    assert_eq!(
        socket::bind(sock4.as_raw_fd(), &bind_addrv6),
        Err(Errno::EAFNOSUPPORT)
    );
    socket::bind(sock4.as_raw_fd(), &bind_addrv4).unwrap();

    let sock46 = socket::socket(
        AddressFamily::Inet6,
        SockType::Datagram,
        SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    assert_eq!(
        socket::bind(sock46.as_raw_fd(), &bind_addrv4),
        Err(Errno::EINVAL)
    );
    socket::bind(sock46.as_raw_fd(), &bind_addrv6).unwrap();

    let sock6 = socket::socket(
        AddressFamily::Inet6,
        SockType::Datagram,
        SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    socket::setsockopt(&sock6, Ipv6V6Only, &true).unwrap();
    assert_eq!(
        socket::bind(sock6.as_raw_fd(), &bind_addrv4),
        Err(Errno::EINVAL)
    );
    socket::bind(sock6.as_raw_fd(), &bind_addrv6).unwrap();

    let addr4 = socket::getsockname::<SockaddrIn>(sock4.as_raw_fd()).unwrap();
    let addr46 = socket::getsockname::<SockaddrIn6>(sock46.as_raw_fd()).unwrap();
    let addr6 = socket::getsockname::<SockaddrIn6>(sock6.as_raw_fd()).unwrap();

    assert_eq!(addr4.ip(), Ipv4Addr::UNSPECIFIED);
    assert_eq!(addr46.ip(), Ipv6Addr::UNSPECIFIED);
    assert_eq!(addr6.ip(), Ipv6Addr::UNSPECIFIED);

    assert_ne!(addr4.port(), addr46.port());
    assert_ne!(addr6.port(), addr46.port());

    let mut addr4 = SocketAddrV4::from(addr4);
    addr4.set_ip(Ipv4Addr::LOCALHOST);
    let addr4 = SockaddrIn::from(addr4);

    let mut addr46 = SocketAddrV6::from(addr46);
    addr46.set_ip(Ipv6Addr::LOCALHOST);
    let addr46 = SockaddrIn6::from(addr46);

    let mut addr6 = SocketAddrV6::from(addr6);
    addr6.set_ip(Ipv6Addr::LOCALHOST);
    let addr6 = SockaddrIn6::from(addr6);

    let addr4_mapped = SocketAddrV6::new(addr4.ip().to_ipv6_mapped(), addr4.port(), 0, 0);
    let addr4_mapped = SockaddrIn6::from(addr4_mapped);
    let addr46_mapped = SocketAddrV4::new(Ipv4Addr::LOCALHOST, addr46.port());
    let addr46_mapped = SockaddrIn::from(addr46_mapped);
    let addr46_double_mapped =
        SocketAddrV6::new(Ipv4Addr::LOCALHOST.to_ipv6_mapped(), addr46.port(), 0, 0);
    let addr46_double_mapped = SockaddrIn6::from(addr46_double_mapped);
    let addr6_mapped = SocketAddrV4::new(Ipv4Addr::LOCALHOST, addr6.port());
    let addr6_mapped = SockaddrIn::from(addr6_mapped);
    let addr6_double_mapped =
        SocketAddrV6::new(Ipv4Addr::LOCALHOST.to_ipv6_mapped(), addr6.port(), 0, 0);
    let addr6_double_mapped = SockaddrIn6::from(addr6_double_mapped);

    assert_eq!(
        socket::sendto(sock4.as_raw_fd(), b"4to4", &addr4, MsgFlags::empty()),
        Ok(4)
    );
    assert_eq!(
        socket::sendto(
            sock4.as_raw_fd(),
            b"4to4m",
            &addr4_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::EAFNOSUPPORT)
    );
    assert_eq!(
        socket::sendto(sock4.as_raw_fd(), b"4to46", &addr46, MsgFlags::empty()),
        Err(Errno::EAFNOSUPPORT)
    );
    assert_eq!(
        socket::sendto(
            sock4.as_raw_fd(),
            b"4to46m",
            &addr46_mapped,
            MsgFlags::empty()
        ),
        Ok(6)
    );
    assert_eq!(
        socket::sendto(
            sock4.as_raw_fd(),
            b"4to46dm",
            &addr46_double_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::EAFNOSUPPORT)
    );
    assert_eq!(
        socket::sendto(sock4.as_raw_fd(), b"4to6", &addr6, MsgFlags::empty()),
        Err(Errno::EAFNOSUPPORT)
    );
    assert_eq!(
        socket::sendto(
            sock4.as_raw_fd(),
            b"4to6m",
            &addr6_mapped,
            MsgFlags::empty()
        ),
        Ok(5)
    );
    assert_eq!(
        socket::sendto(
            sock4.as_raw_fd(),
            b"4to6dm",
            &addr6_double_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::EAFNOSUPPORT)
    );

    assert_eq!(
        socket::sendto(sock46.as_raw_fd(), b"46to4", &addr4, MsgFlags::empty()),
        Ok(5)
    );
    assert_eq!(
        socket::sendto(
            sock46.as_raw_fd(),
            b"46to4m",
            &addr4_mapped,
            MsgFlags::empty()
        ),
        Ok(6)
    );
    assert_eq!(
        socket::sendto(sock46.as_raw_fd(), b"46to46", &addr46, MsgFlags::empty()),
        Ok(6)
    );
    assert_eq!(
        socket::sendto(
            sock46.as_raw_fd(),
            b"46to46m",
            &addr46_mapped,
            MsgFlags::empty()
        ),
        Ok(7)
    );
    assert_eq!(
        socket::sendto(
            sock46.as_raw_fd(),
            b"46to46dm",
            &addr46_double_mapped,
            MsgFlags::empty()
        ),
        Ok(8)
    );
    assert_eq!(
        socket::sendto(sock46.as_raw_fd(), b"46to6", &addr6, MsgFlags::empty()),
        Ok(5)
    );
    assert_eq!(
        socket::sendto(
            sock46.as_raw_fd(),
            b"46to6m",
            &addr6_mapped,
            MsgFlags::empty()
        ),
        Ok(6)
    );
    assert_eq!(
        socket::sendto(
            sock46.as_raw_fd(),
            b"46to6dm",
            &addr6_double_mapped,
            MsgFlags::empty()
        ),
        Ok(7)
    );

    assert_eq!(
        socket::sendto(sock6.as_raw_fd(), b"6to4", &addr4, MsgFlags::empty()),
        Err(Errno::ENETUNREACH)
    );
    assert_eq!(
        socket::sendto(
            sock6.as_raw_fd(),
            b"6to4m",
            &addr4_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::ENETUNREACH)
    );
    assert_eq!(
        socket::sendto(sock6.as_raw_fd(), b"6to46", &addr46, MsgFlags::empty()),
        Ok(5)
    );
    assert_eq!(
        socket::sendto(
            sock6.as_raw_fd(),
            b"6to46m",
            &addr46_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::ENETUNREACH)
    );
    assert_eq!(
        socket::sendto(sock6.as_raw_fd(), b"6to6", &addr6, MsgFlags::empty()),
        Ok(4)
    );
    assert_eq!(
        socket::sendto(
            sock6.as_raw_fd(),
            b"6to6m",
            &addr6_mapped,
            MsgFlags::empty()
        ),
        Err(Errno::ENETUNREACH)
    );

    let addrv4 = SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let addrv6 = SockaddrIn6::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));

    let mut buf = [0; 16];

    let (len, addr) = socket::recvfrom::<SockaddrIn>(sock4.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"4to4");
    assert_eq!(addr.unwrap(), addr4);

    let (len, addr) = socket::recvfrom::<SockaddrIn>(sock4.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"46to4");
    assert_eq!(addr.unwrap(), addr46_mapped);

    let (len, addr) = socket::recvfrom::<SockaddrIn>(sock4.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"46to4m");
    assert_eq!(addr.unwrap(), addr46_mapped);

    assert_eq!(
        socket::recvfrom::<SockaddrIn>(sock4.as_raw_fd(), &mut buf),
        Err(Errno::EAGAIN)
    );

    let (len, addr) = socket::recvfrom::<SockaddrIn6>(sock46.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"4to46m");
    assert_eq!(addr.unwrap(), addr4_mapped);

    let (len, addr) = socket::recvfrom::<SockaddrIn6>(sock46.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"46to46");
    assert_eq!(addr.unwrap(), addr46);

    let (len, addr) = socket::recvfrom::<SockaddrIn6>(sock46.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"46to46m");
    assert_eq!(addr.unwrap(), addr46_double_mapped);

    let (len, addr) = socket::recvfrom::<SockaddrIn6>(sock46.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"46to46dm");
    assert_eq!(addr.unwrap(), addr46_double_mapped);

    let (len, addr) = socket::recvfrom::<SockaddrIn6>(sock46.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"6to46");
    assert_eq!(addr.unwrap(), addr6);

    assert_eq!(
        socket::recvfrom::<SockaddrIn>(sock46.as_raw_fd(), &mut buf),
        Err(Errno::EAGAIN)
    );

    let (len, addr) = socket::recvfrom::<SockaddrIn6>(sock6.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"46to6");
    assert_eq!(addr.unwrap(), addr46);

    let (len, addr) = socket::recvfrom::<SockaddrIn6>(sock6.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(buf[..len], *b"6to6");
    assert_eq!(addr.unwrap(), addr6);

    assert_eq!(
        socket::recvfrom::<SockaddrIn>(sock6.as_raw_fd(), &mut buf),
        Err(Errno::EAGAIN)
    );
}

#[test]
fn udp_bind() {
    let ips = [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];

    let mut port = 50000;
    for ip_a in ips {
        for reuse_addr_a in [false, true] {
            let v6only_values: &[Option<bool>] = if ip_a.is_ipv6() {
                &[Some(false), Some(true)]
            } else {
                &[None]
            };
            for v6only_a in v6only_values {
                for ip_b in ips {
                    for reuse_addr_b in [false, true] {
                        let v6only_values: &[Option<bool>] = if ip_b.is_ipv6() {
                            &[Some(false), Some(true)]
                        } else {
                            &[None]
                        };
                        for v6only_b in v6only_values {
                            let domain_a = match ip_a {
                                IpAddr::V4(_) => AddressFamily::Inet,
                                IpAddr::V6(_) => AddressFamily::Inet6,
                            };
                            let sock_a = socket::socket(
                                domain_a,
                                SockType::Datagram,
                                SockFlag::empty(),
                                None,
                            )
                            .unwrap();
                            socket::setsockopt(&sock_a, ReuseAddr, &reuse_addr_a).unwrap();
                            if let Some(v6only_a) = v6only_a {
                                socket::setsockopt(&sock_a, Ipv6V6Only, v6only_a).unwrap();
                            }

                            let domain_b = match ip_b {
                                IpAddr::V4(_) => AddressFamily::Inet,
                                IpAddr::V6(_) => AddressFamily::Inet6,
                            };
                            let sock_b = socket::socket(
                                domain_b,
                                SockType::Datagram,
                                SockFlag::empty(),
                                None,
                            )
                            .unwrap();
                            socket::setsockopt(&sock_b, ReuseAddr, &reuse_addr_b).unwrap();
                            if let Some(v6only_b) = v6only_b {
                                socket::setsockopt(&sock_b, Ipv6V6Only, v6only_b).unwrap();
                            }

                            port += 1;
                            let port = match ip_a {
                                IpAddr::V4(addr) => {
                                    socket::bind(
                                        sock_a.as_raw_fd(),
                                        &SockaddrIn::from(SocketAddrV4::new(addr, port)),
                                    )
                                    .unwrap();
                                    let addr =
                                        socket::getsockname::<SockaddrIn>(sock_a.as_raw_fd())
                                            .unwrap();
                                    addr.port()
                                }
                                IpAddr::V6(addr) => {
                                    socket::bind(
                                        sock_a.as_raw_fd(),
                                        &SockaddrIn6::from(SocketAddrV6::new(addr, port, 0, 0)),
                                    )
                                    .unwrap();
                                    let addr =
                                        socket::getsockname::<SockaddrIn6>(sock_a.as_raw_fd())
                                            .unwrap();
                                    addr.port()
                                }
                            };

                            let res = match ip_b {
                                IpAddr::V4(addr) => socket::bind(
                                    sock_b.as_raw_fd(),
                                    &SockaddrIn::from(SocketAddrV4::new(addr, port)),
                                ),
                                IpAddr::V6(addr) => socket::bind(
                                    sock_b.as_raw_fd(),
                                    &SockaddrIn6::from(SocketAddrV6::new(addr, port, 0, 0)),
                                ),
                            };

                            println!("---------------------------------------");
                            println!(
                                "Bound socket A to         {ip_a}:{port} with reuse_addr={reuse_addr_a} and v6only={v6only_a:?}"
                            );
                            println!(
                                "Tried to bind socket B to {ip_b}:{port} with reuse_addr={reuse_addr_b} and v6only={v6only_b:?} => res={res:?}"
                            );

                            let expect_success = (reuse_addr_a && reuse_addr_b)
                                || (!ip_a.is_unspecified()
                                    && !ip_b.is_unspecified()
                                    && ip_a != ip_b)
                                || (ip_a.is_ipv4() && ip_b.is_ipv6() && v6only_b.unwrap())
                                || (ip_a.is_ipv6() && ip_b.is_ipv4() && v6only_a.unwrap())
                                || (ip_a.is_ipv4()
                                    && ip_b.is_ipv6()
                                    && ip_a.is_unspecified()
                                    && !ip_b.is_unspecified())
                                || (ip_a.is_ipv6()
                                    && ip_b.is_ipv4()
                                    && !ip_a.is_unspecified()
                                    && ip_b.is_unspecified());

                            if expect_success {
                                assert_eq!(res, Ok(()));
                            } else {
                                assert_eq!(res, Err(Errno::EADDRINUSE));
                            }
                        }
                    }
                }
            }
        }
    }
}
