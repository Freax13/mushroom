use std::{
    net::Ipv4Addr,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicU16, Ordering},
};

use nix::{
    Result,
    errno::Errno,
    libc::{Ioctl, ioctl},
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::socket::{
        self, AddressFamily, Backlog, MsgFlags, SockFlag, SockType, SockaddrIn, getpeername,
        getsockname, setsockopt, shutdown,
        sockopt::{ReuseAddr, ReusePort},
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
