use std::{
    io::{IoSlice, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    time::Duration,
};

use nix::{
    Result,
    errno::Errno,
    fcntl::{FcntlArg, OFlag, fcntl},
    libc::{Ioctl, in_addr, in_pktinfo, ioctl, linger},
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::socket::{
        self, AddressFamily, Backlog, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag,
        SockProtocol, SockType, SockaddrIn, SockaddrIn6, SockaddrLike, SockaddrStorage, accept,
        connect, getpeername, getsockname, listen, recv, recvmsg, send, sendmsg, setsockopt,
        shutdown, socket,
        sockopt::{Ipv4PacketInfo, Ipv6RecvPacketInfo, Ipv6V6Only, Linger, ReuseAddr, ReusePort},
    },
    unistd::close,
};

mod multicast;

fn bind(
    addr: IpAddr,
    port: u16,
    reuse_addr: bool,
    reuse_port: bool,
    v6only: Option<bool>,
) -> Result<OwnedFd> {
    let addr = SockaddrStorage::from(SocketAddr::new(addr, port));
    let sock = socket::socket(
        addr.family().unwrap(),
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .unwrap();
    setsockopt(&sock, ReuseAddr, &reuse_addr).unwrap();
    setsockopt(&sock, ReusePort, &reuse_port).unwrap();
    if let Some(v6only) = v6only {
        setsockopt(&sock, Ipv6V6Only, &v6only).unwrap();
    }
    setsockopt(
        &sock,
        Linger,
        &linger {
            l_onoff: 1,
            l_linger: 1,
        },
    )
    .unwrap();
    socket::bind(sock.as_raw_fd(), &addr)?;

    Ok(sock)
}

fn get_port() -> u16 {
    let socket = socket(
        AddressFamily::Inet6,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .unwrap();
    setsockopt(
        &socket,
        Linger,
        &linger {
            l_onoff: 1,
            l_linger: 0,
        },
    )
    .unwrap();
    socket::bind(
        socket.as_raw_fd(),
        &SockaddrIn6::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    )
    .unwrap();
    getsockname::<SockaddrIn6>(socket.as_raw_fd())
        .unwrap()
        .port()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketAOp {
    ListenEarly,
    ListenLate,
    ConnectEarly(IpAddr),
    ConnectLate(IpAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketBOp {
    Listen,
    Connect(IpAddr),
}

const TEST_IPS: [IpAddr; 5] = [
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
    IpAddr::V6(Ipv6Addr::UNSPECIFIED),
];
const SOCKET_A_OPS: [Option<SocketAOp>; 13] = [
    None,
    Some(SocketAOp::ListenEarly),
    Some(SocketAOp::ListenLate),
    Some(SocketAOp::ConnectEarly(IpAddr::V4(Ipv4Addr::new(
        127, 0, 0, 1,
    )))),
    Some(SocketAOp::ConnectEarly(IpAddr::V4(Ipv4Addr::new(
        127, 0, 0, 2,
    )))),
    Some(SocketAOp::ConnectEarly(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
    Some(SocketAOp::ConnectEarly(IpAddr::V6(Ipv6Addr::LOCALHOST))),
    Some(SocketAOp::ConnectEarly(IpAddr::V6(Ipv6Addr::UNSPECIFIED))),
    Some(SocketAOp::ConnectLate(IpAddr::V4(Ipv4Addr::new(
        127, 0, 0, 1,
    )))),
    Some(SocketAOp::ConnectLate(IpAddr::V4(Ipv4Addr::new(
        127, 0, 0, 2,
    )))),
    Some(SocketAOp::ConnectLate(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
    Some(SocketAOp::ConnectLate(IpAddr::V6(Ipv6Addr::LOCALHOST))),
    Some(SocketAOp::ConnectLate(IpAddr::V6(Ipv6Addr::UNSPECIFIED))),
];
const SOCKET_B_OPS: [SocketBOp; 6] = [
    SocketBOp::Listen,
    SocketBOp::Connect(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
    SocketBOp::Connect(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
    SocketBOp::Connect(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    SocketBOp::Connect(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    SocketBOp::Connect(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
];

#[test]
fn test_bind() {
    // Create a socket that we can connect to.
    let connect_port = get_port();
    let sock = bind(
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        connect_port,
        false,
        false,
        Some(false),
    )
    .unwrap();
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
        for ip_b in TEST_IPS {
            for reuse_addr_a in [false, true] {
                for reuse_addr_b in [false, true] {
                    for reuse_port_a in [false, true] {
                        for reuse_port_b in [false, true] {
                            let v6only_options_a = if ip_a.is_ipv6() {
                                &[Some(false), Some(true)] as &[_]
                            } else {
                                &[None]
                            };
                            for v6only_a in v6only_options_a.iter().copied() {
                                let v6only_options_b = if ip_b.is_ipv6() {
                                    &[Some(false), Some(true)] as &[_]
                                } else {
                                    &[None]
                                };
                                for v6only_b in v6only_options_b.iter().copied() {
                                    for socket_a_op in SOCKET_A_OPS {
                                        for socket_b_op in SOCKET_B_OPS {
                                            counter += 1;
                                            println!("---------------------------------------");
                                            println!("test case {counter}");
                                            test_case(
                                                connect_port,
                                                ip_a,
                                                ip_b,
                                                reuse_addr_a,
                                                reuse_port_a,
                                                reuse_addr_b,
                                                reuse_port_b,
                                                v6only_a,
                                                v6only_b,
                                                socket_a_op,
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
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn test_case(
        connect_port: u16,
        mut ip_a: IpAddr,
        ip_b: IpAddr,
        reuse_addr_a: bool,
        reuse_port_a: bool,
        reuse_addr_b: bool,
        reuse_port_b: bool,
        v6only_a: Option<bool>,
        v6only_b: Option<bool>,
        socket_a_op: Option<SocketAOp>,
        socket_b_op: SocketBOp,
    ) {
        let port = get_port();

        let reuse_port_both = reuse_port_a && reuse_port_b;

        // Bind the first socket.
        println!(
            "Binding socket A to {ip_a}:{port} with reuse_addr={reuse_addr_a}, reuse_port={reuse_port_a}, and v6only={v6only_a:?}"
        );
        let a = bind(ip_a, port, reuse_addr_a, reuse_port_a, v6only_a).unwrap();
        let bound_ip_a = ip_a;

        // Optionally make the first socket into a passive socket before binding
        // the other socket.
        if socket_a_op == Some(SocketAOp::ListenEarly) {
            println!("Starting to listen on socket A (early)");
            socket::listen(&a, Backlog::MAXALLOWABLE).unwrap();
        }
        // Optionally make the first socket into an active socket before binding
        // the other socket.
        if let Some(SocketAOp::ConnectEarly(ip)) = socket_a_op {
            println!("Connecting socket A to {ip}:{connect_port} (early)");
            let res = socket::connect(
                a.as_raw_fd(),
                &SockaddrStorage::from(SocketAddr::new(ip, connect_port)),
            );
            let expect_success = ip_a.is_ipv4() == ip.is_ipv4();
            assert_eq!(res.is_ok(), expect_success);

            // Stop the test if connecting failed.
            let Ok(()) = res else {
                return;
            };

            // Connecting the socket might have changed its ip, so update the IP.
            let sockname = getsockname::<SockaddrStorage>(a.as_raw_fd()).unwrap();
            let sockname = if let Some(sockname) = sockname.as_sockaddr_in() {
                IpAddr::V4(sockname.ip())
            } else {
                let sockname = sockname.as_sockaddr_in6().unwrap();
                IpAddr::V6(sockname.ip())
            };
            if ip_a.is_unspecified() {
                match sockname {
                    IpAddr::V4(sockname) => assert_eq!(sockname, Ipv4Addr::LOCALHOST),
                    IpAddr::V6(sockname) => assert_eq!(sockname, Ipv6Addr::LOCALHOST),
                }
            } else {
                assert_eq!(sockname, ip_a);
            }
            ip_a = sockname;

            // Check the IP of the peer.
            let peername = getpeername::<SockaddrStorage>(a.as_raw_fd()).unwrap();
            let peername = if let Some(peername) = peername.as_sockaddr_in() {
                IpAddr::V4(peername.ip())
            } else {
                let peername = peername.as_sockaddr_in6().unwrap();
                IpAddr::V6(peername.ip())
            };
            if !ip.is_unspecified() {
                assert_eq!(peername, ip);
            } else {
                assert_eq!(peername, ip_a);
            }
            println!("sockname is {sockname:?}, peername is {peername:?}");
        }

        let non_overlapping_ip = (!ip_a.is_unspecified() && !ip_b.is_unspecified() && ip_a != ip_b)
            || (ip_a.is_ipv4() && ip_b.is_ipv6() && (!ip_b.is_unspecified() || v6only_b.unwrap()))
            || (ip_a.is_ipv6()
                && ip_b.is_ipv4()
                && (!bound_ip_a.is_unspecified() || v6only_a.unwrap() || !ip_b.is_unspecified())
                && (!ip_a.is_unspecified() || v6only_a.unwrap()));

        // Make sure that binding works when we expect it to.
        let bind_expect_success = non_overlapping_ip
            || (socket_a_op != Some(SocketAOp::ListenEarly) && reuse_addr_a && reuse_addr_b)
            || reuse_port_both;
        println!(
            "Binding socket B to {ip_b}:{port} with reuse_addr={reuse_addr_b}, reuse_port={reuse_port_b}, and v6only={v6only_b:?}"
        );
        let res = bind(ip_b, port, reuse_addr_b, reuse_port_b, v6only_b);
        assert_eq!(res.is_ok(), bind_expect_success);

        // Stop the test if binding failed.
        let Ok(b) = res else {
            return;
        };

        // Optionally make the first socket into a passive socket after binding the
        // the other socket.
        if socket_a_op == Some(SocketAOp::ListenLate) {
            println!("Starting to listen on socket A (late)");
            socket::listen(&a, Backlog::MAXALLOWABLE).unwrap();
        }
        // Optionally make the first socket into an active socket after binding the
        // other socket.
        if let Some(SocketAOp::ConnectLate(ip)) = socket_a_op {
            println!("Connecting socket A to {ip}:{connect_port} (late)");
            let res = socket::connect(
                a.as_raw_fd(),
                &SockaddrStorage::from(SocketAddr::new(ip, connect_port)),
            );

            let expect_success = ip_a.is_ipv4() == ip.is_ipv4();
            assert_eq!(res.is_ok(), expect_success);

            // Stop the test if connecting failed.
            let Ok(()) = res else {
                return;
            };

            // Connecting the socket might have changed its ip, so update the IP.
            let sockname = getsockname::<SockaddrStorage>(a.as_raw_fd()).unwrap();
            let sockname = if let Some(sockname) = sockname.as_sockaddr_in() {
                IpAddr::V4(sockname.ip())
            } else {
                let sockname = sockname.as_sockaddr_in6().unwrap();
                IpAddr::V6(sockname.ip())
            };
            if ip_a.is_unspecified() {
                match sockname {
                    IpAddr::V4(sockname) => assert_eq!(sockname, Ipv4Addr::LOCALHOST),
                    IpAddr::V6(sockname) => assert_eq!(sockname, Ipv6Addr::LOCALHOST),
                }
            } else {
                assert_eq!(sockname, ip_a);
            }
            ip_a = sockname;

            // Check the IP of the peer.
            let peername = getpeername::<SockaddrStorage>(a.as_raw_fd()).unwrap();
            let peername = if let Some(peername) = peername.as_sockaddr_in() {
                IpAddr::V4(peername.ip())
            } else {
                let peername = peername.as_sockaddr_in6().unwrap();
                IpAddr::V6(peername.ip())
            };
            if !ip.is_unspecified() {
                assert_eq!(peername, ip);
            } else {
                assert_eq!(peername, ip_a);
            }
            println!("sockname is {sockname:?}, peername is {peername:?}");
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
            }
            SocketBOp::Connect(ip_dest_b) => {
                // Make sure that connecting works when we expect it to.
                let connect_b_expect_success = ip_b.is_ipv6() == ip_dest_b.is_ipv6()
                    && socket_a_op.is_none_or(|op| {
                        match op {
                            SocketAOp::ListenEarly | SocketAOp::ListenLate => true,
                            SocketAOp::ConnectEarly(ip_dest_a)
                            | SocketAOp::ConnectLate(ip_dest_a) => {
                                // Connecting the ip might update the IP, so factor that in
                                // when predicting whether connecting should fail.
                                let ip_b = if ip_b.is_unspecified() {
                                    match ip_b {
                                        IpAddr::V4(..) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                                        IpAddr::V6(..) => IpAddr::V6(Ipv6Addr::LOCALHOST),
                                    }
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
                    &SockaddrStorage::from(SocketAddr::new(ip_dest_b, connect_port)),
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

#[test]
fn udp_pktinfo() {
    let addrs = [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    for src in addrs {
        let v6only_values: &[Option<bool>] = if src.is_ipv6() {
            &[Some(false), Some(true)]
        } else {
            &[None]
        };
        for src_v6only in v6only_values {
            let src_family = match src {
                IpAddr::V4(_) => AddressFamily::Inet,
                IpAddr::V6(_) => AddressFamily::Inet6,
            };
            let sender = socket::socket(
                src_family,
                SockType::Datagram,
                SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
                SockProtocol::Udp,
            )
            .unwrap();
            if let Some(v6only) = src_v6only {
                setsockopt(&sender, Ipv6V6Only, v6only).unwrap();
            }
            let src_storage = SockaddrStorage::from(SocketAddr::new(src, 0));
            socket::bind(sender.as_raw_fd(), &src_storage).unwrap();

            for dst in addrs {
                let v6only_values: &[Option<bool>] = if dst.is_ipv6() {
                    &[Some(false), Some(true)]
                } else {
                    &[None]
                };
                for dst_v6only in v6only_values {
                    dbg!((src, src_v6only, dst, dst_v6only));

                    let dst_family = match dst {
                        IpAddr::V4(_) => AddressFamily::Inet,
                        IpAddr::V6(_) => AddressFamily::Inet6,
                    };
                    let receiver = socket::socket(
                        dst_family,
                        SockType::Datagram,
                        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
                        SockProtocol::Udp,
                    )
                    .unwrap();
                    if let Some(v6only) = dst_v6only {
                        setsockopt(&receiver, Ipv6V6Only, v6only).unwrap();
                    }
                    setsockopt(&receiver, Ipv4PacketInfo, &true).unwrap();
                    if dst.is_ipv6() {
                        setsockopt(&receiver, Ipv6RecvPacketInfo, &true).unwrap();
                    }
                    let dst_storage = SockaddrStorage::from(SocketAddr::new(dst, 0));
                    socket::bind(receiver.as_raw_fd(), &dst_storage).unwrap();
                    let dst_addr = getsockname::<SockaddrStorage>(receiver.as_raw_fd()).unwrap();

                    let res = sendmsg(
                        sender.as_raw_fd(),
                        &[IoSlice::new(b"foo")],
                        &[],
                        MsgFlags::empty(),
                        Some(&dst_addr),
                    );
                    if res.is_err() {
                        continue;
                    }

                    let mut buf = [0; 4];
                    let mut ioslice = IoSliceMut::new(&mut buf);
                    let mut cmsg_buffer = [0; 64];
                    let res = recvmsg::<SockaddrStorage>(
                        receiver.as_raw_fd(),
                        core::slice::from_mut(&mut ioslice),
                        Some(&mut cmsg_buffer),
                        MsgFlags::empty(),
                    );
                    let received = res.is_ok();
                    if let Ok(msg) = res {
                        let mut cmsgs = msg.cmsgs().unwrap();
                        let cmsg = cmsgs.next().unwrap();
                        match cmsg {
                            ControlMessageOwned::Ipv4PacketInfo(pktinfo) => {
                                let IpAddr::V4(dst) = dst else {
                                    unreachable!();
                                };
                                let addr = if !dst.is_unspecified() {
                                    dst
                                } else {
                                    match src {
                                        IpAddr::V4(src) => {
                                            if !src.is_unspecified() {
                                                src
                                            } else {
                                                Ipv4Addr::LOCALHOST
                                            }
                                        }
                                        IpAddr::V6(_) => Ipv4Addr::LOCALHOST,
                                    }
                                };

                                assert_eq!(pktinfo.ipi_ifindex, 1);
                                let ipi_spec_dst =
                                    Ipv4Addr::from_bits(u32::from_be(pktinfo.ipi_spec_dst.s_addr));
                                let ipi_addr =
                                    Ipv4Addr::from_bits(u32::from_be(pktinfo.ipi_addr.s_addr));
                                assert_eq!(ipi_spec_dst, ipi_addr);
                                assert_eq!(ipi_spec_dst, addr);

                                let addr = match src {
                                    IpAddr::V4(src) => {
                                        if !src.is_unspecified() {
                                            src
                                        } else {
                                            Ipv4Addr::LOCALHOST
                                        }
                                    }
                                    IpAddr::V6(_) => Ipv4Addr::LOCALHOST,
                                };
                                assert_eq!(
                                    msg.address.unwrap().as_sockaddr_in().unwrap().ip(),
                                    addr
                                );
                            }
                            ControlMessageOwned::Ipv6PacketInfo(pktinfo) => {
                                assert_eq!(pktinfo.ipi6_ifindex, 1);
                                let ipi_spec_dst = Ipv6Addr::from_octets(pktinfo.ipi6_addr.s6_addr);
                                assert_eq!(ipi_spec_dst, Ipv6Addr::LOCALHOST);

                                assert_eq!(
                                    msg.address.unwrap().as_sockaddr_in6().unwrap().ip(),
                                    Ipv6Addr::LOCALHOST
                                );
                            }
                            _ => todo!(),
                        }
                        assert_eq!(cmsgs.next(), None);
                        assert_eq!(msg.bytes, 3);

                        assert_eq!(buf[..3], *b"foo");
                    }

                    let src_override = Ipv4Addr::new(127, 0, 0, 3);
                    let send_res = sendmsg(
                        sender.as_raw_fd(),
                        &[IoSlice::new(b"bar")],
                        &[ControlMessage::Ipv4PacketInfo(&in_pktinfo {
                            ipi_ifindex: 1,
                            ipi_spec_dst: in_addr {
                                s_addr: src_override.to_bits().to_be(),
                            },
                            ipi_addr: in_addr {
                                s_addr: src_override.to_bits().to_be(),
                            },
                        })],
                        MsgFlags::empty(),
                        Some(&dst_addr),
                    );
                    assert_eq!(send_res, Ok(3));
                    let mut buf = [0; 4];
                    let mut ioslice = IoSliceMut::new(&mut buf);
                    let mut cmsg_buffer = [0; 64];
                    let res = recvmsg::<SockaddrStorage>(
                        receiver.as_raw_fd(),
                        core::slice::from_mut(&mut ioslice),
                        Some(&mut cmsg_buffer),
                        MsgFlags::empty(),
                    );
                    assert_eq!(received, res.is_ok());
                    if let Ok(msg) = res {
                        let mut cmsgs = msg.cmsgs().unwrap();
                        let cmsg = cmsgs.next().unwrap();
                        match cmsg {
                            ControlMessageOwned::Ipv4PacketInfo(pktinfo) => {
                                let IpAddr::V4(dst) = dst else {
                                    unreachable!();
                                };
                                let addr = if !dst.is_unspecified() {
                                    dst
                                } else {
                                    src_override
                                };

                                assert_eq!(pktinfo.ipi_ifindex, 1);
                                let ipi_spec_dst =
                                    Ipv4Addr::from_bits(u32::from_be(pktinfo.ipi_spec_dst.s_addr));
                                let ipi_addr =
                                    Ipv4Addr::from_bits(u32::from_be(pktinfo.ipi_addr.s_addr));
                                assert_eq!(ipi_spec_dst, ipi_addr);
                                assert_eq!(ipi_spec_dst, addr);

                                assert_eq!(
                                    msg.address.unwrap().as_sockaddr_in().unwrap().ip(),
                                    src_override
                                );
                            }
                            ControlMessageOwned::Ipv6PacketInfo(pktinfo) => {
                                assert_eq!(pktinfo.ipi6_ifindex, 1);
                                let ipi_spec_dst = Ipv6Addr::from_octets(pktinfo.ipi6_addr.s6_addr);
                                assert_eq!(ipi_spec_dst, Ipv6Addr::LOCALHOST);

                                assert_eq!(
                                    msg.address.unwrap().as_sockaddr_in6().unwrap().ip(),
                                    Ipv6Addr::LOCALHOST
                                );
                            }
                            _ => todo!(),
                        }
                        assert_eq!(cmsgs.next(), None);
                        assert_eq!(msg.bytes, 3);
                        assert_eq!(buf[..3], *b"bar");
                    }

                    // ipi_addr is ignored.
                    let res = sendmsg(
                        sender.as_raw_fd(),
                        &[IoSlice::new(b"baz")],
                        &[ControlMessage::Ipv4PacketInfo(&in_pktinfo {
                            ipi_ifindex: 1,
                            ipi_spec_dst: in_addr {
                                s_addr: Ipv4Addr::LOCALHOST.to_bits().to_be(),
                            },
                            ipi_addr: in_addr {
                                s_addr: Ipv4Addr::new(1, 2, 3, 4).to_bits().to_be(),
                            },
                        })],
                        MsgFlags::empty(),
                        Some(&dst_addr),
                    );
                    assert_eq!(res, Ok(3));

                    // ipi_spec_dst is not ignored.
                    let res = sendmsg(
                        sender.as_raw_fd(),
                        &[IoSlice::new(b"baz")],
                        &[ControlMessage::Ipv4PacketInfo(&in_pktinfo {
                            ipi_ifindex: 1,
                            ipi_spec_dst: in_addr {
                                s_addr: Ipv4Addr::new(1, 1, 1, 1).to_bits().to_be(),
                            },
                            ipi_addr: in_addr {
                                s_addr: Ipv4Addr::LOCALHOST.to_bits().to_be(),
                            },
                        })],
                        MsgFlags::empty(),
                        Some(&dst_addr),
                    );
                    if src.is_ipv4() || dst.is_ipv4() {
                        assert_eq!(res, Err(Errno::ENETUNREACH));
                    } else {
                        assert_eq!(res, Ok(3));
                    }
                }
            }
        }
    }
}

fn tcp_socket_pair() -> (OwnedFd, OwnedFd) {
    let server = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        SockProtocol::Tcp,
    )
    .unwrap();
    let sock1 = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        SockProtocol::Tcp,
    )
    .unwrap();

    listen(&server, Backlog::MAXALLOWABLE).unwrap();
    let addr = getsockname::<SockaddrStorage>(server.as_raw_fd()).unwrap();
    connect(sock1.as_raw_fd(), &addr).unwrap();

    let sock2 = accept(server.as_raw_fd()).unwrap();
    let sock2 = unsafe { OwnedFd::from_raw_fd(sock2) };
    (sock1, sock2)
}

fn set_non_blocking<Fd: AsFd>(fd: Fd, non_blocking: bool) {
    let flags = fcntl(&fd, FcntlArg::F_GETFL).unwrap();
    let mut flags = OFlag::from_bits_truncate(flags);
    flags.set(OFlag::O_NONBLOCK, non_blocking);
    fcntl(&fd, FcntlArg::F_SETFL(flags)).unwrap();
}

/// WAITALL has no effect when used with non-blocking a socket.
#[test]
fn tcp_waitall_nonblock() {
    let (sock1, sock2) = tcp_socket_pair();
    set_non_blocking(&sock1, true);
    set_non_blocking(&sock2, true);

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
fn tcp_waitall_dontwait() {
    let (sock1, sock2) = tcp_socket_pair();

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
fn tcp_waitall() {
    let (sock1, sock2) = tcp_socket_pair();

    // Send the first half of the message.
    assert_eq!(
        send(sock1.as_raw_fd(), b"12345678", MsgFlags::empty()),
        Ok(8)
    );

    // Delay sending more bytes.
    std::thread::spawn(move || {
        // Wait for half a second.
        std::thread::sleep(Duration::from_millis(500));
        // Send the second half of the message.
        assert_eq!(
            send(sock1.as_raw_fd(), b"90abcdef", MsgFlags::empty()),
            Ok(8)
        );
    });

    // Make sure that all 16 bytes are received.
    let mut buf = [0; 16];
    assert_eq!(
        recv(sock2.as_raw_fd(), &mut buf, MsgFlags::MSG_WAITALL),
        Ok(16)
    );
}

/// WAITALL has no effect when used with DONTWAIT a socket.
#[test]
fn tcp_waitall_oob() {
    let (sock1, sock2) = tcp_socket_pair();

    // Send the first half of the message.
    assert_eq!(
        send(sock1.as_raw_fd(), b"12345678", MsgFlags::empty()),
        Ok(8)
    );

    // Send a OOB message.
    assert_eq!(send(sock1.as_raw_fd(), b"90ab", MsgFlags::MSG_OOB), Ok(4));

    // Make sure that all 12 bytes are received.
    let mut buf = [0; 16];
    assert_eq!(
        recv(sock2.as_raw_fd(), &mut buf, MsgFlags::MSG_WAITALL),
        Ok(11)
    );
}
