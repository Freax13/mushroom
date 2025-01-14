use std::{
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
    sync::atomic::{AtomicU16, Ordering},
};

use nix::{
    sys::socket::{
        self, getpeername, getsockname, setsockopt,
        sockopt::{ReuseAddr, ReusePort},
        AddressFamily, Backlog, SockFlag, SockType, SockaddrIn,
    },
    unistd::close,
    Result,
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
        println!("Binding socket A to {ip_a}:{port} with reuse_addr={reuse_addr_a} and reuse_port={reuse_port_a}");
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
        println!("Binding socket B to {ip_b}:{port} with reuse_addr={reuse_addr_b} and reuse_port={reuse_port_b}");
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
