use std::{
    net::{Ipv4Addr, SocketAddrV4},
    os::fd::AsRawFd,
};

use nix::{
    errno::Errno,
    sys::socket::{
        AddressFamily, IpMembershipRequest, MsgFlags, SockFlag, SockProtocol, SockType, SockaddrIn,
        bind, getsockname, recvfrom, sendto, setsockopt, socket,
        sockopt::{IpAddMembership, ReusePort},
    },
};

#[test]
fn bind_multicast() {
    let a = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::Udp,
    )
    .unwrap();

    bind(a.as_raw_fd(), &SockaddrIn::new(239, 255, 255, 250, 1990)).unwrap();
}

#[test]
fn bind_multicast_twice() {
    let a = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::Udp,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::Udp,
    )
    .unwrap();

    let addr = SockaddrIn::new(239, 0, 255, 1, 1990);
    assert_eq!(bind(a.as_raw_fd(), &addr), Ok(()));
    // Binding a second time fails (just like with regular addresses).
    assert_eq!(bind(b.as_raw_fd(), &addr), Err(Errno::EADDRINUSE));
}

#[test]
fn join_group() {
    let a = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::Udp,
    )
    .unwrap();

    assert_eq!(
        setsockopt(
            &a,
            IpAddMembership,
            &IpMembershipRequest::new(Ipv4Addr::new(239, 0, 255, 2), None),
        ),
        Ok(())
    );
}

#[test]
fn join_invalid_normal() {
    let a = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::Udp,
    )
    .unwrap();

    assert_eq!(
        setsockopt(
            &a,
            IpAddMembership,
            &IpMembershipRequest::new(Ipv4Addr::new(1, 1, 1, 1), None),
        ),
        Err(Errno::EINVAL)
    );
}

#[test]
fn join_invalid_localhost() {
    let a = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::Udp,
    )
    .unwrap();

    assert_eq!(
        setsockopt(
            &a,
            IpAddMembership,
            &IpMembershipRequest::new(Ipv4Addr::LOCALHOST, None),
        ),
        Err(Errno::EINVAL)
    );
}

#[test]
fn join_group_twice() {
    let a = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::Udp,
    )
    .unwrap();

    assert_eq!(
        setsockopt(
            &a,
            IpAddMembership,
            &IpMembershipRequest::new(Ipv4Addr::new(239, 0, 255, 3), None),
        ),
        Ok(())
    );
    assert_eq!(
        setsockopt(
            &a,
            IpAddMembership,
            &IpMembershipRequest::new(Ipv4Addr::new(239, 0, 255, 3), None),
        ),
        Err(Errno::EADDRINUSE)
    );
}

#[test]
fn join_group_with_two_sockets() {
    let a = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::Udp,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::Udp,
    )
    .unwrap();

    setsockopt(&a, ReusePort, &true).unwrap();
    setsockopt(&b, ReusePort, &true).unwrap();

    bind(a.as_raw_fd(), &SockaddrIn::new(0, 0, 0, 0, 0)).unwrap();
    let addr_a = getsockname::<SockaddrIn>(a.as_raw_fd()).unwrap();
    bind(b.as_raw_fd(), &SockaddrIn::new(0, 0, 0, 0, addr_a.port())).unwrap();

    let group = Ipv4Addr::new(239, 0, 255, 4);
    assert_eq!(
        setsockopt(&a, IpAddMembership, &IpMembershipRequest::new(group, None),),
        Ok(())
    );

    assert_eq!(
        setsockopt(&b, IpAddMembership, &IpMembershipRequest::new(group, None),),
        Ok(())
    );
}

#[test]
fn join_recv() {
    let a = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::Udp,
    )
    .unwrap();
    let b = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::Udp,
    )
    .unwrap();

    let group = Ipv4Addr::new(239, 0, 255, 4);
    setsockopt(&a, IpAddMembership, &IpMembershipRequest::new(group, None)).unwrap();

    bind(a.as_raw_fd(), &SockaddrIn::new(0, 0, 0, 0, 0)).unwrap();
    let addr_a = getsockname::<SockaddrIn>(a.as_raw_fd()).unwrap();

    let destination = SockaddrIn::from(SocketAddrV4::new(group, addr_a.port()));
    sendto(b.as_raw_fd(), b"1234", &destination, MsgFlags::empty()).unwrap();
    let addr_b = getsockname::<SockaddrIn>(b.as_raw_fd()).unwrap();

    let mut buf = [0; 16];
    let (n, src) = recvfrom::<SockaddrIn>(a.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(buf[..4], *b"1234");
    assert_eq!(src.unwrap().port(), addr_b.port());
}
