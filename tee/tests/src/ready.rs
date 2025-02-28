use std::{fs::File, os::fd::AsFd, slice::from_mut};

use nix::{
    poll::{PollFd, PollFlags, PollTimeout, poll},
    unistd::unlink,
};

#[test]
fn poll_file() {
    let path = "poll-file";
    let file = File::create(path).unwrap();

    let mut fd = PollFd::new(file.as_fd(), PollFlags::POLLIN | PollFlags::POLLOUT);
    assert_eq!(poll(from_mut(&mut fd), PollTimeout::ZERO), Ok(1));
    assert_eq!(fd.revents(), Some(PollFlags::POLLIN | PollFlags::POLLOUT));

    unlink(path).unwrap();
}
