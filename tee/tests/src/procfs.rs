use std::fs::read_link;

use nix::unistd::{getpid, gettid};

#[test]
fn resolve_proc_self() {
    // Make sure the test is not running on the main thread.
    let pid = getpid();
    let tid = gettid();
    assert_ne!(pid, tid);

    let link = read_link("/proc/self").unwrap();
    assert_eq!(link, pid.to_string())
}
