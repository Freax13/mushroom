#![cfg(false)]

use nix::libc::{SEM_INFO, semctl, seminfo};

#[test]
fn info() {
    let mut sem_info = seminfo {
        semmap: 0,
        semmni: 0,
        semmns: 0,
        semmnu: 0,
        semmsl: 0,
        semopm: 0,
        semume: 0,
        semusz: 0,
        semvmx: 0,
        semaem: 0,
    };
    let res = unsafe { semctl(0, 0, SEM_INFO, &mut sem_info) };
    assert_eq!(res, 0);
}
