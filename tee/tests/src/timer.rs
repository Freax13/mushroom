use std::mem::MaybeUninit;

use nix::{
    libc::{self, SI_TIMER, sigwaitinfo},
    sys::{
        signal::{SigEvent, SigSet, Signal},
        time::TimeSpec,
        timer::{Expiration, Timer, TimerSetTimeFlags},
    },
    time::ClockId,
    unistd::gettid,
};

#[test]
fn timer() {
    const SI_VALUE: libc::intptr_t = 0x11223344;

    let signal = Signal::SIGALRM;
    let set = SigSet::from(signal);

    set.thread_block().unwrap();

    let mut sigevent = unsafe { std::mem::zeroed::<libc::sigevent>() };
    sigevent.sigev_value = libc::sigval {
        sival_ptr: SI_VALUE as _,
    };
    sigevent.sigev_signo = signal as libc::c_int;
    sigevent.sigev_notify = 4; // SIGEV_THREAD_ID
    sigevent.sigev_notify_thread_id = gettid().as_raw();
    let sigevent = SigEvent::from(&sigevent);

    let mut timer = Timer::new(ClockId::CLOCK_REALTIME, sigevent).unwrap();

    timer
        .set(
            Expiration::OneShot(TimeSpec::new(0, 1_000_000)),
            TimerSetTimeFlags::empty(),
        )
        .unwrap();

    let mut info = MaybeUninit::uninit();
    let res = unsafe { sigwaitinfo(set.as_ref(), info.as_mut_ptr()) };
    assert_eq!(res, signal as libc::c_int);
    let info = unsafe { info.assume_init() };

    assert_eq!(info.si_code, SI_TIMER);

    let si_value = unsafe { info.si_value() };
    assert_eq!(si_value.sival_ptr as libc::intptr_t, SI_VALUE);
}
