use alloc::sync::{Arc, Weak};

use futures::{FutureExt, future::Fuse, select_biased};

use crate::{
    rt::{
        notify::{Notify, NotifyOnDrop},
        spawn,
    },
    spin::mutex::Mutex,
    time::{now, sleep_until},
    user::process::{
        Process,
        syscall::args::{ClockId, ITimerspec, SigEvent, SigEventData, Signal, TimerId, Timespec},
        thread::{SigFields, SigInfo, SigInfoCode, SigTimer},
    },
};

pub struct Timer {
    clock_id: ClockId,
    state: Arc<Mutex<TimerState>>,
    notify: NotifyOnDrop,
}

impl Timer {
    pub fn new(clock_id: ClockId, event: Event, process: Weak<Process>) -> Self {
        let state = Arc::new(Mutex::new(TimerState::Disarmed));
        let notify = Arc::new(Notify::new());

        spawn({
            let state = Arc::downgrade(&state);
            let notify = notify.clone();
            async move {
                while let Some(state) = state.upgrade() {
                    // Check the timer state.
                    let wait = notify.wait();
                    let mut guard = state.lock();
                    let (fire, sleep_fut) = match &mut *guard {
                        TimerState::Disarmed => (false, Fuse::terminated()),
                        TimerState::Periodic {
                            value,
                            interval,
                            overrun,
                        } => {
                            let now = now(clock_id);
                            while *value <= now {
                                *value = value.saturating_add(*interval);
                                match overrun {
                                    None => {
                                        // If the timer hasn't hasn't overrun yet, start a new counter.
                                        *overrun = Some(0);
                                    }
                                    Some(overrun) => {
                                        // If the timer is overrunning, increase the counter.
                                        *overrun = overrun.saturating_add(1);
                                    }
                                }
                            }
                            (overrun.is_some(), sleep_until(*value, clock_id).fuse())
                        }
                        TimerState::Oneshot { value } => {
                            let now = now(clock_id);
                            if *value <= now {
                                *guard = TimerState::Disarmed;
                                (true, Fuse::terminated())
                            } else {
                                (false, sleep_until(*value, clock_id).fuse())
                            }
                        }
                    };

                    // If the timer expired, fire an event.
                    if fire {
                        let Some(process) = process.upgrade() else {
                            break;
                        };

                        match event {
                            Event::ITimer { signal } => {
                                process.queue_signal(SigInfo {
                                    signal,
                                    code: SigInfoCode::KERNEL,
                                    fields: SigFields::None,
                                });
                            }
                            Event::Timer { sig_event, timer } => match sig_event.sigev_notify {
                                SigEventData::None => {}
                                SigEventData::Signal | SigEventData::ThreadId(_) => {
                                    let overrun =
                                        if let TimerState::Periodic { overrun, .. } = &mut *guard {
                                            Some(overrun)
                                        } else {
                                            None
                                        };

                                    let sig_info = SigInfo {
                                        signal: Signal::new(sig_event.sigev_signo as u8).unwrap(),
                                        code: SigInfoCode::TIMER,
                                        fields: SigFields::Timer(SigTimer {
                                            tid: timer,
                                            overrun: overrun
                                                .as_deref()
                                                .copied()
                                                .flatten()
                                                .unwrap_or_default(),
                                            sigval: sig_event.sigev_value,
                                        }),
                                    };

                                    let queued = match sig_event.sigev_notify {
                                        SigEventData::Signal => process.queue_signal(sig_info),
                                        SigEventData::ThreadId(tid) => {
                                            if let Some(thread) = process
                                                .threads()
                                                .into_iter()
                                                .find(|t| t.tid() == tid)
                                            {
                                                thread.queue_signal(sig_info)
                                            } else {
                                                false
                                            }
                                        }
                                        _ => unreachable!(),
                                    };

                                    if let Some(overrun) = overrun {
                                        if queued {
                                            *overrun = None;
                                        } else if let Some(overrun) = overrun {
                                            *overrun += 1;
                                        }
                                    }
                                }
                                SigEventData::Thread { .. } => todo!(),
                            },
                        }
                    }
                    drop(guard);
                    drop(state);

                    // Wait for the timer to expire or for the state to change.
                    select_biased! {
                        _ = wait.fuse() => {}
                        _ = { sleep_fut } => {}
                    }
                }
            }
        });

        Self {
            clock_id,
            state,
            notify: NotifyOnDrop(notify),
        }
    }

    pub fn get_time(&self) -> ITimerspec {
        let guard = self.state.lock();
        let time = guard.get_time(now(self.clock_id));
        drop(guard);
        time
    }

    pub fn set_time(&self, mut new: ITimerspec, absolute: bool) -> ITimerspec {
        let mut guard = self.state.lock();

        let now = now(self.clock_id);
        if !absolute && new.value != Timespec::ZERO {
            new.value = new.value.saturating_add(now);
        }

        let new_state = match (new.value != Timespec::ZERO, new.interval != Timespec::ZERO) {
            (_, true) => TimerState::Periodic {
                value: new.value,
                interval: new.interval,
                overrun: None,
            },
            (true, false) => TimerState::Oneshot { value: new.value },
            (false, false) => TimerState::Disarmed,
        };
        let old_state = core::mem::replace(&mut *guard, new_state);
        drop(guard);

        self.notify.notify();

        old_state.get_time(now)
    }
}

#[derive(Clone, Copy)]
enum TimerState {
    Disarmed,
    Periodic {
        value: Timespec,
        interval: Timespec,
        overrun: Option<u32>,
    },
    Oneshot {
        value: Timespec,
    },
}

impl TimerState {
    fn get_time(self, now: Timespec) -> ITimerspec {
        match self {
            TimerState::Disarmed => ITimerspec {
                interval: Timespec::ZERO,
                value: Timespec::ZERO,
            },
            TimerState::Periodic {
                value, interval, ..
            } => ITimerspec {
                interval,
                value: value.saturating_sub(now),
            },
            TimerState::Oneshot { value } => ITimerspec {
                interval: Timespec::ZERO,
                value: value.saturating_sub(now),
            },
        }
    }
}

pub enum Event {
    ITimer { signal: Signal },
    Timer { sig_event: SigEvent, timer: TimerId },
}
