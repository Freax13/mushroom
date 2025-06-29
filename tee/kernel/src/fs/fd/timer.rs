use core::{future::pending, num::NonZeroU64};

use alloc::{boxed::Box, sync::Arc};
use async_trait::async_trait;
use futures::{FutureExt, select_biased};

use crate::{
    error::{Result, ensure, err},
    fs::{
        FileSystem,
        fd::{Events, FileLock, NonEmptyEvents, OpenFileDescription, ReadBuf},
        node::FileAccessContext,
        ownership::Ownership,
        path::Path,
    },
    rt::notify::Notify,
    spin::mutex::Mutex,
    time::{now, sleep_until},
    user::process::{
        syscall::args::{
            ClockId, FileMode, ITimerspec, OpenFlags, SetTimeFlags, Stat, TimerfdCreateFlags,
            Timespec,
        },
        thread::{Gid, Uid},
    },
};

pub struct Timer {
    clock_id: ClockId,
    internal: Mutex<TimerInternal>,
    set_timer_notify: Notify,
}

struct TimerInternal {
    flags: OpenFlags,
    ownership: Ownership,
    state: TimerState,
}

impl Timer {
    pub fn new(clock_id: ClockId, flags: TimerfdCreateFlags, uid: Uid, gid: Gid) -> Self {
        Self {
            clock_id,
            internal: Mutex::new(TimerInternal {
                flags: OpenFlags::from(flags),
                state: TimerState::Disarmed,
                ownership: Ownership::new(FileMode::from_bits_retain(0o444), uid, gid),
            }),
            set_timer_notify: Notify::new(),
        }
    }
}

#[async_trait]
impl OpenFileDescription for Timer {
    fn flags(&self) -> OpenFlags {
        self.internal.lock().flags
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.internal.lock().flags = flags;
    }

    fn set_non_blocking(&self, non_blocking: bool) {
        self.internal
            .lock()
            .flags
            .set(OpenFlags::NONBLOCK, non_blocking);
    }

    fn path(&self) -> Result<Path> {
        todo!()
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        todo!()
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        todo!()
    }

    fn set_time(&self, flags: SetTimeFlags, new: ITimerspec) -> Result<ITimerspec> {
        let now = now(self.clock_id);

        let deadline = if flags.contains(SetTimeFlags::ABSTIME) {
            new.value
        } else {
            new.value.saturating_add(now)
        };

        if flags.contains(SetTimeFlags::CANCEL_ON_SET) {
            todo!();
        }

        let new_state = match (new.value != Timespec::ZERO, new.interval != Timespec::ZERO) {
            (_, true) => TimerState::Periodic {
                deadline,
                interval: new.interval,
            },
            (true, false) => TimerState::Oneshot { deadline },
            (false, false) => TimerState::Disarmed,
        };

        let mut guard = self.internal.lock();
        let mut old_state = core::mem::replace(&mut guard.state, new_state);
        drop(guard);

        self.set_timer_notify.notify();

        let _ = old_state.advance(now);
        Ok(old_state.get_value(now))
    }

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        let mut ready_events = Events::empty();
        if events.contains(Events::READ) {
            let guard = self.internal.lock();
            let deadline = guard.state.next_deadline();
            drop(guard);
            if let Some(deadline) = deadline
                && deadline < now(self.clock_id)
            {
                ready_events |= Events::READ;
            }
        }
        NonEmptyEvents::new(ready_events)
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        // timerfd only supports reads.
        if !events.contains(Events::READ) {
            return pending().await;
        }

        loop {
            let wait = self.set_timer_notify.wait();

            let guard = self.internal.lock();
            let deadline = guard.state.next_deadline();
            drop(guard);

            let Some(deadline) = deadline else {
                // If there's no deadline, wait until the timer gets
                // reconfigured.
                wait.await;
                continue;
            };

            // Wait until the timer is reconfigured or the deadline expires.
            select_biased! {
                _ = wait.fuse() => continue,
                _ = sleep_until(deadline, self.clock_id).fuse() => return NonEmptyEvents::READ,
            }
        }
    }

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        ensure!(buf.buffer_len() >= 8, Inval);

        let now = now(self.clock_id);

        let mut guard = self.internal.lock();
        let expirations = guard.state.advance(now).ok_or(err!(Again))?;
        drop(guard);

        buf.write(0, &expirations.get().to_ne_bytes())?;

        Ok(8)
    }

    fn file_lock(&self) -> Result<&FileLock> {
        todo!()
    }
}

#[derive(Clone)]
enum TimerState {
    Disarmed,
    Periodic {
        deadline: Timespec,
        interval: Timespec,
    },
    Oneshot {
        deadline: Timespec,
    },
}

impl TimerState {
    fn next_deadline(&self) -> Option<Timespec> {
        match *self {
            TimerState::Disarmed => None,
            TimerState::Periodic { deadline, .. } | TimerState::Oneshot { deadline } => {
                Some(deadline)
            }
        }
    }

    #[must_use]
    fn advance(&mut self, now: Timespec) -> Option<NonZeroU64> {
        match self {
            TimerState::Disarmed => None,
            TimerState::Periodic { deadline, interval } => {
                let mut expired = 0;
                while *deadline <= now {
                    expired += 1;
                    *deadline = deadline.saturating_add(*interval);
                }
                NonZeroU64::new(expired)
            }
            TimerState::Oneshot { deadline } => {
                if *deadline <= now {
                    *self = Self::Disarmed;
                    NonZeroU64::new(1)
                } else {
                    None
                }
            }
        }
    }

    fn get_value(&self, now: Timespec) -> ITimerspec {
        match *self {
            TimerState::Disarmed => ITimerspec {
                interval: Timespec::ZERO,
                value: Timespec::ZERO,
            },
            TimerState::Periodic { deadline, interval } => ITimerspec {
                interval,
                value: deadline.saturating_sub(now),
            },
            TimerState::Oneshot { deadline } => ITimerspec {
                interval: Timespec::ZERO,
                value: deadline.saturating_sub(now),
            },
        }
    }
}
