use alloc::{boxed::Box, sync::Arc};
use core::{future::pending, num::NonZeroU64};

use async_trait::async_trait;
use futures::{FutureExt, select_biased};

use crate::{
    error::{Result, ensure, err},
    fs::{
        FileSystem,
        fd::{
            BsdFileLock, Events, NonEmptyEvents, OpenFileDescription, OpenFileDescriptionData,
            ReadBuf,
            epoll::{EpollReady, EpollRequest, EpollResult, EventCounter, WeakEpollReady},
        },
        node::{FileAccessContext, new_ino},
        ownership::Ownership,
        path::Path,
    },
    rt::notify::Notify,
    spin::mutex::Mutex,
    time::{now, sleep_until},
    user::{
        syscall::args::{
            ClockId, FileMode, FileType, FileTypeAndMode, ITimerspec, OpenFlags, SetTimeFlags,
            Stat, TimerfdCreateFlags, Timespec,
        },
        thread::{Gid, Uid},
    },
};

pub struct Timer {
    ino: u64,
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
            ino: new_ino(),
            clock_id,
            internal: Mutex::new(TimerInternal {
                flags: OpenFlags::from(flags),
                state: TimerState {
                    counter: EventCounter::new(),
                    deadline: TimerStateDeadline::Disarmed,
                },
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
        self.internal.lock().flags.update(flags);
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
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Unknown, FileMode::ALL_READ_WRITE),
            uid: Uid::SUPER_USER,
            gid: Gid::SUPER_USER,
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
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

        let new_deadline = match (new.value != Timespec::ZERO, new.interval != Timespec::ZERO) {
            (_, true) => TimerStateDeadline::Periodic {
                deadline,
                interval: new.interval,
            },
            (true, false) => TimerStateDeadline::Oneshot { deadline },
            (false, false) => TimerStateDeadline::Disarmed,
        };

        let mut guard = self.internal.lock();
        let _ = guard.state.advance(now);
        let old_time = guard.state.get_value(now);
        guard.state.deadline = new_deadline;
        drop(guard);

        self.set_timer_notify.notify();

        Ok(old_time)
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

        let mut wait = self.set_timer_notify.wait();
        loop {
            let guard = self.internal.lock();
            let deadline = guard.state.next_deadline();
            drop(guard);

            let Some(deadline) = deadline else {
                // If there's no deadline, wait until the timer gets
                // reconfigured.
                wait.next().await;
                continue;
            };

            // Wait until the timer is reconfigured or the deadline expires.
            select_biased! {
                _ = wait.next().fuse() => continue,
                _ = sleep_until(deadline, self.clock_id).fuse() => return NonEmptyEvents::READ,
            }
        }
    }

    fn epoll_ready(self: Arc<OpenFileDescriptionData<Self>>) -> Result<Box<dyn WeakEpollReady>> {
        Ok(Box::new(Arc::downgrade(&self)))
    }

    fn read(&self, buf: &mut dyn ReadBuf, _: &FileAccessContext) -> Result<usize> {
        ensure!(buf.buffer_len() >= 8, Inval);

        let now = now(self.clock_id);

        let mut guard = self.internal.lock();
        let expirations = guard.state.advance(now).ok_or(err!(Again))?;
        drop(guard);

        self.set_timer_notify.notify();

        buf.write(0, &expirations.get().to_ne_bytes())?;

        Ok(8)
    }

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
        todo!()
    }
}

#[async_trait]
impl EpollReady for Timer {
    async fn epoll_ready(&self, req: &EpollRequest) -> EpollResult {
        let mut wait = self.set_timer_notify.wait();
        loop {
            let mut state = self.internal.lock().state.clone();

            let start_deadline = state.next_deadline();
            let now = now(self.clock_id);
            let _ = state.advance(now);

            let mut result = EpollResult::new();
            if let Some(start_deadline) = start_deadline
                && start_deadline <= now
            {
                result.set_ready(Events::READ);
            }
            result.add_counter(Events::READ, &state.counter);
            if let Some(result) = result.if_matches(req) {
                return result;
            }

            let Some(deadline) = state.next_deadline() else {
                wait.next().await;
                continue;
            };

            select_biased! {
                _ = wait.next().fuse() => {}
                _ = sleep_until(deadline, self.clock_id).fuse() => {},
            }
        }
    }
}

#[derive(Clone)]
struct TimerState {
    counter: EventCounter,
    deadline: TimerStateDeadline,
}

#[derive(Clone)]
enum TimerStateDeadline {
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
        match self.deadline {
            TimerStateDeadline::Disarmed => None,
            TimerStateDeadline::Periodic { deadline, .. }
            | TimerStateDeadline::Oneshot { deadline } => Some(deadline),
        }
    }

    #[must_use]
    fn advance(&mut self, now: Timespec) -> Option<NonZeroU64> {
        match self.deadline {
            TimerStateDeadline::Disarmed => None,
            TimerStateDeadline::Periodic {
                ref mut deadline,
                interval,
            } => {
                let mut expired = 0;
                while *deadline <= now {
                    expired += 1;
                    *deadline = deadline.saturating_add(interval);
                }
                self.counter.inc();
                NonZeroU64::new(expired)
            }
            TimerStateDeadline::Oneshot { deadline } => {
                if deadline <= now {
                    self.deadline = TimerStateDeadline::Disarmed;
                    self.counter.inc();
                    NonZeroU64::new(1)
                } else {
                    None
                }
            }
        }
    }

    fn get_value(&self, now: Timespec) -> ITimerspec {
        match self.deadline {
            TimerStateDeadline::Disarmed => ITimerspec {
                interval: Timespec::ZERO,
                value: Timespec::ZERO,
            },
            TimerStateDeadline::Periodic {
                deadline, interval, ..
            } => ITimerspec {
                interval,
                value: deadline.saturating_sub(now),
            },
            TimerStateDeadline::Oneshot { deadline } => ITimerspec {
                interval: Timespec::ZERO,
                value: deadline.saturating_sub(now),
            },
        }
    }
}
