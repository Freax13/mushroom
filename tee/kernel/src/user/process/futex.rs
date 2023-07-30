use core::num::NonZeroU32;

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use bytemuck::bytes_of_mut;
use spin::Mutex;
use x86_64::VirtAddr;

use super::{memory::ActiveVirtualMemory, syscall::args::Timespec, thread::WeakThread, Process};
use crate::{
    error::{Error, Result},
    time,
};

pub struct Futexes {
    futexes: Mutex<BTreeMap<VirtAddr, Vec<FutexWaiter>>>,
}

impl Futexes {
    pub fn new() -> Self {
        Self {
            futexes: Mutex::new(BTreeMap::new()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn wait(
        &self,
        weak_thread: &WeakThread,
        process: &Arc<Process>,
        uaddr: VirtAddr,
        val: u32,
        bitset: Option<NonZeroU32>,
        deadline: Option<Timespec>,
        vm: &mut ActiveVirtualMemory,
    ) -> Result<()> {
        let mut current_value = 0;

        // Check if the value already changed. This can help avoid taking the lock.
        vm.read(uaddr, bytes_of_mut(&mut current_value))?;
        if current_value != val {
            return Err(Error::again(()));
        }

        let mut guard = self.futexes.lock();

        // Now that we've taken the lock, we need to check again.
        vm.read(uaddr, bytes_of_mut(&mut current_value))?;
        if current_value != val {
            return Err(Error::again(()));
        }

        let weak_thread = weak_thread.clone();
        guard.entry(uaddr).or_default().push(FutexWaiter {
            weak_thread,
            bitset,
            deadline,
        });

        if let Some(deadline) = deadline {
            time::register_futex_timeout(deadline, Arc::downgrade(process));
        }

        Ok(())
    }

    pub fn wake(&self, uaddr: VirtAddr, num_waiters: u32, bitset: Option<NonZeroU32>) -> u32 {
        if num_waiters == 0 {
            return 0;
        }

        let mut woken = 0;

        let mut guard = self.futexes.lock();
        if let Some(waiters) = guard.get_mut(&uaddr) {
            let mut drain_iter = waiters.drain_filter(|waiter| waiter.matches_bitset(bitset));

            for waiter in drain_iter
                .by_ref()
                .take(usize::try_from(num_waiters).unwrap())
            {
                // Write the result to the thread.
                {
                    let Some(thread) = waiter.weak_thread.upgrade() else {
                        continue;
                    };
                    let mut guard = thread.lock();
                    guard.complete(Ok(0));
                }

                // Record that the thread was woken up.
                woken += 1;
            }

            drain_iter.keep_rest();
        }

        woken
    }

    pub fn fire_timeouts(&self, clock: Timespec) {
        let mut guard = self.futexes.lock();

        for waiters in guard.values_mut() {
            for waiter in waiters.drain_filter(|waiter| waiter.expired(clock)) {
                let Some(thread) = waiter.weak_thread.upgrade() else {
                    continue;
                };
                let mut guard = thread.lock();
                guard.complete(Err(Error::timed_out(())));
            }
        }
    }
}

struct FutexWaiter {
    weak_thread: WeakThread,
    bitset: Option<NonZeroU32>,
    deadline: Option<Timespec>,
}

impl FutexWaiter {
    pub fn matches_bitset(&self, bitset: Option<NonZeroU32>) -> bool {
        match (self.bitset, bitset) {
            (None, None) | (None, Some(_)) | (Some(_), None) => true,
            (Some(lhs), Some(rhs)) => lhs.get() & rhs.get() != 0,
        }
    }

    pub fn expired(&self, clock: Timespec) -> bool {
        let Some(deadline) = self.deadline else {
            return false;
        };
        deadline <= clock
    }
}
