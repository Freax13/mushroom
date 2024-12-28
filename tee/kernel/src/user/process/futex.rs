use core::num::NonZeroU32;

use crate::{
    error::{bail, ensure},
    spin::mutex::Mutex,
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use futures::{select_biased, FutureExt};

use super::{
    memory::VirtualMemory,
    syscall::args::{ClockId, Pointer, Timespec},
};
use crate::{error::Result, rt::oneshot, time::sleep_until};

pub struct Futexes {
    futexes: Mutex<BTreeMap<Pointer<u32>, Vec<FutexWaiter>>>,
}

impl Futexes {
    pub fn new() -> Self {
        Self {
            futexes: Mutex::new(BTreeMap::new()),
        }
    }

    pub async fn wait(
        self: Arc<Self>,
        uaddr: Pointer<u32>,
        val: u32,
        bitset: Option<NonZeroU32>,
        deadline: Option<(Timespec, ClockId)>,
        vm: Arc<VirtualMemory>,
    ) -> Result<()> {
        // Check if the value already changed. This can help avoid taking the lock.
        let current_value = vm.read(uaddr)?;
        ensure!(current_value == val, Again);

        let mut guard = self.futexes.lock();

        // Now that we've taken the lock, we need to check again.
        let current_value = vm.read(uaddr)?;
        ensure!(current_value == val, Again);

        let (sender, receiver) = oneshot::new();
        guard
            .entry(uaddr)
            .or_default()
            .push(FutexWaiter { sender, bitset });
        drop(guard);

        if let Some((deadline, clock_id)) = deadline {
            select_biased! {
                res = receiver.recv().fuse() => {
                    res.unwrap();
                    Ok(())
                }
                _ = sleep_until(deadline, clock_id).fuse() => bail!(TimedOut),
            }
        } else {
            let res = receiver.recv().await;
            res.unwrap();
            Ok(())
        }
    }

    pub fn wake(&self, uaddr: Pointer<u32>, num_waiters: u32, bitset: Option<NonZeroU32>) -> u32 {
        if num_waiters == 0 {
            return 0;
        }

        let mut woken = 0;

        let mut guard = self.futexes.lock();
        if let Some(waiters) = guard.get_mut(&uaddr) {
            for waiter in waiters.extract_if(.., |waiter| waiter.matches_bitset(bitset)) {
                // Wake up the thread.
                if waiter.sender.send(()).is_err() {
                    // The thread has already canceled the operation.
                    continue;
                }
                // Record that the thread was woken up.
                woken += 1;
                if woken >= num_waiters {
                    break;
                }
            }
        }

        woken
    }
}

struct FutexWaiter {
    sender: oneshot::Sender<()>,
    bitset: Option<NonZeroU32>,
}

impl FutexWaiter {
    pub fn matches_bitset(&self, bitset: Option<NonZeroU32>) -> bool {
        match (self.bitset, bitset) {
            (None, None) | (None, Some(_)) | (Some(_), None) => true,
            (Some(lhs), Some(rhs)) => lhs.get() & rhs.get() != 0,
        }
    }
}
