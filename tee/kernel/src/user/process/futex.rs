use core::num::NonZeroU32;

use alloc::{collections::BTreeMap, vec::Vec};
use bytemuck::bytes_of_mut;
use spin::Mutex;
use x86_64::VirtAddr;

use super::{
    memory::ActiveVirtualMemory,
    thread::{schedule_thread, THREADS},
};
use crate::error::{Error, Result};

pub struct Futexes {
    futexes: Mutex<BTreeMap<VirtAddr, Vec<FutexWaiter>>>,
}

impl Futexes {
    pub fn new() -> Self {
        Self {
            futexes: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn wait(
        &self,
        tid: u32,
        uaddr: VirtAddr,
        val: u32,
        bitset: Option<NonZeroU32>,
        vm: &mut ActiveVirtualMemory,
    ) -> Result<()> {
        let mut current_value = 0;

        // Check if the value already changed. This can help avoid taking the lock.
        vm.read(uaddr, bytes_of_mut(&mut current_value))?;
        if current_value != val {
            return Err(Error::Again);
        }

        let mut guard = self.futexes.lock();

        // Now that we've taken the lock, we need to check again.
        vm.read(uaddr, bytes_of_mut(&mut current_value))?;
        if current_value != val {
            return Err(Error::Again);
        }

        guard
            .entry(uaddr)
            .or_default()
            .push(FutexWaiter { tid, bitset });

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
                THREADS.lock()[&waiter.tid].lock().registers.rax = 0;
                schedule_thread(waiter.tid);
                woken += 1;
            }

            drain_iter.keep_rest();
        }

        woken
    }
}

struct FutexWaiter {
    tid: u32,
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