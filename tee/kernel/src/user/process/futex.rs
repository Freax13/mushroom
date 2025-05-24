use core::num::NonZeroU32;

use crate::{error::ensure, memory::page::KernelPage, spin::mutex::Mutex};
use alloc::{collections::BTreeMap, vec::Vec};
use bytemuck::bytes_of_mut;

use crate::{error::Result, rt::oneshot};

pub struct Futexes {
    futexes: Mutex<BTreeMap<usize, Vec<FutexWaiter>>>,
}

impl Futexes {
    pub fn new() -> Self {
        Self {
            futexes: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn wait(
        &self,
        offset: usize,
        val: u32,
        scope: FutexScope,
        bitset: Option<NonZeroU32>,
        page: &KernelPage,
    ) -> Result<impl Future<Output = ()> + 'static> {
        let page_offset = offset & 0xfff;

        // Check if the value already changed. This can help avoid taking the lock.
        let mut current_value = 0u32;
        page.read(page_offset, bytes_of_mut(&mut current_value));
        ensure!(current_value == val, Again);

        let mut guard = self.futexes.lock();

        // Now that we've taken the lock, we need to check again.
        page.read(page_offset, bytes_of_mut(&mut current_value));
        ensure!(current_value == val, Again);

        let (sender, receiver) = oneshot::new();
        guard.entry(offset).or_default().push(FutexWaiter {
            sender,
            scope,
            bitset,
        });
        drop(guard);

        Ok(async move {
            receiver.recv().await.unwrap();
        })
    }

    pub fn wake(
        &self,
        offset: usize,
        num_waiters: u32,
        scope: FutexScope,
        bitset: Option<NonZeroU32>,
    ) -> u32 {
        if num_waiters == 0 {
            return 0;
        }

        let mut woken = 0;

        let mut guard = self.futexes.lock();
        if let Some(waiters) = guard.get_mut(&offset) {
            for waiter in waiters.extract_if(.., |waiter| waiter.matches(scope, bitset)) {
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
    scope: FutexScope,
    bitset: Option<NonZeroU32>,
}

impl FutexWaiter {
    pub fn matches(&self, scope: FutexScope, bitset: Option<NonZeroU32>) -> bool {
        let matches_scope = self.scope == scope;
        let matches_bitset = self
            .bitset
            .zip(bitset)
            .is_none_or(|(lhs, rhs)| lhs.get() & rhs.get() != 0);
        matches_scope && matches_bitset
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FutexScope {
    Global,
    Process(u32),
}
