use alloc::{collections::BTreeMap, sync::Arc};
use core::{
    num::NonZeroU32,
    pin::Pin,
    task::{Context, Poll},
};

use bytemuck::bytes_of_mut;
use crossbeam_utils::atomic::AtomicCell;
use futures::task::AtomicWaker;
use intrusive_collections::{LinkedList, LinkedListAtomicLink, intrusive_adapter};

use crate::{
    error::{Result, ensure},
    memory::page::KernelPage,
    spin::mutex::Mutex,
};

intrusive_adapter!(ListAdapter = Arc<FutexWaiter>: FutexWaiter { link: LinkedListAtomicLink });

pub struct Futexes {
    futexes: Mutex<BTreeMap<usize, LinkedList<ListAdapter>>>,
}

impl Futexes {
    pub fn new() -> Self {
        Self {
            futexes: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn wait(
        self: Arc<Self>,
        offset: usize,
        val: u32,
        scope: FutexScope,
        bitset: Option<NonZeroU32>,
        page: &KernelPage,
    ) -> Result<WaitFuture> {
        let page_offset = offset & 0xfff;

        // Check if the value already changed. This can help avoid taking the lock.
        let mut current_value = 0u32;
        page.read(page_offset, bytes_of_mut(&mut current_value));
        ensure!(current_value == val, Again);

        let node = Arc::new(FutexWaiter {
            link: LinkedListAtomicLink::new(),
            wait_waker: AtomicWaker::new(),
            state: AtomicCell::new(WaiterState::Pending),
            scope,
            bitset,
        });

        let mut guard = self.futexes.lock();

        // Now that we've taken the lock, we need to check again.
        page.read(page_offset, bytes_of_mut(&mut current_value));
        ensure!(current_value == val, Again);

        guard.entry(offset).or_default().push_back(node.clone());
        drop(guard);

        Ok(WaitFuture {
            futexes: self,
            offset,
            node,
            done: false,
        })
    }

    pub fn wake(
        &self,
        offset: usize,
        num_waiters: u32,
        scope: FutexScope,
        bitset: Option<NonZeroU32>,
    ) -> u32 {
        let mut woken = 0;
        if let Some(waiters) = self.futexes.lock().get_mut(&offset) {
            // Find some candiates to wake up and start the wake up process.
            let mut cursor = waiters.front_mut();
            while woken < num_waiters {
                let Some(node) = cursor.get() else {
                    break;
                };

                // Skip nodes that haven't had their requirements satisfied.
                if !node.matches(scope, bitset) {
                    cursor.move_next();
                    continue;
                }

                // Wake the node up.
                if node
                    .state
                    .compare_exchange(WaiterState::Pending, WaiterState::Wakeup)
                    .is_err()
                {
                    cursor.move_next();
                    continue;
                }
                node.wait_waker.wake();

                // Remove the node from the list.
                let node = cursor.remove().unwrap();
                drop(node);

                woken += 1;
            }
        }
        woken
    }
}

struct FutexWaiter {
    link: LinkedListAtomicLink,
    wait_waker: AtomicWaker,
    state: AtomicCell<WaiterState>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaiterState {
    /// The futex wait operation has just started.
    Pending,
    /// The futex wait operation was woken up.
    Wakeup,
    /// The futex wait operation has been cancelled.
    Cancelled,
}

pub struct WaitFuture {
    futexes: Arc<Futexes>,
    offset: usize,
    node: Arc<FutexWaiter>,
    done: bool,
}

impl WaitFuture {
    /// Returns `true` if the wait operation was woken up.
    fn now_or_never_by_mut(&mut self) -> bool {
        let prev = self.node.state.swap(WaiterState::Cancelled);
        match prev {
            WaiterState::Pending => {
                let mut guard = self.futexes.futexes.lock();
                let list = guard.get_mut(&self.offset).unwrap();
                let ptr = Arc::as_ptr(&self.node);
                let mut cursor = unsafe {
                    // SAFETY: The node hasn't been woken up, so it
                    // must still be on the list.
                    list.cursor_mut_from_ptr(ptr)
                };
                cursor.remove();
                drop(guard);

                self.done = true;

                false
            }
            WaiterState::Wakeup => {
                self.done = true;
                true
            }
            WaiterState::Cancelled => unreachable!(),
        }
    }

    /// Returns `true` if the wait operation was woken up.
    pub fn now_or_never(mut self) -> bool {
        self.now_or_never_by_mut()
    }
}

impl Future for WaitFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.node.wait_waker.register(cx.waker());
        let woken = self
            .node
            .state
            .compare_exchange(WaiterState::Wakeup, WaiterState::Cancelled)
            .is_ok();
        if woken {
            self.done = true;
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for WaitFuture {
    fn drop(&mut self) {
        if !self.done {
            self.now_or_never_by_mut();
        }
    }
}
