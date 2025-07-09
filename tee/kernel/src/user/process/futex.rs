use core::{
    future::poll_fn,
    num::NonZeroU32,
    pin::Pin,
    task::{Context, Poll},
};

use crate::{error::ensure, memory::page::KernelPage, spin::mutex::Mutex};
use alloc::{collections::BTreeMap, sync::Arc};
use bytemuck::bytes_of_mut;
use crossbeam_utils::atomic::AtomicCell;
use futures::task::AtomicWaker;
use intrusive_collections::{LinkedList, LinkedListAtomicLink, intrusive_adapter};

use crate::error::Result;

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
        self: &Arc<Self>,
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

        let node = Arc::new(FutexWaiter {
            link: LinkedListAtomicLink::new(),
            wait_waker: AtomicWaker::new(),
            wake_waker: AtomicWaker::new(),
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

        struct WaitFuture {
            futexes: Arc<Futexes>,
            offset: usize,
            node: Arc<FutexWaiter>,
            ready: bool,
        }

        impl Future for WaitFuture {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                self.node.wait_waker.register(cx.waker());
                let woken = self
                    .node
                    .state
                    .compare_exchange(WaiterState::WakupPending, WaiterState::WakupConfirmed)
                    .is_ok();
                if woken {
                    // Wake up the task that was waking us up, so that it can
                    // observe the new state.
                    self.node.wake_waker.wake();

                    self.ready = true;
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }
        }

        impl Drop for WaitFuture {
            fn drop(&mut self) {
                // If the node was woken up, it has already been removed from
                // the list. Check once, before taking the lock.
                if self.ready {
                    return;
                }

                let prev_state = self.node.state.swap(WaiterState::Cancelled);

                // If the node was woken up, it has already been removed from
                // the list. Check once, before taking the lock.
                match prev_state {
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
                    }
                    WaiterState::WakupPending => {
                        // Wake up the task that was waking us up, so that it
                        // can observe the new state.
                        self.node.wake_waker.wake();
                    }
                    WaiterState::WakupConfirmed | WaiterState::Cancelled => unreachable!(),
                }
            }
        }

        Ok(WaitFuture {
            futexes: self.clone(),
            offset,
            node,
            ready: false,
        })
    }

    pub async fn wake(
        &self,
        offset: usize,
        num_waiters: u32,
        scope: FutexScope,
        bitset: Option<NonZeroU32>,
    ) -> u32 {
        let mut woken = 0;
        while woken < num_waiters {
            // Find some candiates to wake up and start the wake up process.
            let mut candidates = LinkedList::new(ListAdapter::NEW);
            if let Some(waiters) = self.futexes.lock().get_mut(&offset) {
                let mut cursor = waiters.front_mut();
                'outer: for _ in woken..num_waiters {
                    loop {
                        let Some(node) = cursor.get() else {
                            break 'outer;
                        };

                        // Skip nodes that haven't had their requirements satisfied.
                        if !node.matches(scope, bitset) {
                            cursor.move_next();
                            continue;
                        }

                        // Wake the node up.
                        if node
                            .state
                            .compare_exchange(WaiterState::Pending, WaiterState::WakupPending)
                            .is_err()
                        {
                            cursor.move_next();
                            continue;
                        }
                        node.wait_waker.wake();

                        // Remove the node from the list.
                        let node = cursor.remove().unwrap();

                        // Add the node to the list of candidates.
                        candidates.push_back(node);
                        break;
                    }
                }
            }

            if candidates.is_empty() {
                break;
            }

            for node in candidates {
                // Wait for the wake operation to be confirmed or cancelled.
                let confirmed = poll_fn(|cx| {
                    node.wake_waker.register(cx.waker());
                    let state = node.state.load();
                    match state {
                        WaiterState::Pending => unreachable!(),
                        WaiterState::WakupPending => Poll::Pending,
                        WaiterState::WakupConfirmed => Poll::Ready(true),
                        WaiterState::Cancelled => Poll::Ready(false),
                    }
                })
                .await;
                woken += u32::from(confirmed);
            }
        }
        woken
    }
}

struct FutexWaiter {
    link: LinkedListAtomicLink,
    wait_waker: AtomicWaker,
    wake_waker: AtomicWaker,
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
    /// The futex wait operation was woken up, but not yet confirmed.
    WakupPending,
    /// The futex wait operation was woken up and confirmed.
    WakupConfirmed,
    /// The futex wait operation has been cancelled.
    Cancelled,
}
