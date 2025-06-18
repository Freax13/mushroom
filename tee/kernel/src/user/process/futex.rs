use core::{
    num::NonZeroU32,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};

use crate::{error::ensure, memory::page::KernelPage, spin::mutex::Mutex};
use alloc::{collections::BTreeMap, sync::Arc};
use bytemuck::bytes_of_mut;
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
            waker: AtomicWaker::new(),
            woken: AtomicBool::new(false),
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
                self.node.waker.register(cx.waker());
                if self.node.woken.load(Ordering::SeqCst) {
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
                if self.ready || self.node.woken.load(Ordering::Relaxed) {
                    return;
                }

                let mut guard = self.futexes.futexes.lock();

                // Check again after taking the lock.
                if self.node.woken.load(Ordering::SeqCst) {
                    return;
                }

                let list = guard.get_mut(&self.offset).unwrap();
                let ptr = Arc::as_ptr(&self.node);
                let mut cursor = unsafe {
                    // SAFETY: The node hasn't been woken up, so it must still be on the list.
                    list.cursor_mut_from_ptr(ptr)
                };
                cursor.remove();
            }
        }

        Ok(WaitFuture {
            futexes: self.clone(),
            offset,
            node,
            ready: false,
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
            let mut cursor = waiters.front_mut();
            while let Some(node) = cursor.get() {
                // Skip nodes that haven't had their requirements satisfied.
                if !node.matches(scope, bitset) {
                    cursor.move_next();
                    continue;
                }

                // Wake the node up.
                node.woken.store(true, Ordering::SeqCst);
                node.waker.wake();

                // Remove the node from the list.
                cursor.remove();

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
    link: LinkedListAtomicLink,
    waker: AtomicWaker,
    woken: AtomicBool,
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
