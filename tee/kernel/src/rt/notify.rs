#![allow(dead_code)]
//! A concurrency primitive that can be used to send and subscribe to
//! notifications.

use alloc::{sync::Arc, vec::Vec};
use core::{
    ops::Deref,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};

use futures::future::{Either, select};

use crate::{
    fs::fd::epoll::{EpollRequest, EpollResult},
    spin::mutex::Mutex,
};

pub struct Notify {
    generation: AtomicU64,
    state: Mutex<State>,
}

struct State {
    wakers: Vec<Waker>,
}

impl Notify {
    pub fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            state: Mutex::new(State { wakers: Vec::new() }),
        }
    }

    /// Returns a `Future` that resolves after a subsequent call to
    /// `Notify::notify`.
    ///
    /// Note that unlike an `async` function this function immediatly starts
    /// executing. This is done so that we can wait for notifies after the
    /// function call and not for notifies after the `Future` starts being
    /// polled.
    pub fn wait(&self) -> NotifyWait<'_> {
        NotifyWait {
            notify: self,
            start_generation: self.generation.load(Ordering::SeqCst),
            registered_waker: None,
        }
    }

    /// Listen for notifications until the closure return `Some`.
    pub async fn wait_until<R>(&self, f: impl Fn() -> Option<R>) -> R {
        self.wait().until(f).await
    }

    /// Execute the poll function until the result matches the request.
    pub async fn epoll_loop(&self, req: &EpollRequest, f: impl Fn() -> EpollResult) -> EpollResult {
        self.wait_until(|| f().if_matches(req)).await
    }

    /// Execute the poll function until the result matches the request.
    pub async fn zip_epoll_loop(
        req: &EpollRequest,
        notify1: &Self,
        f: impl Fn() -> EpollResult,
        notify2: &Self,
        g: impl Fn() -> EpollResult,
    ) -> EpollResult {
        let mut wait1 = notify1.wait();
        let mut wait2 = notify2.wait();

        let mut res1 = f();
        let mut res2 = g();

        loop {
            let combined = res1.merge(res2);
            if let Some(combined) = combined.if_matches(req) {
                return combined;
            }

            let fut = select(&mut wait1, &mut wait2).await;
            match fut {
                Either::Left(_) => res1 = f(),
                Either::Right(_) => res2 = g(),
            }
        }
    }

    pub fn notify(&self) {
        let mut guard = self.state.lock();
        self.generation.fetch_add(1, Ordering::SeqCst);
        for waker in guard.wakers.drain(..) {
            waker.wake();
        }
    }
}

impl Default for Notify {
    fn default() -> Self {
        Self::new()
    }
}

pub struct NotifyWait<'a> {
    notify: &'a Notify,
    start_generation: u64,
    registered_waker: Option<Waker>,
}

impl NotifyWait<'_> {
    fn remove_waker(&self, generation: u64, waker: Waker, state: &mut State) {
        // Don't do anything if the generation no longer matches (the
        // waker will have already been removed if that's the case.)
        if generation != self.start_generation {
            return;
        }

        // Find and remove the waker.
        let idx = state
            .wakers
            .iter()
            .position(|w| w.will_wake(&waker))
            .unwrap();
        state.wakers.swap_remove(idx);
    }

    pub fn next(&mut self) -> impl Future<Output = ()> + Unpin + '_ {
        self
    }

    pub async fn until<R>(mut self, f: impl Fn() -> Option<R>) -> R {
        loop {
            if let Some(value) = f() {
                return value;
            }
            self.next().await;
        }
    }
}

impl Future for NotifyWait<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let mut generation = this.notify.generation.load(Ordering::SeqCst);
        'register: {
            if generation != this.start_generation {
                break 'register;
            }

            let waker = cx.waker();
            if let Some(old_slot) = this.registered_waker.as_mut() {
                if old_slot.will_wake(waker) {
                    // We don't need to do anything.
                } else {
                    let mut guard = this.notify.state.lock();

                    // Re-fetch the generation, after acquiring the lock.
                    generation = this.notify.generation.load(Ordering::SeqCst);
                    if generation != this.start_generation {
                        break 'register;
                    }

                    let old_waker = core::mem::replace(old_slot, waker.clone());
                    this.remove_waker(generation, old_waker, &mut guard);
                    guard.wakers.push(waker.clone());
                }
            } else {
                let mut guard = this.notify.state.lock();

                // Re-fetch the generation, after acquiring the lock.
                generation = this.notify.generation.load(Ordering::SeqCst);
                if generation != this.start_generation {
                    break 'register;
                }

                this.registered_waker = Some(waker.clone());
                guard.wakers.push(waker.clone());
            }

            return Poll::Pending;
        };

        let _ = this.registered_waker.take();

        // Reset the start generation.
        this.start_generation = generation;

        Poll::Ready(())
    }
}

impl Drop for NotifyWait<'_> {
    fn drop(&mut self) {
        // Don't do anything if we haven't registers a waker yet.
        let Some(waker) = self.registered_waker.take() else {
            return;
        };

        let mut guest = self.notify.state.lock();
        let generation = self.notify.generation.load(Ordering::SeqCst);
        self.remove_waker(generation, waker, &mut guest);
    }
}

/// A wrapper around `Arc<Notify>` that sends a notification when it's dropped.
#[derive(Clone)]
pub struct NotifyOnDrop(pub Arc<Notify>);

impl Deref for NotifyOnDrop {
    type Target = Notify;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for NotifyOnDrop {
    fn drop(&mut self) {
        self.0.notify();
    }
}
