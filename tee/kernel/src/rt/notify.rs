#![allow(dead_code)]
//! A concurrency primitive that can be used to send and subscribe to
//! notifications.

use core::{
    ops::Deref,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use crate::spin::mutex::Mutex;
use alloc::{sync::Arc, vec::Vec};

pub struct Notify {
    state: Mutex<State>,
}

struct State {
    generation: u64,
    wakers: Vec<Waker>,
}

impl Notify {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                generation: 0,
                wakers: Vec::new(),
            }),
        }
    }

    /// Returns a `Future` that resolves after a subsequent call to
    /// `Notify::notify`.
    ///
    /// Note that unlike an `async` function this function immediatly starts
    /// executing. This is done so that we can wait for notifies after the
    /// function call and not for notifies after the `Future` starts being
    /// polled.
    pub fn wait(&self) -> impl Future<Output = ()> + '_ {
        struct Wait<'a> {
            notify: &'a Notify,
            start_generation: u64,
            registered_waker: Option<Waker>,
        }

        impl Wait<'_> {
            fn remove_waker(&self, waker: Waker, state: &mut State) {
                // Don't do anything if the generation no longer matches (the
                // waker will have already been removed if that's the case.)
                if state.generation != self.start_generation {
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
        }

        impl Future for Wait<'_> {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut guard = self.notify.state.lock();
                if guard.generation != self.start_generation {
                    return Poll::Ready(());
                }

                let waker = cx.waker();
                if let Some(old_slot) = self.registered_waker.as_mut() {
                    if old_slot.will_wake(waker) {
                        // We don't need to do anything.
                    } else {
                        let old_waker = core::mem::replace(old_slot, waker.clone());

                        self.remove_waker(old_waker, &mut guard);
                        guard.wakers.push(waker.clone());
                    }
                } else {
                    self.registered_waker = Some(waker.clone());
                    guard.wakers.push(waker.clone());
                }

                drop(guard);
                Poll::Pending
            }
        }

        impl Drop for Wait<'_> {
            fn drop(&mut self) {
                // Don't do anything if we haven't registers a waker yet.
                let Some(waker) = self.registered_waker.take() else {
                    return;
                };

                self.remove_waker(waker, &mut self.notify.state.lock());
            }
        }

        // Record the generation.
        let guard = self.state.lock();
        let start_generation = guard.generation;
        drop(guard);

        Wait {
            notify: self,
            start_generation,
            registered_waker: None,
        }
    }

    /// Listen for notifications until the closure return `Some`.
    pub async fn wait_until<R>(&self, f: impl Fn() -> Option<R>) -> R {
        loop {
            let wait = self.wait();
            if let Some(value) = f() {
                return value;
            }
            wait.await;
        }
    }

    pub fn notify(&self) {
        let mut guard = self.state.lock();
        guard.generation += 1;
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
