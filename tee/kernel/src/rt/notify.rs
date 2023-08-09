#![allow(dead_code)]
//! A concurrency primitive that can be used to send and subscribe to
//! notifications.

use core::{
    future::Future,
    ops::Deref,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use alloc::{sync::Arc, vec::Vec};
use spin::mutex::SpinMutex;

pub struct Notify {
    state: SpinMutex<State>,
}

struct State {
    generation: u64,
    wakers: Vec<Waker>,
}

impl Notify {
    pub fn new() -> Self {
        Self {
            state: SpinMutex::new(State {
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
        }

        impl Future for Wait<'_> {
            type Output = ();

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut guard = self.notify.state.lock();
                if guard.generation != self.start_generation {
                    return Poll::Ready(());
                }

                guard.wakers.push(cx.waker().clone());
                drop(guard);
                Poll::Pending
            }
        }

        // Record the generation.
        let guard = self.state.lock();
        let start_generation = guard.generation;
        drop(guard);

        Wait {
            notify: self,
            start_generation,
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

/// A wrapper around `Arc<Notify>` that sends a notification when it's dropped.
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
