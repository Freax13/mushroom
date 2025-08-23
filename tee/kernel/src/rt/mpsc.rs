#![allow(dead_code)]

use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
};
use core::{
    cmp,
    iter::from_fn,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use crate::spin::mutex::Mutex;

pub fn new<T>() -> (Sender<T>, Receiver<T>) {
    let receiver = Receiver::new();
    let sender = receiver.sender();
    (sender, receiver)
}

struct State<T> {
    waker: Option<Waker>,
    values: VecDeque<T>,
}

pub struct Sender<T>(Weak<Mutex<State<T>>>);

pub struct Receiver<T>(Arc<Mutex<State<T>>>);

impl<T> Sender<T> {
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        let Some(strong) = self.0.upgrade() else {
            return Err(SendError(value));
        };

        let mut guard = strong.lock();
        guard.values.push_back(value);
        if let Some(waker) = guard.waker.take() {
            waker.wake();
        }

        Ok(())
    }
}

impl<T> PartialEq for Sender<T> {
    fn eq(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.0, &other.0)
    }
}

impl<T> Eq for Sender<T> {}

impl<T> PartialOrd for Sender<T> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Sender<T> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        let this = self.0.as_ptr() as *const ();
        let other = other.0.as_ptr() as *const ();
        this.cmp(&other)
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        // Try to upgrade to a strong reference.
        let Some(strong) = self.0.upgrade() else {
            return;
        };
        // Drop the weak reference early, so that the `Receiver` doesn't count
        // it as a `Sender` that's still alive.
        drop(core::mem::take(&mut self.0));

        // Wake the waker, so that the `Receiver` can reevaluate whether the
        // channel has been closed.
        let mut guard = strong.lock();
        let Some(waker) = guard.waker.take() else {
            return;
        };
        waker.wake();
    }
}

pub struct SendError<T>(T);

impl<T> Receiver<T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            waker: None,
            values: VecDeque::new(),
        })))
    }

    pub async fn recv(&mut self) -> Result<T, ReceiveError> {
        struct RecvFuture<'a, T>(&'a Receiver<T>);

        impl<T> Future for RecvFuture<'_, T> {
            type Output = Result<T, ReceiveError>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut guard = self.0.0.lock();

                if let Some(value) = guard.values.pop_front() {
                    return Poll::Ready(Ok(value));
                }

                // If there are not more senders, the channel is closed.
                let no_senders = Arc::weak_count(&self.0.0) == 0;
                if no_senders {
                    return Poll::Ready(Err(ReceiveError));
                }

                guard.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }

        RecvFuture(self).await
    }

    pub fn try_iter(&self) -> impl Iterator<Item = T> {
        from_fn(|| self.0.lock().values.pop_front())
    }

    pub fn sender(&self) -> Sender<T> {
        Sender(Arc::downgrade(&self.0))
    }
}

#[derive(Debug)]
pub struct ReceiveError;
