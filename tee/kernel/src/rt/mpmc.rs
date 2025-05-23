#![allow(dead_code)]

use core::{
    pin::Pin,
    task::{Context, Poll, Waker},
};

use crate::spin::mutex::Mutex;
use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
    vec::Vec,
};

pub fn new<T>() -> (Sender<T>, Receiver<T>) {
    let receiver = Receiver::new();
    let sender = receiver.sender();
    (sender, receiver)
}

struct State<T> {
    wakers: Vec<Waker>,
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
        for waker in guard.wakers.drain(..) {
            waker.wake();
        }

        Ok(())
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub struct SendError<T>(T);

impl<T> Receiver<T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            wakers: Vec::new(),
            values: VecDeque::new(),
        })))
    }

    pub fn try_recv(&self) -> Option<T> {
        let mut guard = self.0.lock();
        guard.values.pop_front()
    }

    pub async fn recv(&self) -> T {
        struct RecvFuture<'a, T>(&'a Receiver<T>);

        impl<T> Future for RecvFuture<'_, T> {
            type Output = T;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut guard = self.0.0.lock();

                if let Some(value) = guard.values.pop_front() {
                    return Poll::Ready(value);
                }

                guard.wakers.push(cx.waker().clone());
                Poll::Pending
            }
        }

        RecvFuture(self).await
    }

    pub async fn readable(&self) {
        struct ReadableFuture<'a, T>(&'a Receiver<T>);

        impl<T> Future for ReadableFuture<'_, T> {
            type Output = ();

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut guard = self.0.0.lock();

                if !guard.values.is_empty() {
                    return Poll::Ready(());
                }

                guard.wakers.push(cx.waker().clone());
                Poll::Pending
            }
        }

        ReadableFuture(self).await
    }

    pub fn sender(&self) -> Sender<T> {
        Sender(Arc::downgrade(&self.0))
    }
}

impl<T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
