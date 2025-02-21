use core::{
    pin::Pin,
    task::{Context, Poll, Waker},
};

use crate::spin::mutex::Mutex;
use alloc::sync::Arc;

pub fn new<T>() -> (Sender<T>, Receiver<T>) {
    let state = Arc::new(Mutex::new(State::Empty));
    (Sender(state.clone()), Receiver(state))
}

enum State<T> {
    Empty,
    Waiting(Waker),
    Sent(T),
    Closed,
}

pub struct Sender<T>(Arc<Mutex<State<T>>>);

pub struct SendError<T>(T);

impl<T> Sender<T> {
    /// Returns whether the sender can still send a value.
    /// This is not the case if the receive half has been dropped.
    pub fn can_send(&self) -> bool {
        let guard = self.0.lock();
        !matches!(&*guard, State::Closed)
    }

    pub fn send(self, value: T) -> Result<(), SendError<T>> {
        let mut guard = self.0.lock();

        // Return an error if the channel is already closed.
        if matches!(&*guard, State::Closed) {
            return Err(SendError(value));
        }

        // Take out the waker.
        let mut w = None;
        if let State::Waiting(waker) = &*guard {
            w = Some(waker.clone());
        }

        // Fill the state with the value.
        *guard = State::Sent(value);
        drop(guard);

        // Wake the future waiting for the value.
        if let Some(w) = w {
            w.wake();
        }

        Ok(())
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let mut guard = self.0.lock();

        // If the sender did it's job, it's done.
        if matches!(&*guard, State::Sent(_)) {
            return;
        }

        // Otherwise we might have to do some cleanup.
        // The new state will be Closed.
        let old_state = core::mem::replace(&mut *guard, State::Closed);
        match old_state {
            State::Empty => {}
            State::Waiting(waker) => waker.wake(),
            State::Sent(_) => unreachable!(),
            State::Closed => {}
        }
    }
}

pub struct Receiver<T>(Arc<Mutex<State<T>>>);

#[derive(Debug)]
pub struct RecvError;

impl<T> Receiver<T> {
    pub async fn recv(self) -> Result<T, RecvError> {
        struct RecvFuture<T>(Receiver<T>);

        impl<T> Future for RecvFuture<T> {
            type Output = Result<T, RecvError>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut guard = self.0.0.lock();

                // Try to extract the value.
                if matches!(&*guard, State::Sent(_)) {
                    let State::Sent(value) = core::mem::replace(&mut *guard, State::Closed) else {
                        unreachable!();
                    };
                    return Poll::Ready(Ok(value));
                }

                // Return an error if the channel was closed.
                if matches!(&*guard, State::Closed) {
                    return Poll::Ready(Err(RecvError));
                }

                // Store the waker.
                *guard = State::Waiting(cx.waker().clone());
                Poll::Pending
            }
        }

        RecvFuture(self).await
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let mut guard = self.0.lock();
        *guard = State::Closed;
    }
}
