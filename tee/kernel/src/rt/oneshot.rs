use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use alloc::sync::Arc;
use spin::mutex::SpinMutex;

pub fn new<T>() -> (Sender<T>, Receiver<T>) {
    let state = Arc::new(SpinMutex::new(State::Empty));
    (Sender(state.clone()), Receiver(state))
}

enum State<T> {
    Empty,
    Waiting(Waker),
    Sent(T),
    Closed,
}

pub struct Sender<T>(Arc<SpinMutex<State<T>>>);

pub struct SendError<T>(T);

impl<T> Sender<T> {
    pub fn send(self, value: T) -> Result<(), SendError<T>> {
        let mut guard = self.0.lock();

        // Return an error if the channel is already closed.
        if matches!(&*guard, State::Closed) {
            return Err(SendError(value));
        }

        // Wait the future waiting for the value.
        if let State::Waiting(waker) = &*guard {
            waker.wake_by_ref();
        }

        // Otherwise fill the state with the value.
        *guard = State::Sent(value);

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

pub struct Receiver<T>(Arc<SpinMutex<State<T>>>);

#[derive(Debug)]
pub struct RecvError;

impl<T> Receiver<T> {
    pub async fn recv(self) -> Result<T, RecvError> {
        struct RecvFuture<T>(Receiver<T>);

        impl<T> Future for RecvFuture<T> {
            type Output = Result<T, RecvError>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut guard = self.0 .0.lock();

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
