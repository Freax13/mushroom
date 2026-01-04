#![allow(dead_code)]

use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
};

use crate::{
    fs::fd::{
        Events, NonEmptyEvents,
        epoll::{EpollResult, EventCounter},
    },
    rt::notify::Notify,
    spin::mutex::Mutex,
};

pub fn new<T>() -> (Sender<T>, Receiver<T>) {
    let receiver = Receiver::new();
    let sender = receiver.sender();
    (sender, receiver)
}

struct State<T> {
    internal: Mutex<StateInternal<T>>,
    notify: Notify,
}

struct StateInternal<T> {
    values: VecDeque<T>,
    read_counter: EventCounter,
}

pub struct Sender<T>(Weak<State<T>>);

pub struct Receiver<T>(Arc<State<T>>);

impl<T> Sender<T> {
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        let Some(strong) = self.0.upgrade() else {
            return Err(SendError(value));
        };

        let mut guard = strong.internal.lock();
        guard.values.push_back(value);
        guard.read_counter.inc();
        drop(guard);
        strong.notify.notify();

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
        Self(Arc::new(State {
            internal: Mutex::new(StateInternal {
                values: VecDeque::new(),
                read_counter: EventCounter::new(),
            }),
            notify: Notify::new(),
        }))
    }

    pub fn try_recv(&self) -> Option<T> {
        let mut guard = self.0.internal.lock();
        let value = guard.values.pop_front()?;
        if guard.values.is_empty() {
            self.0.notify.notify();
        }
        Some(value)
    }

    pub fn peek(&self) -> Option<T>
    where
        T: Clone,
    {
        let guard = self.0.internal.lock();
        guard.values.front().cloned()
    }

    pub async fn recv(&self) -> T {
        self.0.notify.wait_until(|| self.try_recv()).await
    }

    pub fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        let mut ready_events = Events::empty();
        ready_events.set(Events::READ, !self.0.internal.lock().values.is_empty());
        ready_events &= events;
        NonEmptyEvents::new(ready_events)
    }

    pub fn epoll_ready(&self) -> EpollResult {
        let mut result = EpollResult::new();
        let guard = self.0.internal.lock();
        if !guard.values.is_empty() {
            result.set_ready(Events::READ);
            result.add_counter(Events::READ, &guard.read_counter);
        }
        result
    }

    pub fn notify(&self) -> &Notify {
        &self.0.notify
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
