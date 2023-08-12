#![allow(dead_code)]

use super::notify::Notify;

pub struct OnceCell<T> {
    state: spin::once::Once<T>,
    notify: Notify,
}

impl<T> OnceCell<T> {
    pub fn new() -> Self {
        Self {
            state: spin::once::Once::new(),
            notify: Notify::new(),
        }
    }

    /// Returns the Cell's value. This may be `value` or an earlier set value.
    pub fn set(&self, value: T) -> &T {
        // Try to initialize the Once.
        let mut option = Some(value);
        let value = self.state.call_once(|| option.take().unwrap());

        // If the value was taken out of the `Option` we just set the value.
        // Notify other tasks.
        let set = option.is_none();
        if set {
            self.notify.notify();
        }

        value
    }

    pub async fn get(&self) -> &T {
        loop {
            let wait = self.notify.wait();

            if let Some(value) = self.state.get() {
                return value;
            }

            wait.await;
        }
    }
}
