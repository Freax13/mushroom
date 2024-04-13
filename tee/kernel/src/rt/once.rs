#![allow(dead_code)]

use super::notify::Notify;

pub struct OnceCell<T> {
    state: crate::spin::once::Once<T>,
    notify: Notify,
}

impl<T> OnceCell<T> {
    pub fn new() -> Self {
        Self {
            state: crate::spin::once::Once::new(),
            notify: Notify::new(),
        }
    }

    /// Initialize the value in the OnceCell if it hasn't been initialized
    /// already. Returns whether the OnceCell was initialized.
    pub fn set(&self, value: T) -> bool {
        // Try to initialize the Once.
        let mut option = Some(value);
        self.state.call_once(|| option.take().unwrap());

        // If the value was taken out of the `Option` we just set the value.
        // Notify other tasks.
        let set = option.is_none();
        if set {
            self.notify.notify();
        }
        set
    }

    pub fn try_get(&self) -> Option<&T> {
        self.state.get()
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
