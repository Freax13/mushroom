use core::{
    pin::Pin,
    task::{Context, Poll},
};

use alloc::vec::Vec;

pub struct FuturesUnorderedBuilder<T> {
    futures: Vec<Option<T>>,
}

impl<T> FuturesUnorderedBuilder<T> {
    pub fn new() -> Self {
        Self {
            futures: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.futures.is_empty()
    }

    pub fn push(&mut self, future: T) {
        self.futures.push(Some(future));
    }

    pub fn finish(self) -> FuturesUnordered<T> {
        FuturesUnordered {
            futures: self.futures,
        }
    }
}

impl<T> Extend<T> for FuturesUnorderedBuilder<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.futures.extend(iter.into_iter().map(Some));
    }
}

pub struct FuturesUnordered<T> {
    futures: Vec<Option<T>>,
}

impl<T> FuturesUnordered<T> {
    pub fn next(&mut self) -> Next<'_, T> {
        Next { this: self }
    }

    pub fn reset(mut self) -> FuturesUnorderedBuilder<T> {
        self.futures.clear();
        FuturesUnorderedBuilder {
            futures: self.futures,
        }
    }
}

pub struct Next<'a, T> {
    this: &'a mut FuturesUnordered<T>,
}

impl<T> Future for Next<'_, T>
where
    T: Future,
{
    type Output = Option<T::Output>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let futures = &mut self.this.futures;

        let mut has_any = false;

        for slot in futures.iter_mut() {
            let Some(future) = slot else {
                continue;
            };

            has_any = true;

            let future = unsafe {
                // SAFETY: The future is stored in a `Vec`, so it's location is
                // stable. We never resize the `Vec` after polling (before
                // resetting), so futures are never moved.
                Pin::new_unchecked(future)
            };

            let Poll::Ready(result) = future.poll(cx) else {
                continue;
            };
            *slot = None;
            return Poll::Ready(Some(result));
        }

        if has_any {
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }
}
