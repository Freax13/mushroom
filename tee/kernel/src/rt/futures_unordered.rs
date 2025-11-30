use alloc::{collections::vec_deque::VecDeque, sync::Arc, vec::Vec};
use core::{
    pin::Pin,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

use bit_field::BitField;

use crate::{exception::TimerInterruptGuard, spin::mutex::Mutex};

pub struct FuturesUnorderedBuilder<T> {
    futures: Vec<Option<T>>,
    waker: Arc<FuturesUnorderedWaker>,
}

impl<T> FuturesUnorderedBuilder<T> {
    pub fn new() -> Self {
        Self {
            futures: Vec::new(),
            waker: FuturesUnorderedWaker::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.futures.is_empty()
    }

    pub fn push(&mut self, future: T) {
        self.futures.push(Some(future));
    }

    pub fn finish(self) -> FuturesUnordered<T> {
        let mut guard = self.waker.internal.lock();
        guard.polled_once = false;
        guard.ready_indices.clear();
        guard.ready_indices.reserve(self.futures.len());
        guard.waker = Waker::noop().clone();
        drop(guard);

        FuturesUnordered {
            futures: self.futures,
            waker: self.waker,
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
    waker: Arc<FuturesUnorderedWaker>,
}

impl<T> FuturesUnordered<T> {
    pub fn next(&mut self) -> Next<'_, T> {
        Next { this: self }
    }

    pub fn reset(mut self) -> FuturesUnorderedBuilder<T> {
        self.futures.clear();
        FuturesUnorderedBuilder {
            futures: self.futures,
            waker: self.waker,
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
        let this = &mut *self.this;

        // Don't do anything if there are no wakers.
        if this.futures.is_empty() {
            return Poll::Ready(None);
        }

        let mut guard = this.waker.internal.lock();
        if !guard.polled_once {
            guard.waker.clone_from(cx.waker());
            drop(guard);

            // We need to poll every future at least once (or return early if a
            // future is ready).

            for (i, slot) in this.futures.iter_mut().enumerate() {
                let Some(future) = slot else {
                    continue;
                };

                let waker = this.waker.create_waker(i);
                let mut cx = Context::from_waker(&waker);

                let future = unsafe {
                    // SAFETY: The future is stored in a `Vec`, so it's location is
                    // stable. We never resize the `Vec` after polling (before
                    // resetting), so futures are never moved.
                    Pin::new_unchecked(future)
                };

                let Poll::Ready(result) = future.poll(&mut cx) else {
                    continue;
                };
                *slot = None;
                return Poll::Ready(Some(result));
            }

            let mut guard = this.waker.internal.lock();
            guard.polled_once = true;
            drop(guard);

            Poll::Pending
        } else {
            while let Some(i) = guard.ready_indices.pop_front() {
                let Some(slot) = this.futures.get_mut(i) else {
                    continue;
                };
                let Some(future) = slot else {
                    continue;
                };

                guard.waker.clone_from(cx.waker());
                drop(guard);

                let waker = this.waker.create_waker(i);
                let mut cx = Context::from_waker(&waker);

                let future = unsafe {
                    // SAFETY: The future is stored in a `Vec`, so it's location is
                    // stable. We never resize the `Vec` after polling (before
                    // resetting), so futures are never moved.
                    Pin::new_unchecked(future)
                };

                let Poll::Ready(result) = future.poll(&mut cx) else {
                    guard = this.waker.internal.lock();
                    continue;
                };
                *slot = None;
                return Poll::Ready(Some(result));
            }

            guard.waker.clone_from(cx.waker());

            Poll::Pending
        }
    }
}

const LOWER_BITS: usize = align_of::<FuturesUnorderedWaker>().ilog2() as usize;
const MAX_KERNEL_VA_BIT: usize = 47;

fn decode_ptr(ptr: *const ()) -> (*const FuturesUnorderedWaker, usize) {
    let mut index = 0;
    index.set_bits(..LOWER_BITS, ptr.addr().get_bits(..LOWER_BITS));
    index.set_bits(LOWER_BITS.., ptr.addr().get_bits(MAX_KERNEL_VA_BIT..));

    let mut addr = ptr.addr();
    addr.set_bits(..LOWER_BITS, 0);
    addr.set_bits(MAX_KERNEL_VA_BIT.., (1 << (64 - MAX_KERNEL_VA_BIT)) - 1);

    (core::ptr::with_exposed_provenance(addr), index)
}

fn encode_ptr(ptr: *const FuturesUnorderedWaker, index: usize) -> *const () {
    let mut addr = ptr.expose_provenance();
    addr.set_bits(..LOWER_BITS, index.get_bits(..LOWER_BITS));
    addr.set_bits(MAX_KERNEL_VA_BIT.., index.get_bits(LOWER_BITS..));
    core::ptr::without_provenance(addr)
}

struct FuturesUnorderedWaker {
    internal: Mutex<FuturesUnorderedWakerInternal, TimerInterruptGuard>,
}

struct FuturesUnorderedWakerInternal {
    /// Whether or not all futures have been polled at least once.
    polled_once: bool,
    /// Indices that got woken up.
    ready_indices: VecDeque<usize>,
    /// Waker for the .next() call
    waker: Waker,
}

impl FuturesUnorderedWaker {
    pub fn new() -> Arc<FuturesUnorderedWaker> {
        Arc::new(FuturesUnorderedWaker {
            internal: Mutex::new(FuturesUnorderedWakerInternal {
                polled_once: false,
                ready_indices: VecDeque::new(),
                waker: Waker::noop().clone(),
            }),
        })
    }

    pub fn create_waker(self: &Arc<Self>, idx: usize) -> Waker {
        let ptr = Arc::into_raw(self.clone());
        let ptr = encode_ptr(ptr, idx);
        unsafe { Waker::new(ptr, &Self::VTABLE) }
    }

    fn wake(&self, idx: usize) {
        let mut guard = self.internal.lock();
        if guard.ready_indices.is_empty() {
            guard.waker.wake_by_ref();
        }
        if !guard.ready_indices.contains(&idx) {
            guard.ready_indices.push_back(idx);
        }
        drop(guard);
    }

    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        Self::waker_clone,
        Self::waker_wake,
        Self::waker_wake_by_ref,
        Self::waker_drop,
    );

    unsafe fn waker_clone(ptr: *const ()) -> RawWaker {
        let (dptr, _) = decode_ptr(ptr);
        unsafe {
            Arc::increment_strong_count(dptr);
        }
        RawWaker::new(ptr, &Self::VTABLE)
    }

    unsafe fn waker_wake(ptr: *const ()) {
        let (dptr, idx) = decode_ptr(ptr);
        let this = unsafe { Arc::from_raw(dptr) };
        this.wake(idx);
    }

    unsafe fn waker_wake_by_ref(ptr: *const ()) {
        let (dptr, idx) = decode_ptr(ptr);
        let this = unsafe { &*dptr };
        this.wake(idx);
    }

    unsafe fn waker_drop(ptr: *const ()) {
        let (dptr, _) = decode_ptr(ptr);
        unsafe {
            Arc::decrement_strong_count(dptr);
        }
    }
}
