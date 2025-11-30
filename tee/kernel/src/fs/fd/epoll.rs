use alloc::{
    boxed::Box,
    collections::linked_list::LinkedList,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    cmp,
    fmt::Debug,
    future::pending,
    mem::transmute_copy,
    num::NonZeroUsize,
    ops::Not,
    pin::{Pin, pin},
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker, ready},
};

use async_trait::async_trait;
use bitflags::Flags;
use futures::future::{Either, select};

use crate::{
    error::{Result, bail, ensure, err},
    fs::{
        FileSystem,
        fd::{
            BsdFileLock, Events, FileDescriptor, NonEmptyEvents, OpenFileDescription,
            OpenFileDescriptionData, StrongFileDescriptor, WeakFileDescriptor,
        },
        node::{FileAccessContext, new_ino},
        ownership::Ownership,
        path::Path,
    },
    rt::{
        futures_unordered::FuturesUnorderedBuilder,
        notify::{Notify, NotifyOnDrop},
        set_yield_flag, spawn,
    },
    spin::mutex::Mutex,
    user::{
        syscall::args::{
            EpollEvent, EpollEvents, FileMode, FileType, FileTypeAndMode, OpenFlags, Stat, Timespec,
        },
        thread::{Gid, Uid},
    },
};

pub struct Epoll {
    ino: u64,
    internal: Mutex<EpollInternal>,
    /// The wakers on this notify are woken every time the interest list is updated.
    notify: NotifyOnDrop,
    bsd_file_lock: BsdFileLock,
    poll_task_handle: ExternallyPollableTaskHandle<()>,
}

struct EpollInternal {
    ownership: Ownership,
    interest_list: Vec<InterestListEntry>,
    ready_list: LinkedList<InterestListEntry>,
    /// This counter is increased every time a fd becomes ready.
    ready_counter: EventCounter,
}

impl Epoll {
    #[expect(clippy::new_ret_no_self)]
    pub fn new(uid: Uid, gid: Gid) -> StrongFileDescriptor {
        let notify = Arc::new(Notify::new());
        let (poll_task_builder, poll_task_handler) = ExternallyPollableTaskBuilder::new();
        let (fd, arc) = StrongFileDescriptor::new_cyclic_with_data(|_| Self {
            ino: new_ino(),
            internal: Mutex::new(EpollInternal {
                ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
                interest_list: Vec::new(),
                ready_list: LinkedList::new(),
                ready_counter: EventCounter::new(),
            }),
            notify: NotifyOnDrop(notify.clone()),
            bsd_file_lock: BsdFileLock::anonymous(),
            poll_task_handle: poll_task_handler,
        });

        let weak = Arc::downgrade(&arc);
        spawn(poll_task_builder.build(async move {
            let mut builder = FuturesUnorderedBuilder::new();
            let mut pending_result = Option::<(WeakFileDescriptor, EpollResult)>::None;
            while let Some(arc) = weak.upgrade() {
                let mut guard = arc.internal.lock();

                if let Some((wfd, result)) = pending_result {
                    if let Some((i, entry)) = guard
                        .interest_list
                        .iter_mut()
                        .enumerate()
                        .find(|(_, entry)| entry.epoll_ready.fd() == wfd)
                    {
                        entry.ready_events = result.ready_events;
                        entry.current_values = result.counter_values;

                        if entry.ready() {
                            let entry = guard.interest_list.swap_remove(i);
                            guard.ready_list.push_back(entry);
                            guard.ready_counter.inc();
                            notify.notify();
                        }
                    } else {
                        let mut cursor = guard.ready_list.cursor_front_mut();
                        while let Some(entry) = cursor.current() {
                            if entry.epoll_ready.fd() != wfd {
                                cursor.move_next();
                                continue;
                            }

                            entry.ready_events = result.ready_events;
                            entry.current_values = result.counter_values;

                            if !entry.ready() {
                                let entry = cursor.remove_current().unwrap();
                                guard.interest_list.push(entry);
                            } else {
                                guard.ready_counter.inc();
                                notify.notify();
                            }

                            break;
                        }
                    }
                }

                async fn wait_on_fd(
                    wfd: WeakFileDescriptor,
                    future: Pin<Box<dyn Future<Output = EpollResult> + Send>>,
                    request: EpollRequest,
                ) -> (WeakFileDescriptor, EpollResult) {
                    let mut result = future.await;
                    result.ready_events &= request.events;
                    (wfd, result)
                }
                let mut i = 0;
                while let Some(entry) = guard.interest_list.get(i) {
                    debug_assert!(!entry.ready());
                    let request = entry.request();
                    let Some(future) = entry.epoll_ready.epoll_ready(request) else {
                        guard.interest_list.swap_remove(i);
                        continue;
                    };
                    let wfd = entry.epoll_ready.fd();
                    builder.push(wait_on_fd(wfd, future, request));
                    i += 1;
                }
                let mut cursor = guard.ready_list.cursor_front_mut();
                while let Some(entry) = cursor.current() {
                    debug_assert!(entry.ready());
                    let request = entry.request();
                    let Some(future) = entry.epoll_ready.epoll_ready(request) else {
                        cursor.remove_current().unwrap();
                        continue;
                    };
                    let wfd = entry.epoll_ready.fd();
                    builder.push(wait_on_fd(wfd, future, request));
                    cursor.move_next();
                }

                let wait = notify.wait();
                drop(guard);
                drop(arc);

                let mut futures = builder.finish();
                let fut = select(wait, futures.next()).await;
                match fut {
                    Either::Left(_) => {
                        pending_result = None;
                    }
                    Either::Right((result, wait)) => {
                        if let Some(result) = result {
                            pending_result = Some(result);
                        } else {
                            wait.await;
                            pending_result = None;
                        }
                    }
                }

                builder = futures.reset();
            }
        }));

        fd
    }
}

#[async_trait]
impl OpenFileDescription for Epoll {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn path(&self) -> Result<Path> {
        Path::new(b"anon_inode:[eventpoll]".to_vec())
    }

    fn force_poll(&self) {
        let mut guard = self.internal.lock();
        guard
            .interest_list
            .iter_mut()
            .filter_map(|entry| entry.epoll_ready.fd().upgrade())
            .for_each(|epoll| {
                epoll.force_poll();
            });
        drop(guard);

        self.poll_task_handle.poll();
    }

    async fn epoll_wait(&self, maxevents: NonZeroUsize) -> Result<Vec<EpollEvent>> {
        self.force_poll();

        let events = self
            .notify
            .wait_until(|| {
                let mut guard = self.internal.lock();
                let guard = &mut *guard;
                let available_len = NonZeroUsize::new(guard.ready_list.len())?;
                let len = cmp::min(maxevents, available_len).get();
                let mut events = Vec::with_capacity(len);

                let mut cursor = guard.ready_list.cursor_front_mut();
                while events.len() < len
                    && let Some(entry) = cursor.current()
                {
                    assert!(entry.ready());

                    // Make sure that the fd hasn't been closed.
                    if entry
                        .epoll_ready
                        .fd()
                        .upgrade()
                        .is_none_or(|fd| fd.is_closed())
                    {
                        cursor.remove_current().unwrap();
                        continue;
                    }

                    // Record the event.
                    events.push(EpollEvent {
                        events: EpollEvents::from(entry.ready_events),
                        data: entry.data,
                    });

                    // Update the entry.
                    if entry.oneshot {
                        entry.events = Events::empty();
                    }
                    if entry.edge_triggered {
                        entry.last_acked_counter_values = entry.current_values;
                    }

                    // If the entry is no longer ready, move it to the interest
                    // list.
                    if !entry.ready() {
                        let entry = cursor.remove_current().unwrap();
                        guard.interest_list.push(entry);
                        continue;
                    }

                    cursor.move_next();
                }

                // Cycle the list entries.
                if cursor.current().is_some() {
                    let mut list = cursor.split_before();
                    guard.ready_list.append(&mut list);
                }

                events.is_empty().not().then_some(events)
            })
            .await;
        Ok(events)
    }

    fn epoll_add(&self, fd: &FileDescriptor, event: EpollEvent) -> Result<()> {
        assert!(
            !event
                .events
                .intersects(EpollEvents::EXCLUSIVE | EpollEvents::WAKEUP),
            "{:?}",
            event.events
        );

        let epoll_ready = Arc::clone(&**fd).epoll_ready()?;

        let mut guard = self.internal.lock();
        // Make sure that the file descriptor is not already registered.
        ensure!(
            !guard
                .interest_list
                .iter()
                .chain(guard.ready_list.iter())
                .any(|entry| entry.epoll_ready.fd() == *fd),
            Exist
        );
        // Register the file descriptor.
        guard
            .interest_list
            .push(InterestListEntry::new(epoll_ready, event));
        drop(guard);
        self.notify.notify();
        Ok(())
    }

    fn epoll_del(&self, fd: &dyn OpenFileDescription) -> Result<()> {
        let mut guard = self.internal.lock();
        if let Some(idx) = guard
            .interest_list
            .iter()
            .position(|entry| entry.epoll_ready.fd() == *fd)
        {
            guard.interest_list.swap_remove(idx);
        } else {
            let mut cursor = guard.ready_list.cursor_front_mut();
            loop {
                let entry = cursor.current().ok_or(err!(NoEnt))?;
                if entry.epoll_ready.fd() != *fd {
                    cursor.move_next();
                    continue;
                }
                cursor.remove_current().unwrap();
                break;
            }
        }
        drop(guard);
        self.notify.notify();
        Ok(())
    }

    fn epoll_mod(&self, fd: &dyn OpenFileDescription, event: EpollEvent) -> Result<()> {
        assert!(
            !event
                .events
                .intersects(EpollEvents::EXCLUSIVE | EpollEvents::WAKEUP),
            "{:?}",
            event.events
        );

        let mut guard = self.internal.lock();
        if let Some(entry) = guard
            .interest_list
            .iter_mut()
            .find(|entry| entry.epoll_ready.fd() == *fd)
        {
            *entry = InterestListEntry::new(entry.epoll_ready.clone_epoll_ready(), event);
        } else {
            let mut cursor = guard.ready_list.cursor_front_mut();
            loop {
                let entry = cursor.current().ok_or(err!(NoEnt))?;
                if entry.epoll_ready.fd() != *fd {
                    cursor.move_next();
                    continue;
                }

                *entry = InterestListEntry::new(entry.epoll_ready.clone_epoll_ready(), event);

                let entry = cursor.remove_current().unwrap();
                guard.interest_list.push(entry);
                break;
            }
        }
        drop(guard);
        self.notify.notify();
        Ok(())
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
    }

    #[inline]
    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Unknown, guard.ownership.mode()),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        bail!(BadF)
    }

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        if !events.contains(Events::READ) {
            return None;
        }

        self.force_poll();
        let guard = self.internal.lock();
        guard
            .ready_list
            .is_empty()
            .not()
            .then_some(NonEmptyEvents::READ)
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        if !events.contains(Events::READ) {
            return pending().await;
        }

        self.force_poll();
        self.notify
            .wait_until(|| {
                let guard = self.internal.lock();
                guard
                    .ready_list
                    .is_empty()
                    .not()
                    .then_some(NonEmptyEvents::READ)
            })
            .await
    }

    fn epoll_ready(self: Arc<OpenFileDescriptionData<Self>>) -> Result<Box<dyn WeakEpollReady>> {
        Ok(Box::new(Arc::downgrade(&self)))
    }

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
        Ok(&self.bsd_file_lock)
    }
}

#[async_trait]
impl EpollReady for Epoll {
    async fn epoll_ready(&self, req: &EpollRequest) -> EpollResult {
        self.force_poll();
        self.notify
            .epoll_loop(req, || {
                let mut result = EpollResult::new();
                let guard = self.internal.lock();
                if !guard.ready_list.is_empty() {
                    result.set_ready(Events::READ);
                    result.add_counter(Events::READ, &guard.ready_counter);
                }
                result
            })
            .await
    }
}

struct InterestListEntry {
    epoll_ready: Box<dyn WeakEpollReady>,

    data: u64,
    events: Events,
    oneshot: bool,
    edge_triggered: bool,

    ready_events: Events,
    last_acked_counter_values: EventArray<u64>,
    current_values: EventArray<u64>,
}

impl InterestListEntry {
    fn new(epoll_ready: Box<dyn WeakEpollReady>, event: EpollEvent) -> Self {
        Self {
            epoll_ready,
            data: event.data,
            events: Events::from(event.events) | Events::ERR | Events::HUP,
            oneshot: event.events.contains(EpollEvents::ONESHOT),
            edge_triggered: event.events.contains(EpollEvents::ET),
            ready_events: Events::empty(),
            last_acked_counter_values: EventArray::default(),
            current_values: EventArray::default(),
        }
    }

    fn ready(&self) -> bool {
        self.last_acked_counter_values
            .zip(self.current_values)
            .any(self.events & self.ready_events, |&(last, current)| {
                last < current
            })
    }

    fn request(&self) -> EpollRequest {
        EpollRequest {
            events: self.events,
            last_ready_values: self.ready_events,
            min_counter_values: self.current_values,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EventCounter(u64);

impl EventCounter {
    pub const fn new() -> Self {
        Self(1)
    }

    pub fn inc(&mut self) {
        self.0 += 1;
    }
}

pub struct AtomicEventCounter(AtomicU64);

impl AtomicEventCounter {
    pub const fn new() -> Self {
        Self(AtomicU64::new(1))
    }

    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EpollRequest {
    events: Events,
    last_ready_values: Events,
    min_counter_values: EventArray<u64>,
}

impl EpollRequest {
    pub fn events(&self) -> Events {
        self.events
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EpollResult {
    ready_events: Events,
    counter_values: EventArray<u64>,
}

impl EpollResult {
    pub fn new() -> Self {
        Self {
            ready_events: Events::empty(),
            counter_values: EventArray::default(),
        }
    }

    pub fn add_counter(&mut self, events: Events, counter: &EventCounter) {
        if events.is_empty() {
            return;
        }
        self.counter_values.update(events, |cv| *cv += counter.0);
    }

    pub fn add_atomic_counter(&mut self, events: Events, counter: &AtomicEventCounter) {
        if events.is_empty() {
            return;
        }
        let value = counter.0.load(Ordering::SeqCst);
        self.counter_values.update(events, |cv| *cv += value);
    }

    pub fn set_ready(&mut self, events: Events) {
        self.ready_events |= events;
        self.counter_values.update(events, |cv| *cv += 1);
    }

    fn matches(&self, request: &EpollRequest) -> bool {
        // It's a match if the set of ready events changed.
        if (self.ready_events & request.events) != request.last_ready_values {
            return true;
        }

        let combined = self.counter_values.zip(request.min_counter_values);
        combined.any(self.ready_events & request.events, |&(value, min)| {
            value > min
        })
    }

    pub fn if_matches(self, request: &EpollRequest) -> Option<Self> {
        self.matches(request).then_some(self)
    }

    pub fn merge(self, other: Self) -> Self {
        Self {
            ready_events: self.ready_events | other.ready_events,
            counter_values: self
                .counter_values
                .zip(other.counter_values)
                .map(|(lhs, rhs)| lhs + rhs),
        }
    }
}

pub type EventArray<T> = FlagArray<Events, T>;

pub struct FlagArray<F, T>
where
    F: Flags,
    [(); F::FLAGS.len()]: Sized,
{
    arr: [T; F::FLAGS.len()],
}

impl<F, T> FlagArray<F, T>
where
    F: Flags,
    F::Bits: ToFlagArrayIndex<F>,
    [(); F::FLAGS.len()]: Sized,
    [(); F::Bits::NUM_BITS]: Sized,
{
    pub fn update(&mut self, flags: F, f: impl Fn(&mut T)) {
        flags.iter().map(F::Bits::to_index).for_each(|i| {
            f(&mut self.arr[i]);
        });
    }

    pub fn any(&self, mask: F, f: impl Fn(&T) -> bool) -> bool {
        mask.iter().map(F::Bits::to_index).any(|i| f(&self.arr[i]))
    }

    pub fn map<U>(self, f: impl Fn(T) -> U) -> FlagArray<F, U> {
        FlagArray {
            arr: self.arr.map(f),
        }
    }

    pub fn zip<U>(self, other: FlagArray<F, U>) -> FlagArray<F, (T, U)> {
        let mut this = self.arr.map(Some);
        let mut other = other.arr.map(Some);
        FlagArray {
            arr: core::array::from_fn(|i| (this[i].take().unwrap(), other[i].take().unwrap())),
        }
    }
}

impl<F, T> Clone for FlagArray<F, T>
where
    F: Flags,
    [(); F::FLAGS.len()]: Sized,
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            arr: self.arr.clone(),
        }
    }
}

impl<F, T> Copy for FlagArray<F, T>
where
    F: Flags,
    [(); F::FLAGS.len()]: Sized,
    T: Copy,
{
}

impl<F, T> Default for FlagArray<F, T>
where
    F: Flags,
    [(); F::FLAGS.len()]: Sized,
    T: Default,
{
    fn default() -> Self {
        Self {
            arr: core::array::from_fn(|_| Default::default()),
        }
    }
}

impl<F, T> Debug for FlagArray<F, T>
where
    F: Flags,
    [(); F::FLAGS.len()]: Sized,
    T: Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut map = f.debug_map();
        for (flag, value) in F::FLAGS.iter().zip(self.arr.iter()) {
            map.entry(&flag.name(), value);
        }
        map.finish()
    }
}

pub trait Int {
    const NUM_BITS: usize;
}

const SENTINEL: u8 = !0;

pub trait ToFlagArrayIndex<T>: Int + Into<usize>
where
    T: Flags<Bits = Self>,
    [(); Self::NUM_BITS]: Sized,
{
    const INDICES: [u8; Self::NUM_BITS];

    fn to_index(flag: T) -> usize {
        let value: usize = flag.bits().into();
        // Make sure that exactly one bit is set.
        assert!(value.count_ones() == 1);
        // Get the bit position.
        let idx = value.trailing_zeros() as usize;
        // Look up the array index.
        let array_index = Self::INDICES[idx];
        // Make sure it's valid.
        assert_ne!(array_index, SENTINEL);
        usize::from(array_index)
    }
}

macro_rules! impl_int {
    ($($ty:ty,)*) => {
        $(
            impl Int for $ty {
                const NUM_BITS: usize = <$ty>::BITS as usize;
            }

            impl<T> ToFlagArrayIndex<T> for $ty
            where
                T: Flags<Bits = Self>,
            {
                const INDICES: [u8; Self::NUM_BITS] = {
                    let mut arr = [SENTINEL; Self::NUM_BITS];
                    let mut i = 0;
                    while i < T::FLAGS.len() {
                        // Get the integer value for the flag.
                        let flag = T::FLAGS[i].value();
                        let value = unsafe {
                            // SAFETY: The layout is the same.
                            assert!(size_of::<T>() == size_of::<Self>());
                            transmute_copy::<T, Self>(flag)
                        };

                        // Make sure that exactly one bit is set.
                        assert!(value.count_ones() == 1);

                        // Get the bit position.
                        let bit_idx = value.trailing_zeros() as usize;

                        // Make sure that the bit isn't already used by another flag.
                        assert!(arr[bit_idx] == SENTINEL);

                        // Set the index for the bit.
                        arr[bit_idx] = i as u8;

                        i += 1;
                    }
                    arr
                };
            }
        )*
    };
}

impl_int!(u8,);

struct ExternallyPollableTaskBuilder<T> {
    internal: Arc<Mutex<ExternallyPollableTaskInternal<T>>>,
}

impl<T> ExternallyPollableTaskBuilder<T> {
    pub fn new() -> (Self, ExternallyPollableTaskHandle<T>) {
        let internal = Arc::new(Mutex::new(ExternallyPollableTaskInternal::Uninit));
        let weak = Arc::downgrade(&internal);
        (
            Self { internal },
            ExternallyPollableTaskHandle { internal: weak },
        )
    }

    pub fn build<F>(self, fut: F) -> ExternallyPollableTask<T>
    where
        F: Future<Output = T> + Send + 'static,
    {
        let mut guard = self.internal.lock();
        *guard = ExternallyPollableTaskInternal::Live {
            last_waker: Waker::noop().clone(),
            fut: Box::pin(fut),
        };
        drop(guard);
        ExternallyPollableTask {
            internal: self.internal,
        }
    }
}

struct ExternallyPollableTask<T> {
    internal: Arc<Mutex<ExternallyPollableTaskInternal<T>>>,
}

enum ExternallyPollableTaskInternal<T> {
    Uninit,
    Live {
        last_waker: Waker,
        fut: Pin<Box<dyn Future<Output = T> + Send + 'static>>,
    },
    Finished {
        result: Option<T>,
    },
}

impl<T> Future for ExternallyPollableTask<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(mut guard) = self.internal.try_lock() else {
            // Another thread is already polling the task. Let's just tell the
            // scheduler that we want to yield.
            set_yield_flag();
            return Poll::Pending;
        };

        match &mut *guard {
            ExternallyPollableTaskInternal::Uninit => unreachable!(),
            ExternallyPollableTaskInternal::Live { last_waker, fut } => {
                last_waker.clone_from(cx.waker());

                let fut = fut.as_mut();
                let result = ready!(fut.poll(cx));
                *guard = ExternallyPollableTaskInternal::Finished { result: None };
                Poll::Ready(result)
            }
            ExternallyPollableTaskInternal::Finished { result } => {
                let result = result.take().unwrap();
                Poll::Ready(result)
            }
        }
    }
}

struct ExternallyPollableTaskHandle<T> {
    internal: Weak<Mutex<ExternallyPollableTaskInternal<T>>>,
}

impl<T> ExternallyPollableTaskHandle<T> {
    pub fn poll(&self) {
        let Some(internal) = self.internal.upgrade() else {
            return;
        };

        let mut guard = internal.lock();
        let ExternallyPollableTaskInternal::Live { last_waker, fut } = &mut *guard else {
            return;
        };

        let fut = fut.as_mut();
        match fut.poll(&mut Context::from_waker(last_waker)) {
            Poll::Ready(result) => {
                last_waker.wake_by_ref();
                *guard = ExternallyPollableTaskInternal::Finished {
                    result: Some(result),
                };
            }
            Poll::Pending => {}
        }
    }
}

pub trait WeakEpollReady: Send + Sync {
    /// Returns a future resolving when the file descriptor's ready state
    /// matches the request or `None` when the file descriptor has been closed.
    fn epoll_ready(
        &self,
        req: EpollRequest,
    ) -> Option<Pin<Box<dyn Future<Output = EpollResult> + Send>>>;

    /// Get a weak reference to the file descriptor polled by this instance.
    fn fd(&self) -> WeakFileDescriptor;

    /// Clone to a dyn Box.
    fn clone_epoll_ready(&self) -> Box<dyn WeakEpollReady>;
}

impl<T> WeakEpollReady for Weak<OpenFileDescriptionData<T>>
where
    T: EpollReady + OpenFileDescription,
{
    fn epoll_ready(
        &self,
        req: EpollRequest,
    ) -> Option<Pin<Box<dyn Future<Output = EpollResult> + Send>>> {
        self.upgrade().filter(|fd| !fd.is_closed()).map(|this| {
            Box::pin(async move {
                {
                    let ready_future = EpollReady::epoll_ready(&**this, &req);
                    let closed_future = this.wait_until_closed();
                    let pinned = pin!(closed_future);
                    if let Either::Left((res, _)) = select(ready_future, pinned).await {
                        return res;
                    }
                    // End the scope to drop `closed_future`.
                }
                drop(this);
                pending().await
            }) as Pin<Box<_>>
        })
    }

    fn fd(&self) -> WeakFileDescriptor {
        WeakFileDescriptor(Clone::clone(self) as Weak<_>)
    }

    fn clone_epoll_ready(&self) -> Box<dyn WeakEpollReady> {
        Box::new(Clone::clone(self))
    }
}

#[async_trait]
pub trait EpollReady: Send + Sync + 'static {
    /// Returns a future resolving when the file descriptor's ready state
    /// matches the request.
    async fn epoll_ready(&self, req: &EpollRequest) -> EpollResult;
}
