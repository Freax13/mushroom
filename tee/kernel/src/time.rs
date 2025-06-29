use crate::{
    error::{Result, bail},
    exception::{InterruptGuard, TimerInterruptGuard},
    spin::mutex::Mutex,
    user::{
        LastRunningVcpuGuard,
        process::syscall::args::{ClockId, Timespec},
    },
};
use alloc::sync::Arc;
use bit_field::BitField;
use core::{
    cell::SyncUnsafeCell,
    cmp,
    ops::{Add, RangeInclusive, Sub},
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use crossbeam_utils::atomic::AtomicCell;
use intrusive_collections::{
    KeyAdapter, LinkedList, LinkedListAtomicLink, RBTree, RBTreeAtomicLink, intrusive_adapter,
};
use log::debug;

#[cfg(all(feature = "fake-time", feature = "real-time"))]
compile_error!("the fake-time and real-time features are both enabled");
#[cfg(not(any(feature = "fake-time", feature = "real-time")))]
compile_error!("neither the fake-time nor real-time features are enabled");

#[cfg(feature = "fake-time")]
mod fake;
#[cfg(feature = "fake-time")]
type DefaultBackend = fake::FakeBackend;
#[cfg(feature = "real-time")]
mod real;
#[cfg(feature = "real-time")]
type DefaultBackend = real::RealBackend;

static DEFAULT_BACKEND: DefaultBackend = DefaultBackend::new();

intrusive_adapter!(TreeAdapter = Arc<Node>: Node { rb_link: RBTreeAtomicLink });
intrusive_adapter!(ListAdapter = Arc<Node>: Node { list_link: LinkedListAtomicLink });
intrusive_adapter!(DeleteListAdapter = Arc<Node>: Node { delete_link: LinkedListAtomicLink });

static SKIP_OFFSET: AtomicU64 = AtomicU64::new(0);

static REALTIME_TIMERS: TimerLists = TimerLists::new();
static REALTIME: Time = unsafe { Time::new(&REALTIME_TIMERS, &DEFAULT_BACKEND) };

static MONOTONIC_TIMERS: TimerLists = TimerLists::new();
static MONOTONIC: Time = unsafe { Time::new(&MONOTONIC_TIMERS, &DEFAULT_BACKEND) };

pub fn now(clock: ClockId) -> Timespec {
    let now = match clock {
        ClockId::Realtime => REALTIME.now(),
        ClockId::Monotonic => MONOTONIC.now(),
    };
    Timespec::from(now)
}

pub fn set(clock: ClockId, time: Timespec) -> Result<()> {
    match clock {
        ClockId::Realtime => {
            let time = Tick::try_from(time).unwrap();
            REALTIME.update_offset(time);
            Ok(())
        }
        ClockId::Monotonic => bail!(OpNotSupp),
    }
}

/// Expire timers and wake the tasks that wait for them.
pub fn expire_timers() {
    REALTIME.expire_timers();
    MONOTONIC.expire_timers();
}

/// Advance forward in time to the next timer deadline.
pub fn advance_time(last_vcpu_guard: LastRunningVcpuGuard) -> Result<(), NoTimeoutScheduledError> {
    debug!("advancing simulated time");

    // Determine the delta until the next deadline.
    let guard = TimerInterruptGuard::new();
    let realtime_delta = REALTIME.next_deadline().unwrap();
    let monotonic_delta = MONOTONIC.next_deadline().unwrap();
    drop(guard);
    let delta = zip_min(realtime_delta, monotonic_delta).ok_or(NoTimeoutScheduledError)?;

    // Allow other vCPUs to run again. It's important that we do this before
    // expiring timers. If we don't do this, we'll likely wake up vCPUs only
    // for them to go immediately back to sleep.
    drop(last_vcpu_guard);

    // Skip forward in time.
    let delta = u64::try_from(delta.0).unwrap();
    SKIP_OFFSET.fetch_add(delta, Ordering::Relaxed);

    // Now that we advance forward in time, we can expire some more timers.
    expire_timers();

    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub struct NoTimeoutScheduledError;

/// Wait until the deadline.
pub async fn sleep_until(deadline: Timespec, clock_id: ClockId) {
    let deadline = Tick::try_from(deadline).unwrap();
    match clock_id {
        ClockId::Realtime => REALTIME.sleep_until(deadline).await,
        ClockId::Monotonic => MONOTONIC.sleep_until(deadline).await,
    }
}

/// Returns a timestamp from a time source that never skips forward.
pub fn default_backend_offset() -> u64 {
    DEFAULT_BACKEND.current_offset()
}

/// A method of reading wall clock time.
pub trait TimeBackend {
    /// Read the current time. Returns a duration since boot in ns.
    fn current_offset(&self) -> u64;
}

impl<T> TimeBackend for &T
where
    T: TimeBackend,
{
    fn current_offset(&self) -> u64 {
        <T as TimeBackend>::current_offset(self)
    }
}

pub struct Time<T = &'static DefaultBackend> {
    backend: T,
    offset: AtomicU64,
    expire_lock: ExpireLock,
    management_lock: Mutex<ManagementLock>,
}

impl<T> Time<T>
where
    T: TimeBackend,
{
    /// Create a new instance.
    ///
    /// # Safety
    ///
    /// `lists` must be not be used elsewhere.
    pub const unsafe fn new(lists: &'static TimerLists, backend: T) -> Self {
        Self {
            backend,
            offset: AtomicU64::new(0),
            expire_lock: unsafe { ExpireLock::new(lists) },
            management_lock: Mutex::new(unsafe { ManagementLock::new(lists) }),
        }
    }

    /// Query the current time.
    pub fn now(&self) -> Tick {
        self.now_with_offset(self.offset.load(Ordering::Relaxed))
    }

    /// Compute the current time assuming the given offset for the clock.
    fn now_with_offset(&self, clock_offset: u64) -> Tick {
        let offset = self.backend.current_offset();
        let offset = offset + SKIP_OFFSET.load(Ordering::Relaxed);
        let offset = offset + clock_offset;
        Tick::from_ns(offset)
    }

    /// Expire pending timers.
    pub fn expire_timers(&self) {
        self.expire_lock.expire_timers(self.now(), false);
    }

    /// Adjust the clock by a given delta.
    pub fn update_offset(&self, tick: Tick) {
        let mut offset = self.offset.load(Ordering::Relaxed);
        loop {
            let delta = tick - self.now_with_offset(offset);
            let new_offset = offset
                .checked_add_signed(delta.0)
                .expect("clock went to far backwards");

            let res = self.offset.compare_exchange(
                offset,
                new_offset,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            if let Err(new_offset) = res {
                offset = new_offset;
                continue;
            }

            // Update the state for the timers.
            self.expire_lock
                .expire_timers(self.now_with_offset(new_offset), delta < TickDelta::ZERO);

            return;
        }
    }

    /// Query the delta until the next timer deadline.
    ///
    /// This method should be called while all other threads are halted and the
    /// timer interrupt is disabled. Returns `Err` if there's contention.
    pub fn next_deadline(&self) -> Result<Option<TickDelta>, ()> {
        self.expire_lock.next_deadline()
    }

    /// Wait until the deadline.
    pub async fn sleep_until(&self, deadline: Tick) {
        struct Sleep<'a, T> {
            timers: &'a Time<T>,
            state: State,
        }

        enum State {
            Pending { deadline: Tick },
            Started { node: Arc<Node> },
        }

        impl<T> Future for Sleep<'_, T>
        where
            T: TimeBackend,
        {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let now = self.timers.now();

                match self.state {
                    State::Pending { deadline } => {
                        if deadline <= now {
                            Poll::Ready(())
                        } else {
                            let node = Node::new(deadline, cx.waker().clone());

                            let mut guard = self.timers.management_lock.lock();
                            guard.add(node.clone());
                            drop(guard);

                            self.state = State::Started { node };
                            Poll::Pending
                        }
                    }
                    State::Started { ref node } => {
                        if node.deadline <= now {
                            Poll::Ready(())
                        } else {
                            node.update_waker(cx.waker());
                            Poll::Pending
                        }
                    }
                }
            }
        }

        impl<T> Drop for Sleep<'_, T> {
            fn drop(&mut self) {
                let state = core::mem::replace(
                    &mut self.state,
                    State::Pending {
                        deadline: Tick::from_ns(0),
                    },
                );
                let State::Started { node } = state else {
                    return;
                };

                let mut guard = self.timers.management_lock.lock();
                unsafe {
                    guard.remove(node);
                }
            }
        }

        Sleep {
            timers: self,
            state: State::Pending { deadline },
        }
        .await
    }
}

pub struct TimerLists {
    state: AtomicListsState,
    left: SyncUnsafeCell<Half>,
    right: SyncUnsafeCell<Half>,
}

impl TimerLists {
    pub const fn new() -> Self {
        Self {
            state: AtomicListsState::new(ListsState::new()),
            left: SyncUnsafeCell::new(Half {
                pending: LinkedList::new(ListAdapter::NEW),
                expired: LinkedList::new(ListAdapter::NEW),
            }),
            right: SyncUnsafeCell::new(Half {
                pending: LinkedList::new(ListAdapter::NEW),
                expired: LinkedList::new(ListAdapter::NEW),
            }),
        }
    }
}

struct Half {
    pending: LinkedList<ListAdapter>,
    expired: LinkedList<ListAdapter>,
}

struct ExpireLock {
    lists: &'static TimerLists,
}

impl ExpireLock {
    pub const unsafe fn new(lists: &'static TimerLists) -> Self {
        Self { lists }
    }

    pub fn expire_timers(&self, new_tick: Tick, force: bool) {
        let mut state = self.lists.state.load(Ordering::Relaxed);

        loop {
            // If the interrupt lock has already been taken, don't do anything.
            // Another core is already expiring timers. Note that it's
            // technically possible for that other thread to use a lower tick,
            // and that this call would have expire more timers, but that
            // shouldn't be a problem, they'll get expired soon enough.
            if state.expire_lock() {
                return;
            }

            // We don't need to do anything if the new tick value already
            // matches the current one. No new timer can be expired.
            let current_tick = state.tick();
            if !force && current_tick >= new_tick {
                return;
            }

            // Try to acquire the lock.
            let mut new_state = state;
            new_state.set_processed(false);
            new_state.set_expire_lock(true);
            new_state.set_tick(new_tick);
            if let Err(new_state) = self.lists.state.compare_exchange(
                state,
                new_state,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                // Another thread modified the state. Retry.
                state = new_state;
                continue;
            }

            // The lock has been acquired.
            state = new_state;
            break;
        }

        // Expire all timers in one of the halfs depending on the flip flop bit.
        let flip_flop = state.flip_flop();
        if flip_flop {
            let half = unsafe { &mut *self.lists.left.get() };
            Self::process(half, new_tick);
        } else {
            let half = unsafe { &mut *self.lists.right.get() };
            Self::process(half, new_tick);
        }

        // If the normal lock has already been acquired, it will expire all
        // timers for the other half. If not, try to flip the flip flop bit and
        // process the timers on the other half.
        if !state.management_lock() {
            let mut new_state = state;
            new_state.set_processed(true);
            new_state.set_flip_flop(!new_state.flip_flop());
            let res = self.lists.state.compare_exchange(
                state,
                new_state,
                Ordering::AcqRel,
                Ordering::Relaxed,
            );

            if let Err(new_state) = res {
                // The only change that's allowed to happen here is that the
                // normal lock bit is suddenly set and/or that the processed
                // bit has been set.
                debug_assert_eq!(state.tick(), new_state.tick());
                debug_assert_eq!(state.flip_flop(), new_state.flip_flop());
                debug_assert_eq!(state.expire_lock(), new_state.expire_lock());
                debug_assert!(
                    (state.processed() != new_state.processed())
                        || (state.management_lock() != new_state.management_lock())
                );

                // We don't need to expire any timers, the ManagementLock will
                // do so before it's released.
            } else {
                state = new_state;

                // Expire all timers in the other half.
                if state.flip_flop() {
                    let half = unsafe { &mut *self.lists.left.get() };
                    Self::process(half, new_tick);
                } else {
                    let half = unsafe { &mut *self.lists.right.get() };
                    Self::process(half, new_tick);
                }
            }
        }

        // Release the lock.
        self.lists.state.clear_expire_lock(Ordering::Release);
    }

    fn process(half: &mut Half, tick: Tick) {
        let mut cursor = half.pending.front_mut();
        while let Some(node) = cursor.get() {
            // Skip processing timers when we reach the first that hasn't
            // expired yet.
            if node.deadline > tick {
                break;
            }

            let prev_state = node.state.swap(NodeState::Expired);

            let node = cursor.remove().unwrap();
            // Skip over timers that have already been removed.
            if prev_state != NodeState::Removed {
                node.wake();
            }
            half.expired.push_back(node);
        }
    }

    fn next_deadline(&self) -> Result<Option<TickDelta>, ()> {
        // Make sure that no other lock has already been acquired.
        let state = self.lists.state.load(Ordering::Relaxed);
        if state.management_lock() || state.expire_lock() {
            return Err(());
        }

        // Acquire the expire lock.
        let mut new_state = state;
        new_state.set_expire_lock(true);
        self.lists
            .state
            .compare_exchange(state, new_state, Ordering::Acquire, Ordering::Relaxed)
            .map_err(drop)?;
        let state = new_state;

        // Find the next deadline in one of the halfs.
        let flip_flop = state.flip_flop();
        let half = if flip_flop {
            unsafe { &mut *self.lists.left.get() }
        } else {
            unsafe { &mut *self.lists.right.get() }
        };
        let first_deadline = half
            .pending
            .iter()
            .find(|node| node.waker_state.load() != WakerState::Woken)
            .map(|node| node.deadline);

        // Flip to the other half.
        let mut new_state = state;
        new_state.set_flip_flop(!flip_flop);
        let res = self.lists.state.compare_exchange(
            state,
            new_state,
            Ordering::Acquire,
            Ordering::Relaxed,
        );
        if res.is_err() {
            // The compare exchange can only fail if the management lock was
            // taken and not yet released.
            self.lists.state.clear_expire_lock(Ordering::Relaxed);
            return Err(());
        }
        let state = new_state;

        // Find the next deadline for the other half.
        let flip_flop = state.flip_flop();
        let half = if flip_flop {
            unsafe { &mut *self.lists.left.get() }
        } else {
            unsafe { &mut *self.lists.right.get() }
        };
        let second_deadline = half
            .pending
            .iter()
            .find(|node| node.waker_state.load() != WakerState::Woken)
            .map(|node| node.deadline);

        // Release the lock.
        self.lists.state.clear_expire_lock(Ordering::Relaxed);

        // Find the smallest deadline and compute the delta.
        let tick = zip_min(first_deadline, second_deadline);
        let delta = tick.map(|tick| tick.saturating_sub(state.tick()));
        Ok(delta)
    }
}

struct ManagementLock {
    lists: &'static TimerLists,
    rb_tree_left: RBTree<TreeAdapter>,
    rb_tree_right: RBTree<TreeAdapter>,
    deleted_left: LinkedList<DeleteListAdapter>,
    deleted_right: LinkedList<DeleteListAdapter>,
}

impl ManagementLock {
    pub const unsafe fn new(lists: &'static TimerLists) -> Self {
        Self {
            lists,
            rb_tree_left: RBTree::new(TreeAdapter::NEW),
            rb_tree_right: RBTree::new(TreeAdapter::NEW),
            deleted_left: LinkedList::new(DeleteListAdapter::NEW),
            deleted_right: LinkedList::new(DeleteListAdapter::NEW),
        }
    }

    pub fn add(&mut self, node: Arc<Node>) {
        debug_assert!(!node.rb_link.is_linked());
        debug_assert!(!node.list_link.is_linked());
        debug_assert_eq!(node.state.load(), NodeState::Uninit);

        let mut state = self.lists.state.load(Ordering::Relaxed);
        loop {
            // Short-circuit if the timer has already expired.
            if node.deadline <= state.tick() {
                node.wake();
                return;
            }

            debug_assert!(!state.management_lock());
            let mut new_state = state;
            new_state.set_management_lock(true);
            if let Err(new_state) = self.lists.state.compare_exchange(
                state,
                new_state,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                // Another thread modified the state. Retry.
                state = new_state;
                continue;
            }

            // The lock has been acquired.
            state = new_state;
            break;
        }

        self.flush_deleted_nodes();

        // Add the timer to one of the halfs depending on the flip flop bit.
        if !state.flip_flop() {
            node.state.store(NodeState::InsertedLeft);
            let half = unsafe { &mut *self.lists.left.get() };
            let rb_tee = &mut self.rb_tree_left;
            Self::add_to_half(half, rb_tee, node);
        } else {
            node.state.store(NodeState::InsertedRight);
            let half = unsafe { &mut *self.lists.right.get() };
            let rb_tee = &mut self.rb_tree_right;
            Self::add_to_half(half, rb_tee, node);
        }

        self.release_lock();
    }

    fn add_to_half(half: &mut Half, rb_tree: &mut RBTree<TreeAdapter>, node: Arc<Node>) {
        // Insert the node into the red black tree.
        let cursor = rb_tree.insert(node.clone());

        // Insert the node at the appropriate position into the list.
        if let Some(next) = cursor.peek_next().get() {
            debug_assert!(half.pending.iter().any(|n| core::ptr::eq(n, next)));
            let mut cursor = unsafe { half.pending.cursor_mut_from_ptr(next) };
            cursor.insert_before(node);
        } else {
            half.pending.push_back(node);
        }
    }

    unsafe fn remove(&mut self, node: Arc<Node>) {
        let state = node.state.load();
        match state {
            NodeState::Uninit => return, // The node was never inserted.
            NodeState::InsertedLeft => {
                debug_assert!(self.rb_tree_left.iter().any(|n| core::ptr::eq(n, &*node)));
                let mut cursor = unsafe { self.rb_tree_left.cursor_mut_from_ptr(&*node) };
                cursor.remove().unwrap();
            }
            NodeState::InsertedRight => {
                debug_assert!(self.rb_tree_right.iter().any(|n| core::ptr::eq(n, &*node)));
                let mut cursor = unsafe { self.rb_tree_right.cursor_mut_from_ptr(&*node) };
                cursor.remove().unwrap();
            }
            _ => {}
        }

        let preferred_flip_flop = match state {
            NodeState::Uninit => unreachable!(),
            NodeState::InsertedLeft => Some(false),
            NodeState::InsertedRight => Some(true),
            NodeState::Removed => None,
            NodeState::Expired => None,
        };

        let mut state = self.lists.state.load(Ordering::Relaxed);
        loop {
            debug_assert!(!state.management_lock());

            let mut new_state = state;
            new_state.set_management_lock(true);

            // It's better to acquire the half containing the node, but it's
            // not safe to do so when the ExpireLock has already been acquired.
            // Try to update the flip flop value if possible.
            if !state.expire_lock() {
                debug_assert!(state.processed());
                if let Some(preferred_flip_flop) = preferred_flip_flop {
                    new_state.set_flip_flop(preferred_flip_flop);
                }
            }

            if let Err(new_state) = self.lists.state.compare_exchange(
                state,
                new_state,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                // Another thread modified the state. Retry.
                state = new_state;
                continue;
            }

            // The lock has been acquired.
            state = new_state;
            break;
        }

        let prev = node.state.swap(NodeState::Removed);
        match (prev, state.flip_flop()) {
            (NodeState::InsertedLeft, false) => {
                let half = unsafe { &mut *self.lists.left.get() };
                debug_assert!(half.pending.iter().any(|n| core::ptr::eq(n, &*node))); // this fails
                let mut cursor = unsafe { half.pending.cursor_mut_from_ptr(&*node) };
                cursor.remove();
            }
            (NodeState::InsertedRight, true) => {
                let half = unsafe { &mut *self.lists.right.get() };
                debug_assert!(half.pending.iter().any(|n| core::ptr::eq(n, &*node)));
                let mut cursor = unsafe { half.pending.cursor_mut_from_ptr(&*node) };
                cursor.remove();
            }
            (NodeState::InsertedLeft, true) => self.deleted_left.push_back(node),
            (NodeState::InsertedRight, false) => self.deleted_right.push_back(node),
            (NodeState::Expired, _) => {}
            _ => unreachable!(),
        }

        self.flush_deleted_nodes();

        self.release_lock();
    }

    fn flush_deleted_nodes(&mut self) {
        let state = self.lists.state.load(Ordering::Relaxed);
        assert!(state.management_lock());

        let flip_flop = state.flip_flop();
        let half = if !flip_flop {
            unsafe { &mut *self.lists.left.get() }
        } else {
            unsafe { &mut *self.lists.right.get() }
        };
        let deleted = if !flip_flop {
            &mut self.deleted_left
        } else {
            &mut self.deleted_right
        };
        while let Some(node) = deleted.pop_front() {
            if node.state.load() != NodeState::Removed {
                continue;
            }

            debug_assert!(half.pending.iter().any(|n| core::ptr::eq(n, &*node)));
            let mut cursor = unsafe { half.pending.cursor_mut_from_ptr(&*node) };
            cursor.remove().unwrap();
        }
    }

    fn release_lock(&mut self) {
        let mut state = self.lists.state.load(Ordering::Relaxed);
        assert!(state.management_lock());

        let flip_flop = state.flip_flop();
        let half = if flip_flop {
            self.lists.right.get()
        } else {
            self.lists.left.get()
        };
        let rb_tree = if flip_flop {
            &mut self.rb_tree_right
        } else {
            &mut self.rb_tree_left
        };

        loop {
            let mut new_state = state;
            new_state.set_management_lock(false);

            // The ExpireLock wanted to expire timers, but we held the lock.
            // Help it out by expiring the timers.
            if !state.processed() {
                debug_assert_eq!(flip_flop, state.flip_flop());

                let tick = state.tick();
                Self::process(unsafe { &mut *half }, tick, rb_tree);

                new_state.set_processed(true);
            }

            if let Err(new_state) = self.lists.state.compare_exchange(
                state,
                new_state,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                // Another thread modified the state. Retry.
                state = new_state;
                continue;
            }

            // The lock has been released.
            break;
        }
    }

    fn process(half: &mut Half, tick: Tick, rb_tree: &mut RBTree<TreeAdapter>) {
        // Expire and wake pending timers.
        let mut cursor = half.pending.front_mut();
        while cursor.get().is_some_and(|node| node.deadline <= tick) {
            let node = cursor.remove().unwrap();
            if node.state.swap(NodeState::Expired) != NodeState::Removed {
                node.wake();
            }
        }

        // Clear the list of expired timers.
        half.expired.clear();

        // Remove all expired timers from the red black tree.
        let mut cursor = rb_tree.front_mut();
        while cursor.get().is_some_and(|node| node.deadline <= tick) {
            cursor.remove().unwrap();
        }
    }
}

struct Node {
    /// Some state information about whether a node has been inserted into an
    /// list (and if so in which list) or whether it has been removed.
    state: AtomicCell<NodeState>,
    /// The code that expires timers pops of a linked list.
    list_link: LinkedListAtomicLink,
    /// We store the node in a rb tree so that we can quickly find the correct
    /// spot to insert the node in the linked list.
    rb_link: RBTreeAtomicLink,
    /// When the normal linked list containing the node is locked,
    delete_link: LinkedListAtomicLink,

    deadline: Tick,

    waker_state: AtomicCell<WakerState>,
    waker: SyncUnsafeCell<Waker>,
}

impl Node {
    pub fn new(deadline: Tick, waker: Waker) -> Arc<Self> {
        Arc::new(Node {
            rb_link: RBTreeAtomicLink::new(),
            list_link: LinkedListAtomicLink::new(),
            state: AtomicCell::new(NodeState::Uninit),
            delete_link: LinkedListAtomicLink::new(),
            deadline,
            waker_state: AtomicCell::new(WakerState::Init),
            waker: SyncUnsafeCell::new(waker),
        })
    }

    fn update_waker(&self, waker: &Waker) {
        // Try to acquire the lock.
        let res = self
            .waker_state
            .compare_exchange(WakerState::Init, WakerState::Updating);
        match res {
            Ok(_) => {
                // Success!

                // Update the waker.
                let w = unsafe {
                    // SAFETY: We've acquire the lock, so we have mutable
                    // ownership over the waker.
                    &mut *self.waker.get()
                };
                w.clone_from(waker);

                // Release the lock.
                let res = self
                    .waker_state
                    .compare_exchange(WakerState::Updating, WakerState::Init);

                // If the waker has been woken up, do that now.
                if let Err(err) = res {
                    debug_assert_eq!(err, WakerState::Woken);

                    let w = unsafe {
                        // SAFETY: If the state has gone from Updating to
                        // Woken, we still have ownership of the waker.
                        &mut *self.waker.get()
                    };
                    // Release and wake the waker that we just installed.
                    let waker = core::mem::replace(w, Waker::noop().clone());
                    waker.wake();
                }
            }
            Err(WakerState::Woken) => waker.wake_by_ref(),
            Err(_) => unreachable!(),
        }
    }

    fn wake(&self) {
        let prev = self.waker_state.swap(WakerState::Woken);
        match prev {
            WakerState::Init => {
                let w = unsafe {
                    // SAFETY: We've acquire the lock, so we have mutable
                    // ownership over the waker.
                    &*self.waker.get()
                };
                w.wake_by_ref();

                // Note that we don't consume the waker because doing so might
                // release the waker and we shouldn't do free memory in an IRQ
                // context.
            }
            WakerState::Updating => {
                // The other thread is in charge of waking the task.
            }
            WakerState::Woken => unreachable!("each node should only get woken up at most once"),
        }
    }
}

struct NodeKey<'a>(&'a Tick);

impl PartialEq for NodeKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for NodeKey<'_> {}

impl PartialOrd for NodeKey<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NodeKey<'_> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        // Compare the deadline and then compare the pointer to the deadline.
        // This will give a strict ordering for nodes.
        self.0
            .cmp(other.0)
            .then_with(|| (self.0 as *const Tick).cmp(&(other.0 as *const Tick)))
    }
}

impl<'a> KeyAdapter<'a> for TreeAdapter {
    type Key = NodeKey<'a>;

    fn get_key(
        &self,
        value: &'a <Self::PointerOps as intrusive_collections::PointerOps>::Value,
    ) -> Self::Key {
        NodeKey(&value.deadline)
    }
}

const _: () = assert!(AtomicCell::<NodeState>::is_lock_free());
const _: () = assert!(AtomicCell::<WakerState>::is_lock_free());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeState {
    Uninit,
    InsertedLeft,
    InsertedRight,
    Removed,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WakerState {
    Init,
    Updating,
    Woken,
}

#[derive(Clone, Copy)]
struct ListsState(u64);

impl ListsState {
    const PROCESSED: usize = 0;
    const FLIP_FLOP_BIT: usize = 1;
    const MANAGEMENT_LOCK_BIT: usize = 2;
    const EXPIRE_LOCK_BIT: usize = 3;
    const TICK_BITS: RangeInclusive<usize> = 4..=63;

    pub const fn new() -> Self {
        Self(1 << Self::PROCESSED)
    }

    pub fn processed(&self) -> bool {
        self.0.get_bit(Self::PROCESSED)
    }

    pub fn set_processed(&mut self, processed: bool) {
        self.0.set_bit(Self::PROCESSED, processed);
    }

    pub fn flip_flop(&self) -> bool {
        self.0.get_bit(Self::FLIP_FLOP_BIT)
    }

    pub fn set_flip_flop(&mut self, flip_flop: bool) {
        self.0.set_bit(Self::FLIP_FLOP_BIT, flip_flop);
    }

    pub fn management_lock(&self) -> bool {
        self.0.get_bit(Self::MANAGEMENT_LOCK_BIT)
    }

    pub fn set_management_lock(&mut self, management_lock: bool) {
        self.0.set_bit(Self::MANAGEMENT_LOCK_BIT, management_lock);
    }

    pub fn expire_lock(&self) -> bool {
        self.0.get_bit(Self::EXPIRE_LOCK_BIT)
    }

    pub fn set_expire_lock(&mut self, expire_lock: bool) {
        self.0.set_bit(Self::EXPIRE_LOCK_BIT, expire_lock);
    }

    pub fn tick(&self) -> Tick {
        Tick::from_ns(self.0)
    }

    pub fn set_tick(&mut self, tick: Tick) {
        let ns = tick.into_ns();
        self.0
            .set_bits(Self::TICK_BITS, ns.get_bits(Self::TICK_BITS));
    }
}

impl core::fmt::Debug for ListsState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ListsState")
            .field("processed", &self.processed())
            .field("flip_flop", &self.flip_flop())
            .field("management_lock", &self.management_lock())
            .field("expire_lock", &self.expire_lock())
            .field("tick", &self.tick())
            .finish()
    }
}

struct AtomicListsState(AtomicU64);

impl AtomicListsState {
    pub const fn new(value: ListsState) -> Self {
        Self(AtomicU64::new(value.0))
    }

    pub fn load(&self, order: Ordering) -> ListsState {
        ListsState(self.0.load(order))
    }

    fn compare_exchange(
        &self,
        current: ListsState,
        new: ListsState,
        success: Ordering,
        failure: Ordering,
    ) -> Result<ListsState, ListsState> {
        self.0
            .compare_exchange(current.0, new.0, success, failure)
            .map(ListsState)
            .map_err(ListsState)
    }

    fn clear_expire_lock(&self, order: Ordering) {
        self.0.fetch_and(!(1 << ListsState::EXPIRE_LOCK_BIT), order);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tick(u64);

impl Tick {
    pub const ZERO: Self = Self::from_ns(0);

    const MASK: u64 = !0xF;
    const DIVISOR: u64 = (!Self::MASK + 1);

    pub const fn from_ns(ns: u64) -> Self {
        //  Mask off the low 4 bits.
        Self(ns & Self::MASK)
    }

    pub const fn into_ns(self) -> u64 {
        self.0
    }

    pub fn saturating_sub(self, rhs: Self) -> TickDelta {
        TickDelta(i64::try_from(self.0.saturating_sub(rhs.0)).unwrap())
    }
}

impl Add<TickDelta> for Tick {
    type Output = Self;

    fn add(self, rhs: TickDelta) -> Self::Output {
        Self(self.0.checked_add_signed(rhs.0).unwrap())
    }
}

impl Sub for Tick {
    type Output = TickDelta;

    fn sub(self, rhs: Self) -> Self::Output {
        TickDelta(i64::try_from(self.0).unwrap() - i64::try_from(rhs.0).unwrap())
    }
}

impl From<Tick> for Timespec {
    fn from(value: Tick) -> Self {
        Self::from(value - Tick::ZERO)
    }
}

// TODO: Can this just be From<>?
impl TryFrom<Timespec> for Tick {
    type Error = NegativeTickError;

    fn try_from(value: Timespec) -> Result<Self, Self::Error> {
        let delta = TickDelta::from(value);
        if delta.is_negative() {
            return Err(NegativeTickError(delta.as_nanos()));
        }
        Ok(Tick::ZERO + delta)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NegativeTickError(#[allow(dead_code)] i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TickDelta(i64);

impl TickDelta {
    pub const ZERO: Self = Self::new(0);

    const fn new(nanos: i64) -> Self {
        Self((nanos / Tick::DIVISOR as i64) * Tick::DIVISOR as i64)
    }

    pub const fn is_negative(self) -> bool {
        self.0.is_negative()
    }

    pub const fn as_nanos(self) -> i64 {
        self.0
    }

    pub const fn from_nanos(nanos: i64) -> Self {
        Self::new(nanos)
    }
}

impl Add for TickDelta {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl From<Timespec> for TickDelta {
    fn from(value: Timespec) -> Self {
        TickDelta::from_nanos(i64::from(value.tv_sec) * 1_000_000_000 + i64::from(value.tv_nsec))
    }
}

impl From<TickDelta> for Timespec {
    fn from(value: TickDelta) -> Self {
        Timespec::from_ns(value.as_nanos())
    }
}

/// Returns the smaller `Some` value or `None` if both are `None`.
fn zip_min<T>(lhs: Option<T>, rhs: Option<T>) -> Option<T>
where
    T: Ord,
{
    match (lhs, rhs) {
        (Some(lhs), Some(rhs)) => Some(cmp::min(lhs, rhs)),
        (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
        (None, None) => None,
    }
}
