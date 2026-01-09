use alloc::{collections::vec_deque::VecDeque, sync::Arc};
use core::{
    cmp,
    num::NonZeroUsize,
    sync::atomic::{AtomicU8, Ordering},
};

use crate::{
    error::{Result, bail, ensure},
    fs::fd::{
        Events, NonEmptyEvents, PipeBlocked, ReadBuf, WriteBuf,
        epoll::{EpollResult, EventCounter},
        err,
    },
    rt::notify::{Notify, NotifyOnDrop},
    spin::mutex::Mutex,
};

pub fn new(capacity: usize, ty: Type) -> (ReadHalf, WriteHalf) {
    let buffer = Arc::new(PipeData {
        buffer: Mutex::new(PipeDataBuffer {
            ty,
            bytes: VecDeque::new(),
            capacity,
            half_closed: false,
            read_event_counter: EventCounter::new(),
            hup_event_counter: EventCounter::new(),
            write_event_counter: EventCounter::new(),
            err_event_counter: EventCounter::new(),
            read_shutdown: false,
            write_shutdown: false,
            write_read_shutdown: false,
            oob_mark_state: OobMarkState::None,
        }),
    });
    let notify = Arc::new(Notify::new());
    (
        ReadHalf {
            data: buffer.clone(),
            notify: NotifyOnDrop(notify.clone()),
        },
        WriteHalf {
            data: buffer,
            notify: NotifyOnDrop(notify),
        },
    )
}

struct PipeData {
    buffer: Mutex<PipeDataBuffer>,
}

struct PipeDataBuffer {
    ty: Type,
    bytes: VecDeque<u8>,
    capacity: usize,
    half_closed: bool,
    read_event_counter: EventCounter,
    hup_event_counter: EventCounter,
    write_event_counter: EventCounter,
    err_event_counter: EventCounter,
    /// For sockets (not used for pipes):
    /// Whether the read half of a socket has been shut down.
    read_shutdown: bool,
    /// Whether the write half of a socket has been shut down.
    write_shutdown: bool,
    /// Whether the socket whose read half this is has had its read write shut down.
    write_read_shutdown: bool,
    /// This field tracks the state of the mark for OOB data.
    oob_mark_state: OobMarkState,
}

impl PipeDataBuffer {
    fn total_capacity(&self) -> usize {
        // For sockets allow writing a little more than the capacity.
        let extra_capacity = match self.ty {
            Type::Pipe { .. } => 0,
            Type::Socket { .. } => 0x1000,
        };
        self.capacity.saturating_add(extra_capacity)
    }
}

pub enum Type {
    Pipe {
        atomic_write_size: NonZeroUsize,
    },
    Socket {
        read_reset: Arc<ConnectionState>,
        write_reset: Arc<ConnectionState>,
    },
}

impl Type {
    fn atomic_write_size(&self) -> usize {
        match self {
            Type::Pipe { atomic_write_size } => atomic_write_size.get(),
            Type::Socket { .. } => 1,
        }
    }

    fn is_either_reset(&self) -> bool {
        match self {
            Self::Pipe { .. } => false,
            Self::Socket {
                read_reset,
                write_reset,
            } => read_reset.was_ever_reset() || write_reset.was_ever_reset(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum OobMarkState {
    None,
    Pending { remaining_length: usize, read: bool },
}

impl OobMarkState {
    /// Returns whether the buffer is at the OOB mark.
    pub fn at_mark(&self) -> bool {
        match *self {
            Self::None => false,
            Self::Pending {
                remaining_length, ..
            } => remaining_length == 0,
        }
    }

    /// Returns whether there's a pending OOB byte.
    pub fn pri_event(&self) -> bool {
        match self {
            Self::None => false,
            Self::Pending { read, .. } => !read,
        }
    }

    /// Returns whether an OOB byte needs to be skipped in preparation of a
    /// read or write operation.
    pub fn should_skip(&mut self) -> bool {
        let at_mark = self.at_mark();
        if at_mark {
            *self = OobMarkState::None;
        }
        at_mark
    }

    /// Clamp the number of bytes returned in reads, so that they don't skip
    /// over OOB data.
    pub fn clamp_read_length(&mut self, len: &mut usize) {
        if let OobMarkState::Pending {
            remaining_length, ..
        } = *self
        {
            *len = cmp::min(*len, remaining_length);
        }
    }

    /// Update the index of OOB data following a read of `read` bytes.
    pub fn update(&mut self, read: usize) {
        if let OobMarkState::Pending {
            remaining_length, ..
        } = self
        {
            *remaining_length -= read;
        }
    }

    /// Returns the index of the OOB mark iff it hasn't already been read.
    pub fn take_oob_index(&mut self, peek: bool) -> Option<usize> {
        match self {
            OobMarkState::None => None,
            OobMarkState::Pending {
                remaining_length,
                read,
            } => {
                if *read {
                    return None;
                }
                if !peek {
                    *read = true;
                }
                Some(*remaining_length)
            }
        }
    }
}

pub struct ReadHalf {
    data: Arc<PipeData>,
    notify: NotifyOnDrop,
}

impl ReadHalf {
    pub fn read(&self, buf: &mut dyn ReadBuf, peek: bool, waitall: bool) -> Result<usize> {
        if buf.buffer_len() == 0 {
            return Ok(0);
        }

        let mut guard = self.data.buffer.lock();

        if guard.oob_mark_state.should_skip() {
            guard.bytes.pop_front().unwrap();
        }
        let mut len = buf.buffer_len();

        // Check if there is data to receive.
        if guard.bytes.is_empty() {
            match &guard.ty {
                Type::Pipe { .. } => {
                    ensure!(guard.half_closed, Again);
                    return Ok(0);
                }
                Type::Socket { read_reset, .. } => {
                    ensure!(!read_reset.take_reset().0, ConnReset);

                    // Check if the write half has been closed.
                    if guard.read_shutdown || guard.write_shutdown {
                        return Ok(0);
                    }
                    ensure!(!guard.half_closed, ConnReset);
                    bail!(Again);
                }
            }
        }
        let was_full =
            guard.capacity.saturating_sub(guard.bytes.len()) < guard.ty.atomic_write_size();

        let old_len = len;
        guard.oob_mark_state.clamp_read_length(&mut len);
        let clamped = old_len != len;

        if !clamped && waitall {
            ensure!(guard.bytes.len() >= len, Again);
        }

        let len = cmp::min(len, guard.bytes.len());
        let (slice1, slice2) = guard.bytes.as_slices();
        let len1 = cmp::min(len, slice1.len());
        let len2 = len - len1;
        let slice1 = &slice1[..len1];
        let slice2 = &slice2[..len2];

        // Copy the bytes to userspace.
        buf.write(0, slice1)?;
        if !slice2.is_empty() {
            buf.write(len1, slice2)?;
        }

        if !peek {
            // Remove the bytes from the VecDeque.
            guard.bytes.drain(..len);

            // Update the OOB mark.
            guard.oob_mark_state.update(len);

            if was_full {
                guard.write_event_counter.inc();
                self.notify.notify();
            }
            if guard.bytes.is_empty() {
                guard.read_event_counter.inc();
                self.notify.notify();
            }
        }

        Ok(len)
    }

    pub fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        let guard = self.data.buffer.lock();

        let mut ready_events = Events::empty();

        ready_events.set(
            Events::READ,
            !guard.bytes.is_empty()
                || guard.half_closed
                || guard.read_shutdown
                || guard.write_shutdown,
        );
        ready_events.set(
            Events::HUP,
            guard.half_closed || guard.read_shutdown || guard.write_shutdown,
        );
        ready_events.set(Events::PRI, guard.oob_mark_state.pri_event());

        ready_events &= events;
        NonEmptyEvents::new(ready_events)
    }

    pub fn epoll_ready(&self) -> EpollResult {
        let mut result = EpollResult::new();

        let guard = self.data.buffer.lock();

        if !guard.bytes.is_empty()
            || guard.half_closed
            || guard.read_shutdown
            || guard.write_shutdown
        {
            result.set_ready(Events::READ);
        }
        if guard.half_closed || guard.read_shutdown || guard.write_shutdown {
            result.set_ready(Events::HUP);
        }
        if guard.oob_mark_state.pri_event() {
            result.set_ready(Events::PRI);
        }

        result.add_counter(Events::READ, &guard.read_event_counter);
        result.add_counter(Events::HUP, &guard.hup_event_counter);

        result
    }

    pub fn notify(&self) -> &Notify {
        &self.notify
    }

    pub fn make_write_half(&self) -> WriteHalf {
        let mut guard = self.data.buffer.lock();
        assert!(guard.half_closed);
        guard.half_closed = false;
        drop(guard);

        WriteHalf {
            data: self.data.clone(),
            notify: self.notify.clone(),
        }
    }

    pub fn splice_to(
        &self,
        mut len: usize,
        write: impl FnOnce(&mut VecDeque<u8>, usize),
    ) -> Result<Result<usize, PipeBlocked>> {
        let mut guard = self.data.buffer.lock();

        if guard.oob_mark_state.should_skip() {
            guard.bytes.pop_front().unwrap();
        }
        guard.oob_mark_state.clamp_read_length(&mut len);

        // Bail out early if there are no bytes to be copied.
        if guard.bytes.is_empty() {
            // Check if the write half has been closed.
            if guard.read_shutdown || guard.write_shutdown {
                return Ok(Ok(0));
            }

            if guard.half_closed {
                match guard.ty {
                    Type::Pipe { .. } => return Ok(Ok(0)),
                    Type::Socket { .. } => bail!(ConnReset),
                }
            }

            return Ok(Err(PipeBlocked));
        }

        let was_full =
            guard.capacity.saturating_sub(guard.bytes.len()) < guard.ty.atomic_write_size();

        let len = cmp::min(len, guard.bytes.len());
        let prev_len = guard.bytes.len();
        write(&mut guard.bytes, len);
        assert_eq!(guard.bytes.len(), prev_len - len);

        // Update the OOB mark.
        guard.oob_mark_state.update(len);

        drop(guard);

        if was_full {
            self.notify().notify();
        }

        Ok(Ok(len))
    }

    pub fn shutdown(&self) {
        let mut guard = self.data.buffer.lock();

        // Don't do anything if the stream buffer is already shutdown.
        if guard.read_shutdown {
            return;
        }

        guard.read_shutdown = true;
        guard.write_event_counter.inc();
        self.notify().notify();
    }

    pub fn write_shutdown(&self) {
        let mut guard = self.data.buffer.lock();
        guard.write_read_shutdown = true;
        self.notify().notify();
    }

    /// Close the read half.
    ///
    /// Returns `true` if there are remaining bytes in the buffer.
    pub fn close(&self) -> bool {
        let mut guard = self.data.buffer.lock();

        // The socket will not be shut down if there are still unread bytes.
        if !guard.bytes.is_empty() {
            return true;
        }

        guard.read_shutdown = true;
        guard.write_event_counter.inc();
        self.notify().notify();

        false
    }

    pub fn read_oob(&self, peek: bool) -> Result<u8> {
        let mut guard = self.data.buffer.lock();
        let index = guard
            .oob_mark_state
            .take_oob_index(peek)
            .ok_or(err!(Again))?;
        Ok(guard.bytes[index])
    }

    pub fn at_mark(&self) -> bool {
        let guard = self.data.buffer.lock();
        guard.oob_mark_state.at_mark()
    }
}

impl Drop for ReadHalf {
    fn drop(&mut self) {
        let mut guard = self.data.buffer.lock();
        guard.half_closed = true;
        guard.write_event_counter.inc();
        guard.err_event_counter.inc();
        drop(guard);
        self.notify.notify();
    }
}

pub struct WriteHalf {
    data: Arc<PipeData>,
    notify: NotifyOnDrop,
}

impl WriteHalf {
    pub fn write(&self, buf: &dyn WriteBuf) -> Result<usize> {
        self.send(buf, false)
    }

    pub fn send(&self, buf: &dyn WriteBuf, oob: bool) -> Result<usize> {
        let mut guard = self.data.buffer.lock();

        // Check if the write half has been closed.
        match &guard.ty {
            Type::Pipe { .. } => ensure!(!guard.half_closed, Pipe),
            Type::Socket {
                read_reset,
                write_reset,
            } => {
                let (_, ever_reset) = write_reset.take_reset();
                ensure!(!ever_reset, ConnReset);
                ensure!(!read_reset.was_ever_reset(), Pipe);
                ensure!(!guard.write_shutdown, Pipe);
                if guard.half_closed {
                    write_reset.reset();
                    return Ok(cmp::min(buf.buffer_len(), guard.total_capacity()));
                }
                if guard.read_shutdown && guard.write_read_shutdown {
                    read_reset.reset();
                    return Ok(cmp::min(buf.buffer_len(), guard.total_capacity()));
                }
            }
        }

        let len = buf.buffer_len();
        if len == 0 {
            return Ok(0);
        }

        if guard.oob_mark_state.should_skip() {
            guard.bytes.pop_front();
        }

        let atomic_write = len <= guard.ty.atomic_write_size();
        let remaining_capacity = guard.total_capacity().saturating_sub(guard.bytes.len());
        if atomic_write {
            ensure!(remaining_capacity >= len, Again);
        } else {
            ensure!(remaining_capacity > 0, Again);
        }
        let len = cmp::min(len, remaining_capacity);

        let start_idx = guard.bytes.len();
        // Reserve some space for the new bytes.
        guard.bytes.resize(start_idx + len, 0);

        let (first, second) = guard.bytes.as_mut_slices();
        let res = if second.len() >= len {
            let second_len = second.len();
            buf.read(0, &mut second[second_len - len..])
        } else {
            let first_write_len = len - second.len();
            let first_len = first.len();
            buf.read(0, &mut first[first_len - first_write_len..])
                .and_then(|_| buf.read(first_write_len, second))
        };

        // Rollback all bytes if an error occured.
        // FIXME: We should not roll back all bytes.
        if res.is_err() {
            guard.bytes.truncate(start_idx);
        }
        res?;

        if oob && let Some(remaining_length) = guard.bytes.len().checked_sub(1) {
            guard.oob_mark_state = OobMarkState::Pending {
                remaining_length,
                read: false,
            };
        }

        guard.read_event_counter.inc();

        drop(guard);

        self.notify.notify();

        Ok(len)
    }

    pub fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        let mut ready_events = Events::empty();

        let guard = self.data.buffer.lock();
        let reset = guard.ty.is_either_reset();
        ready_events.set(
            Events::WRITE,
            guard.bytes.len() < guard.capacity || guard.read_shutdown || reset || guard.half_closed,
        );
        ready_events &= events;
        ready_events.set(Events::ERR, reset || guard.half_closed);
        drop(guard);

        NonEmptyEvents::new(ready_events)
    }

    pub async fn ready_for_write(&self, count: usize) {
        self.notify
            .wait_until(|| {
                let guard = self.data.buffer.lock();
                let is_atomic = count <= guard.ty.atomic_write_size();
                let remaining_capacity = guard.capacity.saturating_sub(guard.bytes.len());
                let can_write = if is_atomic {
                    count <= remaining_capacity
                } else {
                    0 < remaining_capacity
                };
                (can_write
                    || guard.half_closed
                    || guard.read_shutdown
                    || guard.ty.is_either_reset())
                .then_some(())
            })
            .await
    }

    pub fn epoll_ready(&self) -> EpollResult {
        let mut result = EpollResult::new();
        let guard = self.data.buffer.lock();
        let reset = guard.ty.is_either_reset();
        if guard.bytes.len() < guard.capacity || guard.read_shutdown || reset || guard.half_closed {
            result.set_ready(Events::WRITE);
        }
        if reset || guard.half_closed {
            result.set_ready(Events::ERR);
        }

        result.add_counter(Events::WRITE, &guard.write_event_counter);
        result.add_counter(Events::ERR, &guard.err_event_counter);

        result
    }

    pub fn notify(&self) -> &Notify {
        &self.notify
    }

    pub fn make_read_half(&self) -> ReadHalf {
        let mut guard = self.data.buffer.lock();
        assert!(guard.half_closed);
        guard.half_closed = false;
        drop(guard);

        ReadHalf {
            data: self.data.clone(),
            notify: NotifyOnDrop(self.notify.0.clone()),
        }
    }

    pub fn splice_from(
        &self,
        len: usize,
        read: impl FnOnce(&mut VecDeque<u8>, usize),
    ) -> Result<Result<usize, PipeBlocked>> {
        let mut guard = self.data.buffer.lock();

        // Check if the write half has been closed.
        match &guard.ty {
            Type::Pipe { .. } => ensure!(!guard.half_closed, Pipe),
            Type::Socket {
                read_reset,
                write_reset,
            } => {
                ensure!(!write_reset.was_ever_reset(), ConnReset);
                let (_, ever_reset) = read_reset.take_reset();
                ensure!(!ever_reset, Pipe);
                ensure!(!guard.write_shutdown, Pipe);
                if guard.half_closed {
                    write_reset.reset();
                    return Ok(Ok(cmp::min(len, guard.total_capacity())));
                }
                if guard.read_shutdown && guard.write_read_shutdown {
                    read_reset.reset();
                    return Ok(Ok(cmp::min(len, guard.total_capacity())));
                }
            }
        }

        if len == 0 {
            return Ok(Ok(0));
        }

        if guard.oob_mark_state.should_skip() {
            guard.bytes.pop_front();
        }

        let remaining_capacity = guard.total_capacity().saturating_sub(guard.bytes.len());
        if remaining_capacity == 0 {
            return Ok(Err(PipeBlocked));
        }

        let len = cmp::min(len, remaining_capacity);

        let prev_len = guard.bytes.len();

        read(&mut guard.bytes, len);

        debug_assert_eq!(guard.bytes.len(), prev_len + len);

        drop(guard);

        self.notify().notify();

        Ok(Ok(len))
    }

    pub fn set_buffer_capacity(&self, capacity: usize) {
        let mut guard = self.data.buffer.lock();
        guard.capacity = capacity;
    }

    pub fn shutdown(&self) {
        let mut guard = self.data.buffer.lock();

        // Don't do anything if the stream buffer is already shutdown.
        if guard.write_shutdown {
            return;
        }

        guard.write_shutdown = true;
        self.notify().notify();
    }
}

impl Drop for WriteHalf {
    fn drop(&mut self) {
        let mut guard = self.data.buffer.lock();
        guard.half_closed = true;
        guard.read_event_counter.inc();
        guard.hup_event_counter.inc();
        drop(guard);
    }
}

pub fn splice(
    read_half: &ReadHalf,
    write_half: &WriteHalf,
    len: usize,
) -> Result<usize, SpliceBlockedError> {
    if Arc::ptr_eq(&read_half.data, &write_half.data) {
        todo!()
    }

    let (mut read_guard, mut write_guard) = read_half.data.buffer.lock_two(&write_half.data.buffer);
    // Bail out early if there are no bytes to be copied.
    if read_guard.bytes.is_empty() {
        // Check if the write half has been closed.
        if read_guard.half_closed {
            return Ok(0);
        }
        return Err(SpliceBlockedError::Read);
    }

    let was_full = read_guard.capacity.saturating_sub(read_guard.bytes.len())
        < read_guard.ty.atomic_write_size();

    // Make sure that the write half can receive at least one byte.
    let remaining_capacity = write_guard
        .total_capacity()
        .saturating_sub(write_guard.bytes.len());
    if remaining_capacity == 0 {
        return Err(SpliceBlockedError::Write);
    }

    // Determine the number of bytes to be copied.
    let len = cmp::min(len, read_guard.bytes.len());
    let len = cmp::min(len, remaining_capacity);

    // Copy the bytes.
    write_guard.bytes.extend(read_guard.bytes.drain(..len));

    drop(read_guard);
    drop(write_guard);

    if was_full {
        read_half.notify().notify();
    }
    write_half.notify().notify();

    Ok(len)
}

pub enum SpliceBlockedError {
    /// The read half of the splice operation was blocked.
    Read,
    /// The write half of the splice operation was blocked.
    Write,
}

pub struct ConnectionState(AtomicU8);

impl ConnectionState {
    const RESET: u8 = 1 << 0;
    const EVER_RESET: u8 = 1 << 1;

    pub const fn new() -> Self {
        Self(AtomicU8::new(0))
    }

    pub fn reset(&self) {
        self.0
            .fetch_or(Self::RESET | Self::EVER_RESET, Ordering::SeqCst);
    }

    /// Returns a tuple of (reset, ever_reset).
    pub fn take_reset(&self) -> (bool, bool) {
        let prev = self.0.fetch_and(!Self::RESET, Ordering::SeqCst);
        (prev & Self::RESET != 0, prev & Self::EVER_RESET != 0)
    }

    pub fn was_ever_reset(&self) -> bool {
        self.0.load(Ordering::SeqCst) & Self::EVER_RESET != 0
    }
}
