use core::{cmp, num::NonZeroUsize, ops::Not};

use alloc::{collections::vec_deque::VecDeque, sync::Arc};
use usize_conversions::FromUsize;

use crate::{
    error::{Result, bail, ensure},
    rt::notify::{Notify, NotifyOnDrop},
    spin::mutex::Mutex,
    user::process::{memory::VirtualMemory, syscall::args::Pointer},
};

use super::{Events, PipeBlocked, ReadBuf, err};

pub fn new(capacity: usize, ty: Type) -> (ReadHalf, WriteHalf) {
    let buffer = Arc::new(PipeData {
        buffer: Mutex::new(PipeDataBuffer {
            ty,
            bytes: VecDeque::new(),
            capacity,
            read_shutdown: false,
            write_shutdown: false,
            reset: false,
            closed_socket_write_counter: 16,
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
    /// For sockets (not used for pipes):
    /// Whether the read half of a socket has been shut down.
    read_shutdown: bool,
    /// Whether the write half of a socket has been shut down.
    write_shutdown: bool,
    reset: bool,
    /// After the socket has been shut down, we allow a few more writes and
    /// then fail. This simulates the real world where the local system also
    /// doesn't immediately know that a socket has been shut down on the peer
    /// system.
    closed_socket_write_counter: u8,
    /// This field tracks the state of the mark for OOB data.
    oob_mark_state: OobMarkState,
}

impl PipeDataBuffer {
    fn total_capacity(&self) -> usize {
        // For sockets allow writing a little more than the capacity.
        let extra_capacity = match self.ty {
            Type::Pipe { .. } => 0,
            Type::Socket => 0x1000,
        };
        self.capacity.saturating_add(extra_capacity)
    }
}

pub enum Type {
    Pipe { atomic_write_size: NonZeroUsize },
    Socket,
}

impl Type {
    fn atomic_write_size(&self) -> usize {
        match self {
            Type::Pipe { atomic_write_size } => atomic_write_size.get(),
            Type::Socket => 1,
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
    pub fn take_oob_index(&mut self) -> Option<usize> {
        match self {
            OobMarkState::None => None,
            OobMarkState::Pending {
                remaining_length,
                read,
            } => core::mem::replace(read, true)
                .not()
                .then_some(*remaining_length),
        }
    }
}

pub struct ReadHalf {
    data: Arc<PipeData>,
    notify: NotifyOnDrop,
}

impl ReadHalf {
    pub fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        if buf.buffer_len() == 0 {
            return Ok(0);
        }

        let mut guard = self.data.buffer.lock();

        if guard.oob_mark_state.should_skip() {
            guard.bytes.pop_front().unwrap();
        }
        let mut len = buf.buffer_len();
        guard.oob_mark_state.clamp_read_length(&mut len);

        // Check if there is data to receive.
        if guard.bytes.is_empty() {
            // Check if the write half has been closed.
            if guard.read_shutdown || guard.write_shutdown {
                return Ok(0);
            }

            if Arc::strong_count(&self.data) == 1 {
                match guard.ty {
                    Type::Pipe { .. } => return Ok(0),
                    Type::Socket => bail!(ConnReset),
                }
            }

            bail!(Again);
        }
        let was_full =
            guard.capacity.saturating_sub(guard.bytes.len()) < guard.ty.atomic_write_size();

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

        // Remove the bytes from the VecDeque.
        guard.bytes.drain(..len);

        // Update the OOB mark.
        guard.oob_mark_state.update(len);

        if was_full {
            self.notify.notify();
        }

        Ok(len)
    }

    pub fn poll_ready(&self, events: Events) -> Events {
        let guard = self.data.buffer.lock();

        let mut ready_events = Events::empty();

        let strong_count = Arc::strong_count(&self.data);
        ready_events.set(
            Events::READ,
            !guard.bytes.is_empty()
                || strong_count == 1
                || guard.read_shutdown
                || guard.write_shutdown,
        );
        ready_events.set(
            Events::RDHUP,
            strong_count == 1 || guard.read_shutdown || guard.write_shutdown,
        );
        ready_events.set(Events::PRI, guard.oob_mark_state.pri_event());

        ready_events &= events;
        ready_events
    }

    pub fn wait(&self) -> impl Future<Output = ()> + '_ {
        self.notify.wait()
    }

    pub fn notify(&self) {
        self.notify.notify();
    }

    pub fn make_write_half(&self) -> WriteHalf {
        assert_eq!(Arc::strong_count(&self.data), 1);
        WriteHalf {
            data: self.data.clone(),
            notify: NotifyOnDrop(self.notify.0.clone()),
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

            if Arc::strong_count(&self.data) == 1 {
                match guard.ty {
                    Type::Pipe { .. } => return Ok(Ok(0)),
                    Type::Socket => bail!(ConnReset),
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
            self.notify();
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
        self.notify();
    }

    pub fn read_oob(&self) -> Result<u8> {
        let mut guard = self.data.buffer.lock();
        let index = guard.oob_mark_state.take_oob_index().ok_or(err!(Again))?;
        Ok(guard.bytes[index])
    }

    pub fn at_mark(&self) -> bool {
        let guard = self.data.buffer.lock();
        guard.oob_mark_state.at_mark()
    }
}

pub struct WriteHalf {
    data: Arc<PipeData>,
    notify: NotifyOnDrop,
}

impl WriteHalf {
    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut guard = self.data.buffer.lock();

        ensure!(!guard.reset, ConnReset);

        // Check if the write half has been closed.
        match guard.ty {
            Type::Pipe { .. } => ensure!(Arc::strong_count(&self.data) > 1, Pipe),
            Type::Socket => {
                ensure!(!guard.write_shutdown, ConnReset);
                if Arc::strong_count(&self.data) == 1 {
                    guard.reset = true;
                    return Ok(buf.len());
                }
            }
        }

        if buf.is_empty() {
            return Ok(0);
        }

        if guard.read_shutdown {
            let next = guard
                .closed_socket_write_counter
                .checked_sub(1)
                .ok_or(err!(Pipe))?;
            guard.closed_socket_write_counter = next;
            return Ok(buf.len());
        }

        if guard.oob_mark_state.should_skip() {
            guard.bytes.pop_front();
        }

        let atomic_write = buf.len() <= guard.ty.atomic_write_size();
        let remaining_capacity = guard.total_capacity().saturating_sub(guard.bytes.len());
        if atomic_write {
            ensure!(remaining_capacity >= buf.len(), Again);
        } else {
            ensure!(remaining_capacity > 0, Again);
        }
        let len = cmp::min(buf.len(), remaining_capacity);
        let buf = &buf[..len];

        guard.bytes.extend(buf.iter().copied());
        drop(guard);

        self.notify.notify();

        Ok(buf.len())
    }

    pub fn write_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        self.send_from_user(vm, pointer, len, false)
    }

    pub fn send_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
        oob: bool,
    ) -> Result<usize> {
        let mut guard = self.data.buffer.lock();

        ensure!(!guard.reset, ConnReset);

        // Check if the write half has been closed.
        match guard.ty {
            Type::Pipe { .. } => ensure!(Arc::strong_count(&self.data) > 1, Pipe),
            Type::Socket => {
                ensure!(!guard.write_shutdown, ConnReset);
                if Arc::strong_count(&self.data) == 1 {
                    guard.reset = true;
                    return Ok(len);
                }
            }
        }

        if len == 0 {
            return Ok(0);
        }

        if guard.read_shutdown {
            let next = guard
                .closed_socket_write_counter
                .checked_sub(1)
                .ok_or(err!(Pipe))?;
            guard.closed_socket_write_counter = next;
            return Ok(len);
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
            vm.read_bytes(pointer.get(), &mut second[second_len - len..])
        } else {
            let first_write_len = len - second.len();
            let first_len = first.len();
            vm.read_bytes(pointer.get(), &mut first[first_len - first_write_len..])
                .and_then(|_| {
                    vm.read_bytes(pointer.get() + u64::from_usize(first_write_len), second)
                })
        };

        // Rollback all bytes if an error occured.
        // FIXME: We should not roll back all bytes.
        if res.is_err() {
            guard.bytes.truncate(start_idx);
        }

        if oob {
            if let Some(remaining_length) = guard.bytes.len().checked_sub(1) {
                guard.oob_mark_state = OobMarkState::Pending {
                    remaining_length,
                    read: false,
                };
            }
        }

        drop(guard);

        res?;

        self.notify.notify();

        Ok(len)
    }

    pub fn poll_ready(&self, events: Events) -> Events {
        let mut ready_events = Events::empty();

        let guard = self.data.buffer.lock();
        let closed = guard.read_shutdown || guard.reset || Arc::strong_count(&self.data) == 1;
        ready_events.set(Events::WRITE, guard.bytes.len() < guard.capacity || closed);
        ready_events &= events;
        ready_events.set(Events::HUP, closed);
        ready_events.set(Events::ERR, closed);
        drop(guard);

        ready_events
    }

    pub async fn ready_for_write(&self, count: usize) -> Result<()> {
        loop {
            let wait = self.notify.wait();

            {
                let guard = self.data.buffer.lock();
                let is_atomic = count <= guard.ty.atomic_write_size();
                let remaining_capacity = guard.capacity.saturating_sub(guard.bytes.len());
                let can_write = if is_atomic {
                    count <= remaining_capacity
                } else {
                    0 < remaining_capacity
                };
                if can_write
                    || Arc::strong_count(&self.data) == 1
                    || guard.read_shutdown
                    || guard.reset
                {
                    break;
                }
            }

            wait.await;
        }

        Ok(())
    }

    pub fn wait(&self) -> impl Future<Output = ()> + '_ {
        self.notify.wait()
    }

    pub fn notify(&self) {
        self.notify.notify();
    }

    pub fn make_read_half(&self) -> ReadHalf {
        assert_eq!(Arc::strong_count(&self.data), 1);
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

        ensure!(!guard.reset, ConnReset);

        // Check if the write half has been closed.
        match guard.ty {
            Type::Pipe { .. } => ensure!(Arc::strong_count(&self.data) > 1, Pipe),
            Type::Socket => {
                ensure!(!guard.write_shutdown, ConnReset);
                if Arc::strong_count(&self.data) == 1 {
                    guard.reset = true;
                    return Ok(Ok(len));
                }
            }
        }

        if len == 0 {
            return Ok(Ok(0));
        }

        if guard.read_shutdown {
            let next = guard
                .closed_socket_write_counter
                .checked_sub(1)
                .ok_or(err!(Pipe))?;
            guard.closed_socket_write_counter = next;
            return Ok(Ok(len));
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

        self.notify();

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
        self.notify();
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
        if Arc::strong_count(&read_half.data) == 1 {
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
        read_half.notify();
    }
    write_half.notify();

    Ok(len)
}

pub enum SpliceBlockedError {
    /// The read half of the splice operation was blocked.
    Read,
    /// The write half of the splice operation was blocked.
    Write,
}
