use core::{cmp, future::Future, iter::from_fn, num::NonZeroUsize};

use alloc::{collections::vec_deque::VecDeque, sync::Arc};
use usize_conversions::FromUsize;

use crate::{
    error::{bail, ensure, Result},
    rt::notify::{Notify, NotifyOnDrop},
    spin::mutex::Mutex,
    user::process::{memory::VirtualMemory, syscall::args::Pointer},
};

use super::{Events, PipeBlocked};

pub fn new(capacity: usize, ty: Type) -> (ReadHalf, WriteHalf) {
    let buffer = Arc::new(PipeData {
        buffer: Mutex::new(PipeDataBuffer {
            ty,
            bytes: VecDeque::new(),
            capacity,
            shutdown: false,
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
    /// For sockets: Whether the socket-half has been shut down. This is not
    /// used for pipes.
    shutdown: bool,
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

    pub fn is_pipe(&self) -> bool {
        matches!(self, Self::Pipe { .. })
    }
}

pub struct ReadHalf {
    data: Arc<PipeData>,
    notify: NotifyOnDrop,
}

impl ReadHalf {
    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut guard = self.data.buffer.lock();

        // Check if there is data to receive.
        if guard.bytes.is_empty() {
            // Check if the write half has been closed.
            if Arc::strong_count(&self.data) == 1 || guard.shutdown {
                return Ok(0);
            }

            bail!(Again);
        }

        let was_full = guard.capacity - guard.bytes.len() < guard.ty.atomic_write_size();

        let mut read = 0;
        for (dest, src) in buf.iter_mut().zip(from_fn(|| guard.bytes.pop_front())) {
            *dest = src;
            read += 1;
        }

        if was_full {
            self.notify.notify();
        }

        Ok(read)
    }

    pub fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        if len == 0 {
            return Ok(0);
        }

        let mut guard = self.data.buffer.lock();

        // Check if there is data to receive.
        if guard.bytes.is_empty() {
            // Check if the write half has been closed.
            if Arc::strong_count(&self.data) == 1 || guard.shutdown {
                return Ok(0);
            }

            bail!(Again);
        }
        let was_full = guard.capacity - guard.bytes.len() < guard.ty.atomic_write_size();

        let len = cmp::min(len, guard.bytes.len());
        let (slice1, slice2) = guard.bytes.as_slices();
        let len1 = cmp::min(len, slice1.len());
        let len2 = len - len1;
        let slice1 = &slice1[..len1];
        let slice2 = &slice2[..len2];

        // Copy the bytes to userspace.
        vm.write_bytes(pointer.get(), slice1)?;
        if !slice2.is_empty() {
            vm.write_bytes(pointer.get() + u64::from_usize(len1), slice2)?;
        }

        // Remove the bytes from the VecDeque.
        guard.bytes.drain(..len);

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
            !guard.bytes.is_empty() || strong_count == 1 || guard.shutdown,
        );
        ready_events.set(Events::RDHUP, strong_count == 1 || guard.shutdown);

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
        len: usize,
        write: impl FnOnce(&mut VecDeque<u8>, usize),
    ) -> Result<Result<usize, PipeBlocked>> {
        let mut guard = self.data.buffer.lock();

        // Bail out early if there are no bytes to be copied.
        if guard.bytes.is_empty() {
            // Check if the write half has been closed.
            if Arc::strong_count(&self.data) == 1 || guard.shutdown {
                return Ok(Ok(0));
            }
            return Ok(Err(PipeBlocked));
        }

        let was_full = guard.capacity - guard.bytes.len() < guard.ty.atomic_write_size();

        let len = cmp::min(len, guard.bytes.len());
        let prev_len = guard.bytes.len();
        write(&mut guard.bytes, len);
        assert_eq!(guard.bytes.len(), prev_len - len);

        drop(guard);

        if was_full {
            self.notify();
        }

        Ok(Ok(len))
    }

    pub fn shutdown(&self) {
        let mut guard = self.data.buffer.lock();

        // Don't do anything if the stream buffer is already shutdown.
        if guard.shutdown {
            return;
        }

        guard.shutdown = true;
        self.notify();
    }
}

pub struct WriteHalf {
    data: Arc<PipeData>,
    notify: NotifyOnDrop,
}

impl WriteHalf {
    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        // Check if the write half has been closed.
        ensure!(Arc::strong_count(&self.data) > 1, Pipe);

        if buf.is_empty() {
            return Ok(0);
        }

        let mut guard = self.data.buffer.lock();
        ensure!(!guard.shutdown, Pipe);

        let atomic_write = buf.len() <= guard.ty.atomic_write_size();
        let remaining_capacity = guard.capacity - guard.bytes.len();
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
        // Check if the write half has been closed.
        ensure!(Arc::strong_count(&self.data) > 1, Pipe);

        if len == 0 {
            return Ok(0);
        }

        let mut guard = self.data.buffer.lock();
        ensure!(!guard.shutdown, Pipe);

        let atomic_write = len <= guard.ty.atomic_write_size();
        let remaining_capacity = guard.capacity - guard.bytes.len();
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

        drop(guard);

        res?;

        self.notify.notify();

        Ok(len)
    }

    pub fn poll_ready(&self, events: Events) -> Events {
        let mut ready_events = Events::empty();

        let guard = self.data.buffer.lock();
        let strong_count = Arc::strong_count(&self.data);
        ready_events.set(
            Events::WRITE,
            guard.bytes.len() < guard.capacity || strong_count == 1,
        );
        ready_events &= events;
        ready_events.set(Events::HUP, strong_count == 1);
        ready_events.set(Events::ERR, guard.ty.is_pipe() && strong_count == 1);
        drop(guard);

        ready_events
    }

    pub async fn ready_for_write(&self, count: usize) -> Result<()> {
        loop {
            let wait = self.notify.wait();

            {
                let guard = self.data.buffer.lock();
                let is_atomic = count <= guard.ty.atomic_write_size();
                let remaining_capacity = guard.capacity - guard.bytes.len();
                let can_write = if is_atomic {
                    count <= remaining_capacity
                } else {
                    0 < remaining_capacity
                };
                if can_write || Arc::strong_count(&self.data) == 1 || guard.shutdown {
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
        // Check if the write half has been closed.
        ensure!(Arc::strong_count(&self.data) > 1, Pipe);

        let mut guard = self.data.buffer.lock();

        let remaining_capacity = guard.capacity - guard.bytes.len();
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

    pub fn shutdown(&self) {
        let mut guard = self.data.buffer.lock();

        // Don't do anything if the stream buffer is already shutdown.
        if guard.shutdown {
            return;
        }

        guard.shutdown = true;
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

    let was_full = read_guard.capacity - read_guard.bytes.len() < read_guard.ty.atomic_write_size();

    // Make sure that the write half can receive at least one byte.
    let remaining_capacity = write_guard.capacity - write_guard.bytes.len();
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
