use core::{cmp, future::Future, iter::from_fn};

use alloc::{collections::vec_deque::VecDeque, sync::Arc};
use usize_conversions::FromUsize;

use crate::{
    error::{bail, ensure, Result},
    rt::notify::{Notify, NotifyOnDrop},
    spin::mutex::Mutex,
    user::process::{memory::VirtualMemory, syscall::args::Pointer},
};

use super::Events;

pub fn new<const MAX_CAPACITY: usize, const ATOMIC_WRITE_SIZE: usize>() -> (
    ReadHalf<MAX_CAPACITY, ATOMIC_WRITE_SIZE>,
    WriteHalf<MAX_CAPACITY, ATOMIC_WRITE_SIZE>,
) {
    let buffer = Arc::new(Mutex::new(VecDeque::new()));
    let notify = Arc::new(Notify::new());
    (
        ReadHalf {
            buffer: buffer.clone(),
            notify: NotifyOnDrop(notify.clone()),
        },
        WriteHalf {
            buffer,
            notify: NotifyOnDrop(notify),
        },
    )
}

pub struct ReadHalf<const MAX_CAPACITY: usize, const ATOMIC_WRITE_SIZE: usize> {
    buffer: Arc<Mutex<VecDeque<u8>>>,
    notify: NotifyOnDrop,
}

impl<const CAPACITY: usize, const ATOMIC_WRITE_SIZE: usize> ReadHalf<CAPACITY, ATOMIC_WRITE_SIZE> {
    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut guard = self.buffer.lock();

        // Check if there is data to receive.
        if guard.is_empty() {
            // Check if the write half has been closed.
            if Arc::strong_count(&self.buffer) == 1 {
                return Ok(0);
            }

            bail!(Again);
        }

        let was_full = CAPACITY - guard.len() < ATOMIC_WRITE_SIZE;

        let mut read = 0;
        for (dest, src) in buf.iter_mut().zip(from_fn(|| guard.pop_front())) {
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

        let mut guard = self.buffer.lock();

        // Check if there is data to receive.
        if guard.is_empty() {
            // Check if the write half has been closed.
            if Arc::strong_count(&self.buffer) == 1 {
                return Ok(0);
            }

            bail!(Again);
        }
        let was_full = CAPACITY - guard.len() < ATOMIC_WRITE_SIZE;

        let len = cmp::min(len, guard.len());
        let (slice1, slice2) = guard.as_slices();
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
        guard.drain(..len);

        if was_full {
            self.notify.notify();
        }

        Ok(len)
    }

    pub fn poll_ready(&self, events: Events) -> Events {
        let guard = self.buffer.lock();

        let mut ready_events = Events::empty();

        let strong_count = Arc::strong_count(&self.buffer);
        ready_events.set(Events::READ, !guard.is_empty() || strong_count == 1);
        ready_events.set(Events::HUP, strong_count == 1);

        ready_events &= events;
        ready_events
    }

    pub fn wait(&self) -> impl Future<Output = ()> + '_ {
        self.notify.wait()
    }
}

pub struct WriteHalf<const CAPACITY: usize, const ATOMIC_WRITE_SIZE: usize> {
    buffer: Arc<Mutex<VecDeque<u8>>>,
    notify: NotifyOnDrop,
}

impl<const CAPACITY: usize, const ATOMIC_WRITE_SIZE: usize> WriteHalf<CAPACITY, ATOMIC_WRITE_SIZE> {
    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        // Check if the write half has been closed.
        ensure!(Arc::strong_count(&self.buffer) > 1, Pipe);

        if buf.is_empty() {
            return Ok(0);
        }

        let mut guard = self.buffer.lock();

        let atomic_write = buf.len() <= ATOMIC_WRITE_SIZE;
        let max_remaining_capacity = CAPACITY - guard.len();
        if atomic_write {
            ensure!(max_remaining_capacity >= buf.len(), Again);
        } else {
            ensure!(max_remaining_capacity > 0, Again);
        }
        let len = cmp::min(buf.len(), max_remaining_capacity);
        let buf = &buf[..len];

        guard.extend(buf.iter().copied());
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
        ensure!(Arc::strong_count(&self.buffer) > 1, Pipe);

        if len == 0 {
            return Ok(0);
        }

        let mut guard = self.buffer.lock();

        let atomic_write = len <= ATOMIC_WRITE_SIZE;
        let max_remaining_capacity = CAPACITY - guard.len();
        if atomic_write {
            ensure!(max_remaining_capacity >= len, Again);
        } else {
            ensure!(max_remaining_capacity > 0, Again);
        }
        let len = cmp::min(len, max_remaining_capacity);

        let start_idx = guard.len();
        // Reserve some space for the new bytes.
        guard.resize(start_idx + len, 0);

        let (first, second) = guard.as_mut_slices();
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
            guard.truncate(start_idx);
        }

        drop(guard);

        res?;

        self.notify.notify();

        Ok(len)
    }

    pub fn poll_ready(&self, events: Events) -> Events {
        let mut ready_events = Events::empty();

        let guard = self.buffer.lock();
        let strong_count = Arc::strong_count(&self.buffer);
        ready_events.set(Events::WRITE, guard.len() < CAPACITY || strong_count == 1);
        ready_events.set(Events::ERR, strong_count == 1);
        drop(guard);

        ready_events &= events;
        ready_events
    }

    pub async fn ready_for_write(&self, count: usize) -> Result<()> {
        let is_atomic = count <= ATOMIC_WRITE_SIZE;

        loop {
            let wait = self.notify.wait();

            {
                let guard = self.buffer.lock();
                let max_remaining_capacity = CAPACITY - guard.len();
                let can_write = if is_atomic {
                    count <= max_remaining_capacity
                } else {
                    0 < max_remaining_capacity
                };
                if can_write || Arc::strong_count(&self.buffer) == 1 {
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
}
