#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::new_without_default)]

#[cfg(feature = "std")]
use core::str::from_utf8;
use core::{
    fmt::Write,
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
};

const BUFFER_SIZE: usize = 0x10000 - 16;

#[repr(C)]
pub struct LogBuffer {
    pending_index: AtomicUsize,
    completed_index: AtomicUsize,
    buffer: [AtomicU8; BUFFER_SIZE],
}

impl LogBuffer {
    pub const fn new() -> Self {
        Self {
            pending_index: AtomicUsize::new(0),
            completed_index: AtomicUsize::new(0),
            buffer: [const { AtomicU8::new(0) }; BUFFER_SIZE],
        }
    }
}

pub struct LogWriter {
    buffer: &'static LogBuffer,
}

impl LogWriter {
    pub const fn new(buffer: &'static LogBuffer) -> Self {
        Self { buffer }
    }
}

impl Write for LogWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let mut pending_index = self.buffer.pending_index.load(Ordering::SeqCst);
        let mut completed_index = self.buffer.completed_index.load(Ordering::SeqCst);

        for b in s.as_bytes().iter().copied() {
            let mut next_pending_index = pending_index + 1;
            if next_pending_index == BUFFER_SIZE {
                next_pending_index = 0;
            }

            while next_pending_index == completed_index {
                completed_index = self.buffer.completed_index.load(Ordering::SeqCst);
            }

            self.buffer.buffer[pending_index].store(b, Ordering::SeqCst);

            pending_index = next_pending_index;
        }

        self.buffer
            .pending_index
            .store(pending_index, Ordering::SeqCst);

        Ok(())
    }
}

pub struct LogReader<'a> {
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    buffer: &'a LogBuffer,
}

impl<'a> LogReader<'a> {
    pub const fn new(buffer: &'a LogBuffer) -> Self {
        Self { buffer }
    }

    #[cfg(feature = "std")]
    pub fn read_line(&mut self, buffer: &mut String) {
        use core::time::Duration;

        let mut buf = [0; 4];
        let mut buf_index = 0;

        let mut pending_index = self.buffer.pending_index.load(Ordering::SeqCst);
        let mut completed_index = self.buffer.completed_index.load(Ordering::SeqCst);

        loop {
            while pending_index == completed_index {
                std::thread::sleep(Duration::from_millis(1));
                pending_index = self.buffer.pending_index.load(Ordering::SeqCst);
            }

            let value = self.buffer.buffer[completed_index].load(Ordering::Relaxed);
            buf[buf_index] = value;
            buf_index += 1;

            completed_index += 1;
            if completed_index == BUFFER_SIZE {
                completed_index = 0;
            }

            let buf = &buf[..buf_index];
            if let Ok(s) = from_utf8(buf) {
                self.buffer
                    .completed_index
                    .store(completed_index, Ordering::Relaxed);

                if s == "\n" {
                    return;
                } else {
                    buffer.push_str(s);
                    buf_index = 0;
                }
            }
        }
    }
}
