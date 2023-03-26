//! This module contains a type to buffer AP logs into.
//! This ensures that logs are always emitted line by line and APs can't
//! interrupt each other's logs.

use constants::LOG_PORT;

use crate::ghcb::ioio_write;

pub struct LogBuffer {
    buffer: [u8; 256],
    cursor: usize,
}

impl LogBuffer {
    pub const fn new() -> Self {
        Self {
            buffer: [0; 256],
            cursor: 0,
        }
    }

    pub fn write(&mut self, c: char) {
        // Encode the char.
        let mut bytes = [0; 4];
        let str = c.encode_utf8(&mut bytes);

        // Write to the buffer.
        self.buffer[self.cursor..][..str.len()].copy_from_slice(str.as_bytes());
        self.cursor += str.len();

        let remaining = self.buffer.len() - self.cursor;
        if remaining < 4 || c == '\n' {
            self.flush();
        }
    }

    pub fn flush(&mut self) {
        let str = unsafe { core::str::from_utf8_unchecked(&self.buffer[..self.cursor]) };
        for c in str.chars() {
            ioio_write(LOG_PORT, u32::from(c));
        }
        self.cursor = 0;
    }
}
