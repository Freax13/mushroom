//! This module implements a logger that stores the line in the xmm registers
//! before yielding to the supervisor. This is an easy way to store large
//! chunks of bytes without any shared memory.

use core::{
    arch::asm,
    fmt::{self, Write},
};

use constants::LOG_PORT;
use log::{Log, Metadata, Record};

pub struct FastLogger;

impl Log for FastLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        !matches!(
            metadata.target(),
            "kernel::exception" | "kernel::memory::pagetable"
        )
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let level_color = match record.level() {
            log::Level::Error => "\x1b[31;101m",
            log::Level::Warn => "\x1b[33;103m",
            log::Level::Info => "\x1b[34;104m",
            log::Level::Debug => "\x1b[32;102m",
            log::Level::Trace => "\x1b[35;105m",
        };
        let reset_color = "\x1b[0m";

        let mut buffer = Buffer::new();
        let _ = writeln!(
            buffer,
            "{level_color}[{:<5} {}:{}]{reset_color} {}",
            record.level(),
            record.file().unwrap_or("<unknown>"),
            record.line().unwrap_or(0),
            record.args(),
        );

        buffer.flush();
    }

    fn flush(&self) {}
}

#[repr(C, align(16))]
struct Buffer {
    buffer: [u8; 256],
    len: usize,
}

impl Buffer {
    pub fn new() -> Self {
        Self {
            buffer: [0; 256],
            len: 0,
        }
    }

    pub fn flush(&mut self) {
        if self.len == 0 {
            return;
        }

        unsafe {
            asm!(
                // Move the log buffer into the xmm registers.
                "movdqa  xmm0, xmmword ptr [{buffer} + 16 *  0]",
                "movdqa  xmm1, xmmword ptr [{buffer} + 16 *  1]",
                "movdqa  xmm2, xmmword ptr [{buffer} + 16 *  2]",
                "movdqa  xmm3, xmmword ptr [{buffer} + 16 *  3]",
                "movdqa  xmm4, xmmword ptr [{buffer} + 16 *  4]",
                "movdqa  xmm5, xmmword ptr [{buffer} + 16 *  5]",
                "movdqa  xmm6, xmmword ptr [{buffer} + 16 *  6]",
                "movdqa  xmm7, xmmword ptr [{buffer} + 16 *  7]",
                "movdqa  xmm8, xmmword ptr [{buffer} + 16 *  8]",
                "movdqa  xmm9, xmmword ptr [{buffer} + 16 *  9]",
                "movdqa xmm10, xmmword ptr [{buffer} + 16 * 10]",
                "movdqa xmm11, xmmword ptr [{buffer} + 16 * 11]",
                "movdqa xmm12, xmmword ptr [{buffer} + 16 * 12]",
                "movdqa xmm13, xmmword ptr [{buffer} + 16 * 13]",
                "movdqa xmm14, xmmword ptr [{buffer} + 16 * 14]",
                "movdqa xmm15, xmmword ptr [{buffer} + 16 * 15]",
                // Trigger an IOIO #VC exception to start the transfer.
                "out dx, eax",
                buffer = in(reg) self.buffer.as_ptr(),
                in("rdx") LOG_PORT,
                in("eax") self.len,
            );
        }

        self.len = 0;
    }
}

impl Write for Buffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        s.chars().try_for_each(|c| self.write_char(c))
    }

    fn write_char(&mut self, c: char) -> fmt::Result {
        // Ensure that there space available to encode the next byte.
        if self.len + 4 >= self.buffer.len() {
            self.flush();
        }

        let buffer = &mut self.buffer[self.len..];

        let encoded = c.encode_utf8(buffer);
        self.len += encoded.len();

        Ok(())
    }
}
