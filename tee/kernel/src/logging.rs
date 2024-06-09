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

        let mut scratch = [0u8; 512];
        unsafe {
            asm!(
                // Save all ymm registers.
                "vmovdqu ymmword ptr [{scratch} + 32 *  0],  ymm0",
                "vmovdqu ymmword ptr [{scratch} + 32 *  1],  ymm1",
                "vmovdqu ymmword ptr [{scratch} + 32 *  2],  ymm2",
                "vmovdqu ymmword ptr [{scratch} + 32 *  3],  ymm3",
                "vmovdqu ymmword ptr [{scratch} + 32 *  4],  ymm4",
                "vmovdqu ymmword ptr [{scratch} + 32 *  5],  ymm5",
                "vmovdqu ymmword ptr [{scratch} + 32 *  6],  ymm6",
                "vmovdqu ymmword ptr [{scratch} + 32 *  7],  ymm7",
                "vmovdqu ymmword ptr [{scratch} + 32 *  8],  ymm8",
                "vmovdqu ymmword ptr [{scratch} + 32 *  9],  ymm9",
                "vmovdqu ymmword ptr [{scratch} + 32 * 10], ymm10",
                "vmovdqu ymmword ptr [{scratch} + 32 * 11], ymm11",
                "vmovdqu ymmword ptr [{scratch} + 32 * 12], ymm12",
                "vmovdqu ymmword ptr [{scratch} + 32 * 13], ymm13",
                "vmovdqu ymmword ptr [{scratch} + 32 * 14], ymm14",
                "vmovdqu ymmword ptr [{scratch} + 32 * 15], ymm15",
                // Move the log buffer into the xmm registers.
                "movdqu  xmm0, xmmword ptr [{buffer} + 16 *  0]",
                "movdqu  xmm1, xmmword ptr [{buffer} + 16 *  1]",
                "movdqu  xmm2, xmmword ptr [{buffer} + 16 *  2]",
                "movdqu  xmm3, xmmword ptr [{buffer} + 16 *  3]",
                "movdqu  xmm4, xmmword ptr [{buffer} + 16 *  4]",
                "movdqu  xmm5, xmmword ptr [{buffer} + 16 *  5]",
                "movdqu  xmm6, xmmword ptr [{buffer} + 16 *  6]",
                "movdqu  xmm7, xmmword ptr [{buffer} + 16 *  7]",
                "movdqu  xmm8, xmmword ptr [{buffer} + 16 *  8]",
                "movdqu  xmm9, xmmword ptr [{buffer} + 16 *  9]",
                "movdqu xmm10, xmmword ptr [{buffer} + 16 * 10]",
                "movdqu xmm11, xmmword ptr [{buffer} + 16 * 11]",
                "movdqu xmm12, xmmword ptr [{buffer} + 16 * 12]",
                "movdqu xmm13, xmmword ptr [{buffer} + 16 * 13]",
                "movdqu xmm14, xmmword ptr [{buffer} + 16 * 14]",
                "movdqu xmm15, xmmword ptr [{buffer} + 16 * 15]",
                // Trigger an IOIO #VC exception to start the transfer.
                "out dx, eax",
                // Restore ymm registers.
                "vmovdqu  ymm0, ymmword ptr [{scratch} + 32 *  0]",
                "vmovdqu  ymm1, ymmword ptr [{scratch} + 32 *  1]",
                "vmovdqu  ymm2, ymmword ptr [{scratch} + 32 *  2]",
                "vmovdqu  ymm3, ymmword ptr [{scratch} + 32 *  3]",
                "vmovdqu  ymm4, ymmword ptr [{scratch} + 32 *  4]",
                "vmovdqu  ymm5, ymmword ptr [{scratch} + 32 *  5]",
                "vmovdqu  ymm6, ymmword ptr [{scratch} + 32 *  6]",
                "vmovdqu  ymm7, ymmword ptr [{scratch} + 32 *  7]",
                "vmovdqu  ymm8, ymmword ptr [{scratch} + 32 *  8]",
                "vmovdqu  ymm9, ymmword ptr [{scratch} + 32 *  9]",
                "vmovdqu ymm10, ymmword ptr [{scratch} + 32 * 10]",
                "vmovdqu ymm11, ymmword ptr [{scratch} + 32 * 11]",
                "vmovdqu ymm12, ymmword ptr [{scratch} + 32 * 12]",
                "vmovdqu ymm13, ymmword ptr [{scratch} + 32 * 13]",
                "vmovdqu ymm14, ymmword ptr [{scratch} + 32 * 14]",
                "vmovdqu ymm15, ymmword ptr [{scratch} + 32 * 15]",
                scratch = in(reg) scratch.as_mut_ptr(),
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
