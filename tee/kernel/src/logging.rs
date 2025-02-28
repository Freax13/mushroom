use core::fmt::Write;

use log::{Log, Metadata, Record};
use log_types::{LogBuffer, LogWriter};

use crate::spin::mutex::Mutex;

#[unsafe(link_section = ".log_buffer")]
static LOG_BUFFER: LogBuffer = LogBuffer::new();

static WRITER: Mutex<LogWriter> = Mutex::new(LogWriter::new(&LOG_BUFFER));

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

        // Take the lock without potentially trigger a stall warning.
        let mut guard = {
            loop {
                if let Some(guard) = WRITER.try_lock() {
                    break guard;
                }
            }
        };

        let _ = writeln!(
            guard,
            "{level_color}[{:<5} {}:{}]{reset_color} {}",
            record.level(),
            record.file().unwrap_or("<unknown>"),
            record.line().unwrap_or(0),
            record.args(),
        );
    }

    fn flush(&self) {}
}
