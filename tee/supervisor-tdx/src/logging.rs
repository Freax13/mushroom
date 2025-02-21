use core::fmt::Write;

use log::{Log, Metadata, Record};
use log_types::{LogBuffer, LogWriter};
use spin::Mutex;
use x86_64::instructions::interrupts;

#[unsafe(link_section = ".log_buffer")]
static LOG_BUFFER: LogBuffer = LogBuffer::new();

static WRITER: Mutex<LogWriter> = Mutex::new(LogWriter::new(&LOG_BUFFER));

pub struct SerialLogger;

impl Log for SerialLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let level_color = match record.level() {
            log::Level::Error => "\x1b[31;101m",
            log::Level::Warn => "\x1b[33;103m",
            log::Level::Info => "\x1b[34;104m",
            log::Level::Debug => "\x1b[32;102m",
            log::Level::Trace => "\x1b[35;105m",
        };
        let reset_color = "\x1b[0m";

        interrupts::without_interrupts(|| {
            let mut writer = WRITER.lock();
            let _ = writeln!(
                writer,
                "{level_color}[{:<5} {}:{}]{reset_color} {}",
                record.level(),
                record.file().unwrap_or("<unknown>"),
                record.line().unwrap_or(0),
                record.args(),
            );
        });
    }

    fn flush(&self) {}
}
