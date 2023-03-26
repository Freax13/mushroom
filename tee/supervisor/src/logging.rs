use core::fmt::Write;

use constants::LOG_PORT;
use log::{Log, Metadata, Record};

use crate::ghcb::ioio_write;

pub struct SerialLogger;

impl Log for SerialLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let mut writer = SerialLogger;

        let level_color = match record.level() {
            log::Level::Error => "\x1b[31;101m",
            log::Level::Warn => "\x1b[33;103m",
            log::Level::Info => "\x1b[34;104m",
            log::Level::Debug => "\x1b[32;102m",
            log::Level::Trace => "\x1b[35;105m",
        };
        let reset_color = "\x1b[0m";

        let _ = writeln!(
            writer,
            "{level_color}[{:<5} {}:{}]{reset_color} {}",
            record.level(),
            record.file().unwrap_or("<unknown>"),
            record.line().unwrap_or(0),
            record.args(),
        );
    }

    fn flush(&self) {}
}

impl Write for SerialLogger {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for c in s.chars() {
            self.write_char(c)?;
        }
        Ok(())
    }

    fn write_char(&mut self, c: char) -> core::fmt::Result {
        ioio_write(LOG_PORT, u32::from(c));
        Ok(())
    }
}
