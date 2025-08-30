use std::collections::HashMap;

use anyhow::{Result, ensure};
use log_types::{LogBuffer, LogReader};
use x86_64::structures::paging::{PhysFrame, Size2MiB};

use crate::slot::Slot;

pub fn start_log_collection(
    memory_slots: &HashMap<u16, Slot>,
    pa: PhysFrame<Size2MiB>,
) -> Result<()> {
    let Some(log_buffer) = memory_slots
        .values()
        .find(|s| s.gpa().start_address() == pa.start_address())
    else {
        return Ok(());
    };

    let log_buffer = log_buffer
        .shared_mapping()
        .cloned()
        .expect("log slot must have shared mapping");

    ensure!(
        log_buffer.len().get() >= size_of::<LogBuffer>(),
        "log buffer region is too small"
    );

    std::thread::spawn(move || {
        let mut log_buffer = log_buffer.as_ptr().cast::<LogBuffer>();
        let log_buffer = unsafe { log_buffer.as_mut() };
        let mut reader = LogReader::new(log_buffer);
        let mut line = String::new();
        loop {
            line.clear();
            reader.read_line(&mut line);
            eprintln!("{line}");
        }
    });

    Ok(())
}
