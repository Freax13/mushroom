//! This crate contains the interfaces the supervisor and workload kernel use
//! to communicate.

#![no_std]
#![forbid(unsafe_code)]
#![allow(clippy::new_without_default)]

use allocation_buffer::AllocationBuffer;
use command_buffer::CommandBuffer;
use notification_buffer::NotificationBuffer;

pub mod allocation_buffer;
pub mod command_buffer;
pub mod notification_buffer;

#[repr(C)]
pub struct SupervisorServices {
    pub command_buffer: CommandBuffer,
    pub allocation_buffer: AllocationBuffer,
    pub notification_buffer: NotificationBuffer,
}

impl SupervisorServices {
    #[cfg(feature = "kernel")]
    pub const fn new() -> Self {
        Self {
            command_buffer: CommandBuffer::new(),
            allocation_buffer: AllocationBuffer::new(),
            notification_buffer: NotificationBuffer::new(),
        }
    }
}
