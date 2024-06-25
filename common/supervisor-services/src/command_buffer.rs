//! The kernel can push commands into the [`CommandBuffer`] and the supervisor
//! will consume them. All commands are executed asynchronously and no
//! responses are sent back (because we don't need them).

#[cfg(feature = "kernel")]
use core::iter::once;
use core::sync::atomic::{AtomicU16, AtomicU8, Ordering};

#[cfg(feature = "kernel")]
use bytemuck::bytes_of;
#[cfg(feature = "supervisor")]
use bytemuck::bytes_of_mut;
use bytemuck::{Pod, Zeroable};

use crate::allocation_buffer::SlotIndex;

const COMMAND_BUFFER_SIZE: u16 = 0x4000 - 2 * 2;

#[repr(C, align(64))]
pub struct CommandBuffer {
    /// The index of the last completed command.
    completed_index: AtomicU16,
    /// The index past the last command that is ready to be executed.
    pending_index: AtomicU16,
    buffer: [AtomicU8; COMMAND_BUFFER_SIZE as usize],
}

impl CommandBuffer {
    #[cfg(feature = "kernel")]
    pub(crate) const fn new() -> Self {
        Self {
            completed_index: AtomicU16::new(0),
            pending_index: AtomicU16::new(0),
            buffer: [const { AtomicU8::new(0) }; COMMAND_BUFFER_SIZE as usize],
        }
    }
}

#[cfg(feature = "kernel")]
pub struct CommandBufferWriter {
    buffer: &'static CommandBuffer,
}

#[cfg(feature = "kernel")]
impl CommandBufferWriter {
    pub const fn new(buffer: &'static CommandBuffer) -> Self {
        Self { buffer }
    }

    pub fn push<C>(&mut self, command: &C) -> Result<(), CapacityError>
    where
        C: Command,
    {
        let size = 1 + size_of::<C>();

        let mut pending_index = self.buffer.pending_index.load(Ordering::SeqCst);
        let completed_index = self.buffer.completed_index.load(Ordering::SeqCst);

        let available_capacity = if completed_index <= pending_index {
            completed_index + (COMMAND_BUFFER_SIZE - 1 - pending_index)
        } else {
            completed_index - pending_index - 1
        };
        if usize::from(available_capacity) < size {
            return Err(CapacityError);
        }

        let bytes = once(C::ID).chain(bytes_of(command).iter().copied());
        for byte in bytes {
            self.buffer.buffer[usize::from(pending_index)].store(byte, Ordering::Relaxed);
            pending_index += 1;
            if pending_index == COMMAND_BUFFER_SIZE {
                pending_index = 0;
            }
        }

        self.buffer
            .pending_index
            .store(pending_index, Ordering::SeqCst);

        Ok(())
    }
}

#[cfg(feature = "supervisor")]
pub struct CommandBufferReader {
    buffer: &'static CommandBuffer,
}

#[cfg(feature = "supervisor")]
impl CommandBufferReader {
    pub const fn new(buffer: &'static CommandBuffer) -> Self {
        Self { buffer }
    }

    /// Handle a command. Returns `true` if a command was executed or `false`
    /// if there was no command to be handled.
    pub fn handle(&mut self, handler: &mut impl CommandHandler) -> bool {
        let pending_index = self.buffer.pending_index.load(Ordering::SeqCst);
        let mut completed_index = self.buffer.completed_index.load(Ordering::SeqCst);

        if pending_index == completed_index {
            return false;
        }

        let mut read_byte = || {
            let value = self.buffer.buffer[usize::from(completed_index)].load(Ordering::Relaxed);
            completed_index += 1;
            if completed_index == COMMAND_BUFFER_SIZE {
                completed_index = 0;
            }
            value
        };
        macro_rules! handle {
            ($command:ty) => {{
                let mut cmd = <$command as Zeroable>::zeroed();
                for byte in bytes_of_mut(&mut cmd) {
                    *byte = read_byte();
                }
                cmd.dispatch(handler);
            }};
        }
        let command_id = read_byte();
        match command_id {
            StartNextAp::ID => handle!(StartNextAp),
            AllocateMemory::ID => handle!(AllocateMemory),
            DeallocateMemory::ID => handle!(DeallocateMemory),
            UpdateOutput::ID => handle!(UpdateOutput),
            FinishOutput::ID => handle!(FinishOutput),
            FailOutput::ID => handle!(FailOutput),
            _ => {
                unreachable!("unknown command id: {command_id}")
            }
        }

        self.buffer
            .completed_index
            .store(completed_index, Ordering::SeqCst);

        true
    }
}

pub trait CommandHandler {
    fn start_next_ap(&mut self);
    fn allocate_memory(&mut self);
    fn deallocate_memory(&mut self, slot_idx: SlotIndex);
    fn update_output(&mut self, output: &[u8]);
    fn finish_output(&mut self);
    fn fail_output(&mut self);
}

pub struct CapacityError;

pub trait Command: Pod {
    const ID: u8;

    fn dispatch(self, handler: &mut impl CommandHandler);
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct StartNextAp;

impl Command for StartNextAp {
    const ID: u8 = 0;

    fn dispatch(self, handler: &mut impl CommandHandler) {
        handler.start_next_ap()
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct AllocateMemory;

impl Command for AllocateMemory {
    const ID: u8 = 1;

    fn dispatch(self, handler: &mut impl CommandHandler) {
        handler.allocate_memory()
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct DeallocateMemory {
    pub slot_idx: SlotIndex,
}

impl Command for DeallocateMemory {
    const ID: u8 = 2;

    fn dispatch(self, handler: &mut impl CommandHandler) {
        handler.deallocate_memory(self.slot_idx)
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct UpdateOutput {
    size: u16,
    buffer: [u8; 0x1000],
}

impl UpdateOutput {
    pub fn new(chunk: &[u8]) -> Self {
        let size = chunk.len() as u16;
        let mut buffer = [0; 0x1000];
        buffer[..chunk.len()].copy_from_slice(chunk);
        Self { size, buffer }
    }
}

impl Command for UpdateOutput {
    const ID: u8 = 3;

    fn dispatch(self, handler: &mut impl CommandHandler) {
        handler.update_output(&self.buffer[..usize::from(self.size)])
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct FinishOutput;

impl Command for FinishOutput {
    const ID: u8 = 4;

    fn dispatch(self, handler: &mut impl CommandHandler) {
        handler.finish_output()
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct FailOutput;

impl Command for FailOutput {
    const ID: u8 = 5;

    fn dispatch(self, handler: &mut impl CommandHandler) {
        handler.fail_output()
    }
}
