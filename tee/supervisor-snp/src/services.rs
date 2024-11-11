use supervisor_services::{
    allocation_buffer::SlotIndex,
    command_buffer::{CommandBufferReader, CommandHandler},
    SupervisorServices,
};

use crate::{
    ap::{kick, start_next_ap},
    dynamic::HostAllocator,
    ghcb::exit,
    output::{finish, update_output},
};

extern "C" {
    #[link_name = "supervisor_services_shared"]
    static SUPERVISOR_SERVICES: SupervisorServices;
}

fn supervisor_services() -> &'static SupervisorServices {
    unsafe { &SUPERVISOR_SERVICES }
}

pub fn run() -> ! {
    let mut command_buffer_reader = CommandBufferReader::new(&supervisor_services().command_buffer);
    let mut handler = Handler::new();

    loop {
        // Handle all pending commands.
        while command_buffer_reader.handle(&mut handler) {}

        // Notify the APs that requested a notification and wait for the next
        // command.

        for id in supervisor_services().notification_buffer.reset() {
            kick(id);
        }

        wait_for_command();
    }
}

fn wait_for_command() {
    x86_64::instructions::hlt();
}

struct Handler {
    host_allocator: HostAllocator,
}

impl Handler {
    pub fn new() -> Self {
        Self {
            host_allocator: HostAllocator::new(),
        }
    }
}

impl CommandHandler for Handler {
    fn start_next_ap(&mut self) {
        start_next_ap();
    }

    fn allocate_memory(&mut self) {
        while let Some(entry) = supervisor_services().allocation_buffer.find_free_entry() {
            let Some(slot_index) = self.host_allocator.allocate_frame() else {
                break;
            };
            entry.set(slot_index);
        }
    }

    fn deallocate_memory(&mut self, slot_idx: SlotIndex) {
        self.host_allocator.deallocate_frame(slot_idx);
    }

    fn update_output(&mut self, output: &[u8]) {
        update_output(output);
    }

    fn finish_output(&mut self) {
        finish();
    }

    fn fail_output(&mut self) {
        exit();
    }
}
