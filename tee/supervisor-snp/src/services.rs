use spin::Mutex;
use supervisor_services::{
    allocation_buffer::SlotIndex,
    command_buffer::{CommandBufferReader, CommandHandler},
    SupervisorServices,
};

use crate::{
    ap::kick,
    dynamic::HostAllocator,
    ghcb::exit,
    output::{finish, update_output},
    scheduler::start_next_ap,
};

extern "C" {
    #[link_name = "supervisor_services_shared"]
    static SUPERVISOR_SERVICES: SupervisorServices;
}

fn supervisor_services() -> &'static SupervisorServices {
    unsafe { &SUPERVISOR_SERVICES }
}

static HANDLER: Mutex<Handler> = Mutex::new(Handler::new());

pub fn handle_commands() {
    let mut command_buffer_reader = CommandBufferReader::new(&supervisor_services().command_buffer);
    let Some(mut handler) = HANDLER.try_lock() else {
        return;
    };

    // Handle all pending commands.
    let mut pending = supervisor_services().notification_buffer.reset();
    while command_buffer_reader.handle(&mut *handler) {
        pending |= supervisor_services().notification_buffer.reset();
    }

    // Notify the APs that requested a notification and wait for the next
    // command.
    for id in pending {
        kick(id);
    }
}

struct Handler {
    host_allocator: HostAllocator,
}

impl Handler {
    pub const fn new() -> Self {
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
