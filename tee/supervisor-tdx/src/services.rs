use spin::{Lazy, Mutex};
use supervisor_services::{
    allocation_buffer::SlotIndex,
    command_buffer::{CommandBufferReader, CommandHandler},
    SupervisorServices,
};
use x86_64::instructions::interrupts;

use crate::{
    dynamic::HostAllocator,
    exception::{send_ipi, WAKEUP_VECTOR},
    output::{finish, update_output},
    per_cpu::PerCpu,
    tdcall::Vmcall,
    vcpu,
};

extern "C" {
    #[link_name = "supervisor_services_shared"]
    static SUPERVISOR_SERVICES: SupervisorServices;
}

fn supervisor_services() -> &'static SupervisorServices {
    unsafe { &SUPERVISOR_SERVICES }
}

static HANDLER: Lazy<Mutex<Handler>> = Lazy::new(|| Mutex::new(Handler::new()));

pub fn handle(resume: bool) {
    interrupts::disable();

    let idx = PerCpu::current_vcpu_index();

    if let Some(mut handler) = HANDLER.try_lock() {
        let mut command_buffer_reader =
            CommandBufferReader::new(&supervisor_services().command_buffer);
        while command_buffer_reader.handle(&mut *handler) {}
        drop(handler);

        let mut saw_self = false;
        for id in supervisor_services().notification_buffer.reset() {
            if id == idx {
                saw_self = true;
            } else {
                send_ipi(u32::from(id.as_u8()), WAKEUP_VECTOR);
            }
        }
        if saw_self {
            interrupts::enable();
            return;
        }
    }

    if resume {
        interrupts::enable();
    } else {
        Vmcall::instruction_hlt(false, true);
    }
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
        vcpu::start_next();
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
        panic!("fail")
    }
}
