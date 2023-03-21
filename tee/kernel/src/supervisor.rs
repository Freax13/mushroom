use constants::{HALT_PORT, MEMORY_MSR, SCHEDULE_PORT};
use x86_64::{
    instructions::port::PortWriteOnly,
    registers::model_specific::Msr,
    structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size2MiB},
    PhysAddr,
};

pub struct Allocator;

unsafe impl FrameAllocator<Size2MiB> for Allocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        let memory_msr = Msr::new(MEMORY_MSR);
        let addr = unsafe { memory_msr.read() };

        if addr == 0 {
            return None;
        }

        let addr = PhysAddr::new(addr);
        let frame = PhysFrame::from_start_address(addr).unwrap();
        Some(frame)
    }
}

impl FrameDeallocator<Size2MiB> for Allocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size2MiB>) {
        let addr = frame.start_address().as_u64();

        let mut memory_msr = Msr::new(MEMORY_MSR);
        unsafe {
            memory_msr.write(addr);
        }
    }
}

/// Halt this vcpu.
pub fn halt() {
    unsafe {
        PortWriteOnly::new(HALT_PORT).write(0u32);
    }
}

/// Tell the supervisor to schedule another vcpu.
pub fn schedule_vcpu() {
    unsafe {
        PortWriteOnly::new(SCHEDULE_PORT).write(1u32);
    }
}
