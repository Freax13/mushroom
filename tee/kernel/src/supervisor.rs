// Yes, we want to pass pointers to asm blocks that are marked with `nomem`.
// The pointers are function pointers. We don't access the bytes stored at the
// addresses, but we do jump to it.
#![expect(clippy::pointers_in_nomem_asm_block)]

use core::arch::{asm, naked_asm, x86_64::__cpuid};

use crate::spin::{lazy::Lazy, mutex::Mutex};
use arrayvec::ArrayVec;
use constants::{physical_address::DYNAMIC_2MIB, ApIndex, INSECURE_SUPERVISOR_CALL_PORT};
use supervisor_services::{SlotIndex, SupervisorCallNr};
use x86_64::structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size2MiB};

// Note that we don't actually use the C abi.
type SupervisorCallFn = unsafe extern "C" fn();

static SUPERVISOR_CALL_FN: Lazy<SupervisorCallFn> = Lazy::new(|| {
    for base in (0x4000_0000..0x4fff_ffff).step_by(0x100) {
        // Query the hypervisor max leaf.
        let vendor_leaf = base;
        let values = unsafe {
            // SAFETY: CPUID is available.
            __cpuid(vendor_leaf)
        };
        // Bail if the leaf doesn't contain the maximum supported leaf.
        if values.eax == 0 {
            break;
        }

        // Query the hypervisor interface id.
        let interface_id_leaf = base + 1;
        let values = unsafe {
            // SAFETY: CPUID is available.
            __cpuid(interface_id_leaf)
        };

        match values.eax {
            0x4952534d => return insecure_supervisor_call,
            0x5352534d => return snp_supervisor_call,
            0x5452534d => return tdx_supervisor_call,
            _ => {}
        }
    }

    panic!("couldn't determine hypervisor interface");
});

#[naked]
unsafe extern "C" fn tdx_supervisor_call() {
    unsafe {
        naked_asm!("vmcall", "ret");
    }
}

#[naked]
unsafe extern "C" fn snp_supervisor_call() {
    unsafe {
        naked_asm!("vmmcall", "ret");
    }
}

#[naked]
unsafe extern "C" fn insecure_supervisor_call() {
    unsafe {
        naked_asm!(
            "out {port}, al",
            "ret",
            port = const INSECURE_SUPERVISOR_CALL_PORT,
        );
    }
}

pub unsafe fn start_next_ap() {
    unsafe {
        asm!(
            "call {supervisor_call}",
            in("rax") SupervisorCallNr::StartNextAp as u64,
            supervisor_call = in(reg) *SUPERVISOR_CALL_FN,
            options(nomem),
        );
    }
}

pub fn halt() {
    unsafe {
        asm!(
            "call {supervisor_call}",
            in("rax") SupervisorCallNr::Halt as u64,
            supervisor_call = in(reg) *SUPERVISOR_CALL_FN,
            options(nomem),
        );
    }
}

pub fn kick(ap: ApIndex) {
    unsafe {
        asm!(
            "call {supervisor_call}",
            in("rax") SupervisorCallNr::Kick as u64,
            in("rdi") u64::from(ap.as_u8()),
            supervisor_call = in(reg) *SUPERVISOR_CALL_FN,
            options(nomem),
        );
    }
}

pub const OUTPUT_BUFFER_CAPACITY: usize = 32 * 16;

pub fn update_output(data: &[u8]) {
    let mut buffer = [0; OUTPUT_BUFFER_CAPACITY];

    for chunk in data.chunks(OUTPUT_BUFFER_CAPACITY) {
        // We want a slice of size `BUFFER_CAPACITY`. If chunk has this size
        // use it, otherwise copy the chunk into `buffer` and create a slice
        // reference to it.
        let full_buffer = <&[u8; OUTPUT_BUFFER_CAPACITY]>::try_from(chunk).unwrap_or_else(|_| {
            buffer[..chunk.len()].copy_from_slice(chunk);
            &buffer
        });

        unsafe {
            asm!(
                "vmovdqu ymm0,  [{src} + 32 * 0]",
                "vmovdqu ymm1,  [{src} + 32 * 1]",
                "vmovdqu ymm2,  [{src} + 32 * 2]",
                "vmovdqu ymm3,  [{src} + 32 * 3]",
                "vmovdqu ymm4,  [{src} + 32 * 4]",
                "vmovdqu ymm5,  [{src} + 32 * 5]",
                "vmovdqu ymm6,  [{src} + 32 * 6]",
                "vmovdqu ymm7,  [{src} + 32 * 7]",
                "vmovdqu ymm8,  [{src} + 32 * 8]",
                "vmovdqu ymm9,  [{src} + 32 * 9]",
                "vmovdqu ymm10, [{src} + 32 * 10]",
                "vmovdqu ymm11, [{src} + 32 * 11]",
                "vmovdqu ymm12, [{src} + 32 * 12]",
                "vmovdqu ymm13, [{src} + 32 * 13]",
                "vmovdqu ymm14, [{src} + 32 * 14]",
                "vmovdqu ymm15, [{src} + 32 * 15]",
                "call {supervisor_call}",
                in("rax") SupervisorCallNr::UpdateOutput as u64,
                in("rdi") chunk.len(),
                src = in(reg) full_buffer.as_ptr(),
                supervisor_call = in(reg) *SUPERVISOR_CALL_FN,
                options(readonly),
            );
        }
    }
}

/// Tell to supervisor to commit the output and produce and attestation report.
pub fn finish_output() -> ! {
    unsafe {
        asm!(
            "call {supervisor_call}",
            "ud2",
            in("rax") SupervisorCallNr::FinishOutput as u64,
            supervisor_call = in(reg) *SUPERVISOR_CALL_FN,
            options(noreturn)
        );
    }
}

/// Tell the supervisor that something went wrong and to discard the output.
pub fn fail() -> ! {
    unsafe {
        asm!(
            "call {supervisor_call}",
            "ud2",
            in("rax") SupervisorCallNr::FailOutput as u64,
            supervisor_call = in(reg) *SUPERVISOR_CALL_FN,
            options(noreturn)
        );
    }
}

fn allocate() -> SlotIndex {
    let slot_id: u16;
    unsafe {
        asm!(
            "call {supervisor_call}",
            in("rax") SupervisorCallNr::AllocateMemory as u64,
            lateout("rax") slot_id,
            supervisor_call = in(reg) *SUPERVISOR_CALL_FN,
            options(nomem),
        );
    }
    SlotIndex::new(slot_id)
}

fn deallocate(slot_idx: SlotIndex) {
    unsafe {
        asm!(
            "call {supervisor_call}",
            in("rax") SupervisorCallNr::DeallocateMemory as u64,
            in("rdi") u64::from(slot_idx.get()),
            supervisor_call = in(reg) *SUPERVISOR_CALL_FN,
            options(nomem),
        );
    }
}

pub static ALLOCATOR: Allocator = Allocator::new();

pub struct Allocator {
    state: Mutex<AllocatorState>,
}

impl Allocator {
    const fn new() -> Self {
        Self {
            state: Mutex::new(AllocatorState::new()),
        }
    }
}

struct AllocatorState {
    /// A cache for frames. Instead of always freeing, we store a limited
    /// amount of frames for rapid reuse.
    cached: ArrayVec<PhysFrame<Size2MiB>, 128>,
}

impl AllocatorState {
    const fn new() -> Self {
        Self {
            cached: ArrayVec::new_const(),
        }
    }
}

unsafe impl FrameAllocator<Size2MiB> for &'_ Allocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        // Try to reused a cached frame.
        let mut state = self.state.lock();
        if let Some(cached) = state.cached.pop() {
            return Some(cached);
        }
        drop(state);

        let idx = allocate();
        Some(DYNAMIC_2MIB.start + u64::from(idx.get()))
    }
}

impl FrameDeallocator<Size2MiB> for &'_ Allocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size2MiB>) {
        // Try to put the frame in the cache.
        let mut state = self.state.lock();
        let res = state.cached.try_push(frame);
        if res.is_ok() {
            // Success
            return;
        }
        drop(state);

        let slot_idx = SlotIndex::new(u16::try_from(frame - DYNAMIC_2MIB.start).unwrap());
        deallocate(slot_idx);
    }
}
