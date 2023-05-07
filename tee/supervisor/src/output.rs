use core::{
    cell::{LazyCell, RefCell, UnsafeCell},
    mem::{size_of, MaybeUninit},
};

use constants::{FINISH_OUTPUT_MSR, UPDATE_OUTPUT_MSR};
use sha2::{Digest, Sha256};
use snp_types::attestation::AttestionReport;
use x86_64::{
    instructions::hlt,
    structures::paging::{PhysFrame, Size4KiB},
};

use crate::{
    ghcb::{self, write_msr},
    pa_of, FakeSync,
};

/// This hasher is used to calculate the hash of the output that's included in
/// the attestation report.
static HASHER: FakeSync<LazyCell<RefCell<Option<Sha256>>>> =
    FakeSync::new(LazyCell::new(|| RefCell::new(Some(Sha256::default()))));

/// Append some bytes to the output.
pub fn update_output(bytes: &[u8]) {
    // Update the hasher.
    let mut guard = HASHER.borrow_mut();
    let hasher = guard.as_mut().expect("hasher was already finished");
    hasher.update(bytes);

    /// An aligned output buffer.
    #[repr(C, align(4096))]
    struct OutputBuffer {
        buffer: [u8; 0x1000],
    }
    #[link_section = ".shared"]
    static OUTPUT: FakeSync<UnsafeCell<OutputBuffer>> =
        FakeSync::new(UnsafeCell::new(OutputBuffer {
            buffer: [0; 0x1000],
        }));
    let addr = pa_of!(OUTPUT);
    let frame = PhysFrame::<Size4KiB>::from_start_address(addr).unwrap();

    // Split the bytes into chunks.
    for chunk in bytes.chunks(0x1000) {
        // Copy the chunk to shared memory.
        unsafe {
            core::intrinsics::volatile_copy_nonoverlapping_memory(
                OUTPUT.get().cast(),
                chunk.as_ptr(),
                chunk.len(),
            );
        }

        // Tell the host to record the output data.
        let value = frame.start_address().as_u64() | (chunk.len() - 1) as u64;
        write_msr(UPDATE_OUTPUT_MSR, value).unwrap();
    }
}

// Finish output.
pub fn finish() -> ! {
    // Finish the running hash.
    let mut guard = HASHER.borrow_mut();
    let hasher = guard.take().expect("hasher was already finished");
    let result = hasher.finalize();
    let output: [u8; 32] = result.into();

    // Create the attestation report.
    let mut report_data = [0; 64];
    report_data[..32].copy_from_slice(&output);
    let attestation_report = ghcb::create_attestation_report(report_data);
    let output_buffer = OutputBuffer { attestation_report };

    /// An aligned attestation report.
    #[repr(C, align(4096))]
    struct OutputBuffer {
        attestation_report: AttestionReport,
    }

    // Share the attestion report with the host.
    #[link_section = ".shared"]
    static OUTPUT: FakeSync<UnsafeCell<MaybeUninit<OutputBuffer>>> =
        FakeSync::new(UnsafeCell::new(MaybeUninit::uninit()));
    unsafe {
        OUTPUT.get().write_volatile(MaybeUninit::new(output_buffer));
    }
    let addr = pa_of!(OUTPUT);
    let frame = PhysFrame::<Size4KiB>::from_start_address(addr).unwrap();
    let value = frame.start_address().as_u64() | (size_of::<AttestionReport>() as u64);
    write_msr(FINISH_OUTPUT_MSR, value).unwrap();

    // The host shouldn't keep running us. Do nothing.
    loop {
        hlt();
    }
}
