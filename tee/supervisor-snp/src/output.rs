use core::{
    cell::LazyCell,
    mem::{size_of, MaybeUninit},
};

use constants::{FINISH_OUTPUT_MSR, UPDATE_OUTPUT_MSR};
use sha2::{Digest, Sha256};
use snp_types::attestation::AttestionReport;
use spin::Mutex;
use x86_64::instructions::hlt;

use crate::{
    ghcb::{self, write_msr},
    shared,
};

#[derive(Default)]
struct Hasher {
    sha256: Sha256,
    len: usize,
}

impl Hasher {
    pub fn update(&mut self, bytes: &[u8]) {
        self.sha256.update(bytes);
        self.len += bytes.len();
    }

    pub fn finalize(self) -> ([u8; 32], usize) {
        (self.sha256.finalize().into(), self.len)
    }
}

/// This hasher is used to calculate the hash of the output that's included in
/// the attestation report.
static HASHER: Mutex<LazyCell<Option<Hasher>>> =
    Mutex::new(LazyCell::new(|| Some(Hasher::default())));

/// Append some bytes to the output.
pub fn update_output(bytes: &[u8]) {
    // Update the hasher.
    let mut guard = HASHER.lock();
    let hasher = LazyCell::force_mut(&mut guard);
    let hasher = hasher.as_mut().expect("hasher was already finished");
    hasher.update(bytes);

    shared! {
        static OUTPUT: [u8; 0x1000] = [0; 0x1000];
    }

    // Split the bytes into chunks.
    for chunk in bytes.chunks(0x1000) {
        // Copy the chunk to shared memory.
        OUTPUT
            .as_write_only_ptr()
            .as_slice()
            .index(..chunk.len())
            .copy_from_slice(chunk);

        // Tell the host to record the output data.
        let value = OUTPUT.frame().start_address().as_u64() | (chunk.len() - 1) as u64;
        write_msr(UPDATE_OUTPUT_MSR, value).unwrap();
    }
}

// Finish output.
pub fn finish() -> ! {
    // Finish the running hash.
    let mut guard = HASHER.lock();
    let hasher = LazyCell::force_mut(&mut guard);
    let hasher = hasher.take().expect("hasher was already finished");
    let (hash, len) = hasher.finalize();

    // Create the attestation report.
    let mut report_data = [0; 64];
    report_data[..32].copy_from_slice(&hash);
    report_data[32..40].copy_from_slice(&len.to_le_bytes());
    let attestation_report = ghcb::create_attestation_report(report_data);

    shared! {
        static OUTPUT: MaybeUninit<AttestionReport> = MaybeUninit::uninit();
    }

    // Share the attestion report with the host.
    OUTPUT
        .as_write_only_ptr()
        .write(MaybeUninit::new(attestation_report));

    let value = OUTPUT.frame().start_address().as_u64() | (size_of::<AttestionReport>() as u64);
    write_msr(FINISH_OUTPUT_MSR, value).unwrap();

    // The host shouldn't keep running us. Do nothing.
    loop {
        hlt();
    }
}

// Fail the output.
pub fn fail() {
    let mut guard = HASHER.lock();
    let hasher = LazyCell::force_mut(&mut guard);
    hasher.take();
    drop(guard);
}
