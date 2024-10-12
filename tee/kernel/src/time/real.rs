//! When this backend is used, we use the processor clock. This is arguably
//! insecure, because the host can speed up our perception of time by not
//! running the guest.

use core::arch::x86_64::{__cpuid, _rdtsc};

use x86_64::registers::model_specific::Msr;

use crate::spin::lazy::Lazy;

/// Returns the time current offset in ns.
pub fn current_offset() -> u64 {
    static GUEST_TSC_FREQ: Lazy<u64> = Lazy::new(determine_tsc_frequency);
    static START_OFFSET: Lazy<u64> = Lazy::new(|| unsafe { _rdtsc() });

    let guest_tsc_freq = *GUEST_TSC_FREQ;
    let start_offset = *START_OFFSET;
    let current_tsc = unsafe { _rdtsc() };

    (current_tsc - start_offset) * 1000 / guest_tsc_freq
}

// Returns the TSC frequency in MHz.
fn determine_tsc_frequency() -> u64 {
    // Try to get the frequency from cpuid.
    let result = unsafe { __cpuid(0x15) };
    if result.ebx != 0 {
        return u64::from(result.ecx) * u64::from(result.ebx) / u64::from(result.eax) / 1_000_000;
    }

    // For SNP, fall back to reading the frequence from the MSR.
    unsafe { Msr::new(0xC001_0134).read() }
}
