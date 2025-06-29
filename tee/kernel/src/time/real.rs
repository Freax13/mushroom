//! When this backend is used, we use the processor clock. This is arguably
//! insecure, because the host can speed up our perception of time by not
//! running the guest.

use core::arch::x86_64::{__cpuid, _rdtsc};

use x86_64::registers::model_specific::Msr;

use crate::{spin::lazy::Lazy, time::TimeBackend};

pub struct RealBackend {
    guest_tsc_freq: Lazy<u64>,
    start_offset: Lazy<u64>,
}

impl RealBackend {
    pub const fn new() -> Self {
        Self {
            guest_tsc_freq: Lazy::new(determine_tsc_frequency),
            start_offset: Lazy::new(|| unsafe { _rdtsc() }),
        }
    }
}

impl TimeBackend for RealBackend {
    fn current_offset(&self) -> u64 {
        let current_tsc = unsafe { _rdtsc() };
        current_tsc.saturating_sub(*self.start_offset) * 1000 / *self.guest_tsc_freq
    }
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
