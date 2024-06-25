use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "supervisor")]
use bit_field::BitField;

#[repr(C, align(64))]
pub struct NotificationBuffer {
    bits: [AtomicU64; 2],
}

impl NotificationBuffer {
    #[cfg(feature = "kernel")]
    pub(crate) const fn new() -> Self {
        Self {
            bits: [const { AtomicU64::new(0) }; 2],
        }
    }

    /// Tell the supervisor to wake up the vCPU after it's done processing
    /// commands.
    #[cfg(feature = "kernel")]
    pub fn arm(&self, vcpu: usize) {
        let word_index = vcpu / 64;
        let bit_index = vcpu % 64;
        self.bits[word_index].fetch_or(1 << bit_index, Ordering::SeqCst);
    }

    /// Return an iterator yielding all vCPUs that requested to be woken up.
    #[cfg(feature = "supervisor")]
    pub fn reset(&self) -> impl Iterator<Item = usize> + '_ {
        self.bits
            .iter()
            .map(|bits| bits.swap(0, Ordering::SeqCst))
            .flat_map(|bits| (0..64).map(move |i| bits.get_bit(i)))
            .enumerate()
            .filter(|(_, armed)| *armed)
            .map(|(i, _)| i)
    }
}
