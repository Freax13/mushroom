#[cfg(feature = "supervisor")]
use constants::ApBitmap;
#[cfg(feature = "kernel")]
use constants::ApIndex;
use constants::AtomicApBitmap;

#[repr(C, align(64))]
pub struct NotificationBuffer(AtomicApBitmap);

impl NotificationBuffer {
    #[cfg(feature = "kernel")]
    pub(crate) const fn new() -> Self {
        Self(AtomicApBitmap::empty())
    }

    /// Tell the supervisor to wake up the vCPU after it's done processing
    /// commands.
    #[cfg(feature = "kernel")]
    pub fn arm(&self, vcpu: ApIndex) {
        self.0.set(vcpu);
    }

    /// Return an iterator yielding all vCPUs that requested to be woken up.
    #[cfg(feature = "supervisor")]
    pub fn reset(&self) -> ApBitmap {
        self.0.take_all()
    }
}
