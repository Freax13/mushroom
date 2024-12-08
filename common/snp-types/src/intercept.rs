pub const VMEXIT_CPUID: u64 = 0x72;
pub const VMEXIT_IOIO: u64 = 0x7b;
pub const VMEXIT_MSR: u64 = 0x7c;
pub const VMEXIT_VMGEXIT: u64 = 0x403;
// FIXME: This name is not official.
pub const VMEXIT_UNVALIDATED: u64 = 0x404;
