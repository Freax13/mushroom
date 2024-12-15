pub const VMEXIT_INTR: u64 = 0x60;
pub const VMEXIT_NMI: u64 = 0x61;
pub const VMEXIT_SMI: u64 = 0x62;
pub const VMEXIT_INIT: u64 = 0x63;
pub const VMEXIT_CPUID: u64 = 0x72;
pub const VMEXIT_PAUSE: u64 = 0x77;
pub const VMEXIT_IOIO: u64 = 0x7b;
pub const VMEXIT_MSR: u64 = 0x7c;
pub const VMEXIT_VMMCALL: u64 = 0x81;
pub const VMEXIT_NPF: u64 = 0x400;
pub const VMEXIT_VMGEXIT: u64 = 0x403;
// FIXME: This name is not official.
pub const VMEXIT_UNVALIDATED: u64 = 0x404;
pub const VMEXIT_INVALID: u64 = !0;
