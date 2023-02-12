use core::num::NonZeroU32;

use bit_field::BitField;
use x86_64::{registers::model_specific::Msr, structures::paging::PhysFrame, PhysAddr};

/// The Extended Feature Enable Register.
#[derive(Debug)]
pub struct GhcbProtocolMsr;

impl GhcbProtocolMsr {
    /// The underlying model specific register.
    pub const MSR: Msr = Msr::new(0xC001_0130);
}

#[derive(Debug)]
#[non_exhaustive]
pub enum GhcbInfo {
    GhcbGuestPhysicalAddress {
        /// The guest physical address of the GHCB
        address: PhysFrame,
    },
    SevInformation {
        /// The maximum GHCB protocol version supported by the hypervisor.
        maximum_ghcb_protocol_version: u8,
        /// The minimum GHCB protocol version supported by the hypervisor.
        minimum_ghcb_protocol_version: u8,
        /// The SEV page table encryption bit number.
        c_bit_position: u8,
    },
    SevInformationRequest,
    CpuidRequest {
        function: u32,
        register: CpuidRegister,
    },
    CpuidResponse {
        value: u32,
        register: CpuidRegister,
    },
    ApResetHoldRequest,
    ApResetHoldResponse,
    PreferredGhcbGpaRequest,
    PreferredGhcbGpaResponse {
        address: Option<PhysFrame>,
    },
    RegisterGhcbGpaRequest {
        address: PhysFrame,
    },
    RegisterGhcbGpaResponse {
        address: Option<PhysFrame>,
    },
    SnpPageStateChangeRequest {
        operation: PageOperation,
        address: PhysFrame,
    },
    SnpPageStateChangeResponse {
        error_code: Option<NonZeroU32>,
    },
    HypervisorFeatureSupportRequest,
    #[non_exhaustive]
    HypervisorFeatureSupportResponse {
        sev_snp: bool,
        sev_snp_ap_creation: bool,
        sev_snp_restricted_injection: bool,
        sev_snp_restricted_injection_timer: bool,
    },
    TerminationRequest {
        reason_code: TerminateReasonCode,
    },
}

impl From<GhcbInfo> for u64 {
    fn from(info: GhcbInfo) -> Self {
        let mut msr_value = 0;

        match info {
            GhcbInfo::GhcbGuestPhysicalAddress { address } => {
                msr_value.set_bits(0..=11, 0x000); // GHCBInfo
                msr_value.set_bits(12..=63, address.start_address().as_u64().get_bits(12..));
            }
            GhcbInfo::SevInformation {
                maximum_ghcb_protocol_version,
                minimum_ghcb_protocol_version,
                c_bit_position,
            } => {
                msr_value.set_bits(0..=11, 0x001); // GHCBInfo
                msr_value.set_bits(24..=31, u64::from(c_bit_position));
                msr_value.set_bits(32..=47, u64::from(minimum_ghcb_protocol_version));
                msr_value.set_bits(48..=63, u64::from(maximum_ghcb_protocol_version));
            }
            GhcbInfo::SevInformationRequest => {
                msr_value.set_bits(0..=11, 0x002); // GHCBInfo
            }
            GhcbInfo::CpuidRequest { function, register } => {
                msr_value.set_bits(0..=11, 0x004); // GHCBInfo
                msr_value.set_bits(12..=29, 0); // Reserved, must be zero
                msr_value.set_bits(30..=31, register as u64);
                msr_value.set_bits(32..=63, u64::from(function));
            }
            GhcbInfo::CpuidResponse { value, register } => {
                msr_value.set_bits(0..=11, 0x005); // GHCBInfo
                msr_value.set_bits(12..=29, 0); // Reserved, must be zero
                msr_value.set_bits(30..=31, register as u64);
                msr_value.set_bits(32..=63, u64::from(value));
            }
            GhcbInfo::ApResetHoldRequest => {
                msr_value.set_bits(0..=11, 0x006); // GHCBInfo
                msr_value.set_bits(12..=63, 0); // Must be zero
            }
            GhcbInfo::ApResetHoldResponse => {
                msr_value.set_bits(0..=11, 0x007); // GHCBInfo
                msr_value.set_bits(12..=63, 1); // Must be non-zero
            }
            GhcbInfo::PreferredGhcbGpaRequest => {
                msr_value.set_bits(0..=11, 0x010); // GHCBInfo
                msr_value.set_bits(12..=63, 0); // Must be zero
            }
            GhcbInfo::PreferredGhcbGpaResponse { address } => {
                let gfn = address.map_or(0xf_ffff_ffff_ffff, |addr| {
                    addr.start_address().as_u64().get_bits(12..)
                });

                msr_value.set_bits(0..=11, 0x011); // GHCBInfo
                msr_value.set_bits(12..=63, gfn);
            }
            GhcbInfo::RegisterGhcbGpaRequest { address } => {
                let gfn = address.start_address().as_u64().get_bits(12..);

                msr_value.set_bits(0..=11, 0x012); // GHCBInfo
                msr_value.set_bits(12..=63, gfn);
            }
            GhcbInfo::RegisterGhcbGpaResponse { address } => {
                let gfn = address.map_or(0xf_ffff_ffff_ffff, |addr| {
                    addr.start_address().as_u64().get_bits(12..)
                });

                msr_value.set_bits(0..=11, 0x013); // GHCBInfo
                msr_value.set_bits(12..=63, gfn);
            }
            GhcbInfo::SnpPageStateChangeRequest { operation, address } => {
                let gfn = address.start_address().as_u64().get_bits(12..);

                msr_value.set_bits(0..=11, 0x014); // GHCBInfo
                msr_value.set_bits(12..=51, gfn);
                msr_value.set_bits(52..=55, operation as u64);
                msr_value.set_bits(56..=63, 0); // Reserved, must be zero
            }
            GhcbInfo::SnpPageStateChangeResponse { error_code } => {
                let error_code = error_code.map(NonZeroU32::get).unwrap_or(0);

                msr_value.set_bits(0..=11, 0x015); // GHCBInfo
                msr_value.set_bits(12..=31, 0); // Reserved, must be zero
                msr_value.set_bits(32..=63, u64::from(error_code));
            }
            GhcbInfo::HypervisorFeatureSupportRequest => {
                msr_value.set_bits(0..=11, 0x080); // GHCBInfo
                msr_value.set_bits(12..=63, 0); // Reserved, must be zero
            }
            GhcbInfo::HypervisorFeatureSupportResponse {
                sev_snp,
                sev_snp_ap_creation,
                sev_snp_restricted_injection,
                sev_snp_restricted_injection_timer,
            } => {
                let mut features_bitmap = 0;
                features_bitmap.set_bit(0, sev_snp);
                features_bitmap.set_bit(1, sev_snp_ap_creation);
                features_bitmap.set_bit(2, sev_snp_restricted_injection);
                features_bitmap.set_bit(3, sev_snp_restricted_injection_timer);

                msr_value.set_bits(0..=11, 0x081); // GHCBInfo
                msr_value.set_bits(12..=63, features_bitmap);
            }
            GhcbInfo::TerminationRequest { reason_code } => {
                msr_value.set_bits(0..=11, 0x100); // GHCBInfo
                msr_value.set_bits(12..=15, u64::from(reason_code.reason_code_set));
                msr_value.set_bits(16..=23, u64::from(reason_code.reason_code));
            }
        }

        msr_value
    }
}

#[derive(Debug)]
pub struct ParseError(());

impl TryFrom<u64> for GhcbInfo {
    type Error = ParseError;

    fn try_from(msr_value: u64) -> Result<Self, Self::Error> {
        let ghcb_info = msr_value.get_bits(0..=11);
        match ghcb_info {
            0x000 => {
                let gfn = msr_value.get_bits(12..=63);
                let address = PhysAddr::new(gfn << 12);
                let address = PhysFrame::from_start_address(address).unwrap();
                Ok(Self::GhcbGuestPhysicalAddress { address })
            }
            0x001 => {
                let c_bit_position = msr_value.get_bits(24..=31) as u8;
                let minimum_ghcb_protocol_version = msr_value.get_bits(32..=47) as u8;
                let maximum_ghcb_protocol_version = msr_value.get_bits(48..=63) as u8;
                Ok(Self::SevInformation {
                    maximum_ghcb_protocol_version,
                    minimum_ghcb_protocol_version,
                    c_bit_position,
                })
            }
            0x002 => Ok(Self::SevInformationRequest),
            0x004 => {
                if msr_value.get_bits(12..=29) != 0 {
                    return Err(ParseError(()));
                }
                let register = match msr_value.get_bits(30..=31) {
                    0 => CpuidRegister::Eax,
                    1 => CpuidRegister::Ebx,
                    2 => CpuidRegister::Ecx,
                    3 => CpuidRegister::Edx,
                    _ => unreachable!(),
                };
                let function = msr_value.get_bits(32..=63) as u32;
                Ok(Self::CpuidRequest { function, register })
            }
            0x005 => {
                if msr_value.get_bits(12..=29) != 0 {
                    return Err(ParseError(()));
                }
                let register = match msr_value.get_bits(30..=31) {
                    0 => CpuidRegister::Eax,
                    1 => CpuidRegister::Ebx,
                    2 => CpuidRegister::Ecx,
                    3 => CpuidRegister::Edx,
                    _ => unreachable!(),
                };
                let value = msr_value.get_bits(32..=63) as u32;
                Ok(Self::CpuidResponse { value, register })
            }
            0x006 => {
                if msr_value.get_bits(12..=63) != 0 {
                    return Err(ParseError(()));
                }
                Ok(Self::ApResetHoldRequest)
            }
            0x007 => {
                if msr_value.get_bits(12..=63) == 0 {
                    return Err(ParseError(()));
                }
                Ok(Self::ApResetHoldResponse)
            }
            0x010 => {
                if msr_value.get_bits(12..=63) == 0 {
                    return Err(ParseError(()));
                }
                Ok(Self::PreferredGhcbGpaRequest)
            }
            0x011 => {
                let gfn = msr_value.get_bits(12..=63);
                let address = if gfn != 0xf_ffff_ffff_ffff {
                    let address = PhysAddr::new(gfn << 12);
                    let address = PhysFrame::from_start_address(address).unwrap();
                    Some(address)
                } else {
                    None
                };
                Ok(Self::PreferredGhcbGpaResponse { address })
            }
            0x012 => {
                let gfn = msr_value.get_bits(12..=63);
                let address = PhysAddr::new(gfn << 12);
                let address = PhysFrame::from_start_address(address).unwrap();
                Ok(Self::RegisterGhcbGpaRequest { address })
            }
            0x013 => {
                let gfn = msr_value.get_bits(12..=63);
                let address = if gfn != 0xf_ffff_ffff_ffff {
                    let address = PhysAddr::new(gfn << 12);
                    let address = PhysFrame::from_start_address(address).unwrap();
                    Some(address)
                } else {
                    None
                };
                Ok(Self::RegisterGhcbGpaResponse { address })
            }
            0x014 => {
                let gfn = msr_value.get_bits(12..=51);
                let address = PhysAddr::new(gfn << 12);
                let address = PhysFrame::from_start_address(address).unwrap();
                let operation = match msr_value.get_bits(52..=55) {
                    1 => PageOperation::PageAssignmentPrivate,
                    2 => PageOperation::PageAssignmentShared,
                    _ => return Err(ParseError(())),
                };
                if msr_value.get_bits(56..=63) != 0 {
                    return Err(ParseError(()));
                }
                Ok(Self::SnpPageStateChangeRequest { operation, address })
            }
            0x015 => {
                if msr_value.get_bits(12..=31) != 0 {
                    return Err(ParseError(()));
                }
                let error_code = msr_value.get_bits(32..=63) as u32;
                let error_code = NonZeroU32::new(error_code);
                Ok(Self::SnpPageStateChangeResponse { error_code })
            }
            0x080 => {
                if msr_value.get_bits(12..=63) != 0 {
                    return Err(ParseError(()));
                }
                Ok(Self::HypervisorFeatureSupportRequest)
            }
            0x081 => {
                let bitmap = msr_value.get_bits(12..=63);
                let sev_snp = bitmap.get_bit(0);
                let sev_snp_ap_creation = bitmap.get_bit(1);
                let sev_snp_restricted_injection = bitmap.get_bit(2);
                let sev_snp_restricted_injection_timer = bitmap.get_bit(3);
                Ok(Self::HypervisorFeatureSupportResponse {
                    sev_snp,
                    sev_snp_ap_creation,
                    sev_snp_restricted_injection,
                    sev_snp_restricted_injection_timer,
                })
            }
            0x100 => {
                let reason_code_set = msr_value.get_bits(12..=15) as u8;
                let reason_code = msr_value.get_bits(16..=23) as u8;
                let reason_code = TerminateReasonCode::new(reason_code_set, reason_code);
                Ok(Self::TerminationRequest { reason_code })
            }
            _ => Err(ParseError(())),
        }
    }
}

#[derive(Debug)]
pub enum CpuidRegister {
    Eax,
    Ebx,
    Ecx,
    Edx,
}

#[derive(Debug)]
pub enum PageOperation {
    PageAssignmentPrivate = 1,
    PageAssignmentShared = 2,
}

#[derive(Debug)]
pub struct TerminateReasonCode {
    reason_code_set: u8,
    reason_code: u8,
}

impl TerminateReasonCode {
    pub const GENERAL_TERMINATION_REQUEST: Self = Self::new(0x0, 0x00);
    pub const GHCB_PROTOCOL_RANGE_NOT_SUPPORTED: Self = Self::new(0x0, 0x01);
    pub const SEV_SNP_FEATURES_NOT_SUPPORTED: Self = Self::new(0x0, 0x02);

    pub const fn new(reason_code_set: u8, reason_code: u8) -> Self {
        assert!(reason_code_set < 16, "reason code is bigger than 16");
        Self {
            reason_code_set,
            reason_code,
        }
    }
}
