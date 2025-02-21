use bytemuck::{CheckedBitPattern, NoUninit};
use uuid::{Uuid, uuid};

use crate::{Reserved, report::TeeTcbSvn};

const _: () = assert!(u32::to_le(1) == 1, "big endian targets are not supported");

#[derive(Debug, Clone, Copy, NoUninit, CheckedBitPattern)]
#[repr(C)]
pub struct Header {
    pub version: Version,
    pub attestation_type: AttestationType,
    pub tee_type: TeeType,
    _reserved1: Reserved<2>,
    _reserved2: Reserved<2>,
    pub qe_vendor_id: QeVendorId,
    pub user_data: [u8; 20],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, NoUninit, CheckedBitPattern)]
#[repr(u16)]
pub enum Version {
    Four = 4,
}

#[derive(Debug, Clone, Copy, NoUninit, CheckedBitPattern)]
#[repr(u16)]
pub enum AttestationType {
    Ecdsa256P256 = 2,
    Ecdsa384P384 = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, NoUninit, CheckedBitPattern)]
#[repr(u32)]
pub enum TeeType {
    Sgx = 0,
    Tdx = 0x81,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, NoUninit, CheckedBitPattern)]
#[repr(transparent)]
pub struct QeVendorId(pub Uuid);

impl QeVendorId {
    pub const INTEL_SGX: Self = Self(uuid!("939a7233-f79c-4ca9-940a-0db3957f0607"));
}

#[derive(Debug, Clone, Copy, NoUninit, CheckedBitPattern)]
#[repr(C)]
pub struct Body {
    pub tee_tcb_svn: TeeTcbSvn,
    pub mr_seam: [u8; 48],
    pub mr_signer_seam: [u8; 48],
    pub seam_attributes: [u8; 8],
    pub td_attributes: Attributes,
    pub xfam: [u8; 8],
    pub mr_td: [u8; 48],
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_owner_config: [u8; 48],
    pub rtmrs: [[u8; 48]; 4],
    pub report_data: [u8; 64],
}

#[derive(Debug, Clone, Copy, NoUninit, CheckedBitPattern)]
#[repr(transparent)]
pub struct Attributes(pub [u8; 8]);

#[derive(Debug, Clone, Copy, NoUninit, CheckedBitPattern)]
#[repr(C)]
pub struct EnclaveReportBody {
    pub cpu_svn: [u8; 16],
    pub misc_select: u32,
    _reserved1: Reserved<28>,
    pub attributes: [u8; 16],
    pub mr_enclave: [u8; 32],
    _reserved2: Reserved<32>,
    pub mr_signer: [u8; 32],
    _reserved3: Reserved<96>,
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    _reserved4: Reserved<60>,
    pub report_data: [u8; 64],
}
