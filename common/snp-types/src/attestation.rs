use bytemuck::{AnyBitPattern, CheckedBitPattern, NoUninit};

use crate::{guest_policy::GuestPolicy, Reserved};

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit)]
#[repr(C)]
pub struct MsgReportReq {
    pub report_data: [u8; 64],
    pub vmpl: u32,
    pub key_select: KeySelect,
    _reserved: Reserved<24>,
}

impl MsgReportReq {
    pub fn new(report_data: [u8; 64], vmpl: u32, key_select: KeySelect) -> Self {
        Self {
            report_data,
            vmpl,
            key_select,
            _reserved: Reserved([0; 24]),
        }
    }
}

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit)]
#[repr(u32)]
pub enum KeySelect {
    PreferVlek = 0,
    Vcek = 1,
    Vlek = 2,
}

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit)]
#[repr(C)]
#[allow(dead_code)]
pub struct MsgReportRspHeader {
    pub status: MsgReportRspStatus,
    pub report_size: u32,
    _reserved: Reserved<24>,
}

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit, PartialEq, Eq)]
#[repr(u32)]
pub enum MsgReportRspStatus {
    Success = 0,
    InvalidParameters = 0x16,
    InvalidKeySelection = 0x17,
}

#[derive(Debug, Clone, Copy, CheckedBitPattern)]
#[repr(u32)]
pub enum AttestionReport {
    V2(AttestionReportV2) = 2,
}

#[derive(Debug, Clone, Copy, CheckedBitPattern)]
#[repr(C, packed)]
pub struct AttestionReportV2 {
    pub guest_svn: u32,
    pub policy: GuestPolicy,
    pub familiy_id: u128,
    pub image_id: u128,
    pub vmpl: u32,
    pub signature_algo: u32,
    pub current_tcb: TcbVersion,
    pub platform_info: u64,
    pub fixme_key_stuff: u32,
    _reserved1: Reserved<4>,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub id_key_digest: [u8; 48],
    pub author_key_digest: [u8; 48],
    pub report_id: [u8; 32],
    pub report_id_ma: [u8; 32],
    pub reported_tcb: TcbVersion,
    _reserved2: Reserved<24>,
    pub chip_id: [u8; 64],
    pub commited_tcb: TcbVersion,
    pub current_build: u8,
    pub current_minor: u8,
    pub current_major: u8,
    _reserved3: Reserved<1>,
    pub commited_build: u8,
    pub commited_minor: u8,
    pub commited_major: u8,
    _reserved4: Reserved<1>,
    pub launch_tcb: TcbVersion,
    _reserved5: Reserved<168>,
    pub signature: [u8; 512],
}

#[derive(Clone, Copy, AnyBitPattern)]
#[repr(C)]
pub struct EcdsaP384Sha384Signature {
    pub r: [u8; 72],
    pub s: [u8; 72],
}

#[derive(Debug, Clone, Copy, CheckedBitPattern)]
#[repr(transparent)]
pub struct TcbVersion([u8; 8]);

impl TcbVersion {
    /// SVN of PSP bootloader
    pub fn bootloader(&self) -> u8 {
        self.0[0]
    }

    /// SVN of PSP operating system
    pub fn tee(&self) -> u8 {
        self.0[1]
    }

    /// Security Version Number (SVN) of SNP firmware
    pub fn snp(&self) -> u8 {
        self.0[6]
    }

    /// Lowest current patch level of all cores
    pub fn microcode(&self) -> u8 {
        self.0[7]
    }
}
