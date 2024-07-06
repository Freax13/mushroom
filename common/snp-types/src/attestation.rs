use core::{cmp::Ordering, fmt};

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

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct TcbVersion([u8; 8]);

impl TcbVersion {
    pub const fn new(bootloader: u8, tee: u8, snp: u8, microcode: u8) -> Self {
        Self([bootloader, tee, 0, 0, 0, 0, snp, microcode])
    }
}

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

impl PartialEq for TcbVersion {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for TcbVersion {}

impl PartialOrd for TcbVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (
            self.bootloader().cmp(&other.bootloader()),
            self.tee().cmp(&other.tee()),
            self.snp().cmp(&other.snp()),
            self.microcode().cmp(&other.microcode()),
        ) {
            (Ordering::Equal, Ordering::Equal, Ordering::Equal, Ordering::Equal) => {
                // The versions are equal if all components are equal.
                Some(Ordering::Equal)
            }
            (
                Ordering::Greater | Ordering::Equal,
                Ordering::Greater | Ordering::Equal,
                Ordering::Greater | Ordering::Equal,
                Ordering::Greater | Ordering::Equal,
            ) => {
                // The version is greater if all components are greater or
                // equal and they're not all equal.
                Some(Ordering::Greater)
            }
            (
                Ordering::Equal | Ordering::Less,
                Ordering::Equal | Ordering::Less,
                Ordering::Equal | Ordering::Less,
                Ordering::Equal | Ordering::Less,
            ) => {
                // The version is less if all components are less or equal and
                // they're not all equal.
                Some(Ordering::Less)
            }
            // Otherwise some components of `self` are newer and some
            // components of `other` are newer. We consider these TCB unordered
            // relative to one another.
            _ => None,
        }
    }
}

impl fmt::Debug for TcbVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcbVersion")
            .field("bootloader", &self.bootloader())
            .field("tee", &self.tee())
            .field("snp", &self.snp())
            .field("microcode", &self.microcode())
            .finish()
    }
}

unsafe impl CheckedBitPattern for TcbVersion {
    type Bits = [u8; 8];

    fn is_valid_bit_pattern(bits: &Self::Bits) -> bool {
        // Make sure that the reserved bytes are zero.
        bits[2..6] == [0; 4]
    }
}
