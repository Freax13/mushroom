use core::{cmp::Ordering, fmt};

use bytemuck::{AnyBitPattern, CheckedBitPattern, NoUninit, Zeroable};
#[cfg(feature = "p384")]
use p384::ecdsa::Signature;

use crate::{Reserved, guest_policy::GuestPolicy};

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
    V3(AttestionReportV3) = 3,
}

impl AttestionReport {
    pub fn policy(&self) -> GuestPolicy {
        match self {
            AttestionReport::V2(report) => report.policy,
            AttestionReport::V3(report) => report.policy,
        }
    }

    pub fn vmpl(&self) -> u32 {
        match self {
            AttestionReport::V2(report) => report.vmpl,
            AttestionReport::V3(report) => report.vmpl,
        }
    }

    pub fn signature_algo(&self) -> u32 {
        match self {
            AttestionReport::V2(report) => report.signature_algo,
            AttestionReport::V3(report) => report.signature_algo,
        }
    }

    pub fn report_data(&self) -> [u8; 64] {
        match self {
            AttestionReport::V2(report) => report.report_data,
            AttestionReport::V3(report) => report.report_data,
        }
    }

    pub fn measurement(&self) -> [u8; 48] {
        match self {
            AttestionReport::V2(report) => report.measurement,
            AttestionReport::V3(report) => report.measurement,
        }
    }

    pub fn host_data(&self) -> [u8; 32] {
        match self {
            AttestionReport::V2(report) => report.host_data,
            AttestionReport::V3(report) => report.host_data,
        }
    }

    pub fn id_key_digest(&self) -> [u8; 48] {
        match self {
            AttestionReport::V2(report) => report.id_key_digest,
            AttestionReport::V3(report) => report.id_key_digest,
        }
    }

    pub fn launch_tcb(&self) -> TcbVersion {
        match self {
            AttestionReport::V2(report) => report.launch_tcb,
            AttestionReport::V3(report) => report.launch_tcb,
        }
    }

    pub fn signature(&self) -> [u8; 512] {
        match self {
            AttestionReport::V2(report) => report.signature,
            AttestionReport::V3(report) => report.signature,
        }
    }
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

#[derive(Debug, Clone, Copy, CheckedBitPattern)]
#[repr(C, packed)]
pub struct AttestionReportV3 {
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
    pub cpuid_fam_id: u8,
    pub cpuid_mod_id: u8,
    pub cpuid_step: u8,
    _reserved2: Reserved<21>,
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

#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct EcdsaP384Sha384Signature {
    pub r: [u8; 72],
    pub s: [u8; 72],
    _padding: [u8; 0x200 - 0x90],
}

#[cfg(feature = "p384")]
impl TryFrom<EcdsaP384Sha384Signature> for Signature {
    type Error = p384::ecdsa::Error;

    fn try_from(value: EcdsaP384Sha384Signature) -> Result<Self, Self::Error> {
        use p384::ecdsa::Error;

        let (r, rest) = value.r.split_first_chunk::<48>().unwrap();
        if rest != [0; 24] {
            // Make sure that r was zero-padded.
            return Err(Error::new());
        }
        let (s, rest) = value.s.split_first_chunk::<48>().unwrap();
        if rest != [0; 24] {
            // Make sure that s was zero-padded.
            return Err(Error::new());
        }
        let mut r = *r;
        let mut s = *s;
        r.reverse();
        s.reverse();
        Self::from_scalars(r, s)
    }
}

#[cfg(feature = "p384")]
impl From<Signature> for EcdsaP384Sha384Signature {
    fn from(value: Signature) -> Self {
        let r = value.r().to_bytes();
        let s = value.s().to_bytes();
        let mut r = <[u8; 48]>::from(r);
        let mut s = <[u8; 48]>::from(s);
        r.reverse();
        s.reverse();
        let mut zext_r = [0; 72];
        let mut zext_s = [0; 72];
        zext_r[0..48].copy_from_slice(&r);
        zext_s[0..48].copy_from_slice(&s);
        Self {
            r: zext_r,
            s: zext_s,
            _padding: [0; 0x200 - 0x90],
        }
    }
}

impl fmt::Debug for EcdsaP384Sha384Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaP384Sha384Signature")
            .field("r", &self.r)
            .field("s", &self.s)
            .finish()
    }
}

impl Default for EcdsaP384Sha384Signature {
    fn default() -> Self {
        Self::zeroed()
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(into = "StructuredTcbVersion", from = "StructuredTcbVersion")
)]
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

#[cfg(feature = "serde")]
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
struct StructuredTcbVersion {
    bootloader: u8,
    tee: u8,
    snp: u8,
    microcode: u8,
}

#[cfg(feature = "serde")]
impl From<TcbVersion> for StructuredTcbVersion {
    fn from(value: TcbVersion) -> Self {
        Self {
            bootloader: value.bootloader(),
            tee: value.tee(),
            snp: value.snp(),
            microcode: value.microcode(),
        }
    }
}

#[cfg(feature = "serde")]
impl From<StructuredTcbVersion> for TcbVersion {
    fn from(value: StructuredTcbVersion) -> Self {
        Self::new(value.bootloader, value.tee, value.snp, value.microcode)
    }
}
