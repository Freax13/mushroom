use core::{cmp::Ordering, fmt};

use bytemuck::{bytes_of, CheckedBitPattern, NoUninit};

use crate::Reserved;

#[derive(Clone, Copy, NoUninit, CheckedBitPattern)]
#[repr(C, align(1024))]
pub struct TdReport {
    pub report_mac: ReportMac,
    pub tee_tcb_info: TeeTcbInfo,
    _reserved: Reserved<17>,
    pub td_info: TdInfo,
}

#[derive(Clone, Copy, NoUninit, CheckedBitPattern)]
#[repr(C, align(256))]
pub struct ReportMac {
    pub report_type: ReportType,
    _reserved1: Reserved<12>,
    pub cpu_svn: CpuSvn,
    pub tee_tcb_info_hash: [u8; 48],
    pub tee_info_hash: [u8; 48],
    pub report_data: ReportData,
    _reserved2: Reserved<32>,
    pub mac: [u8; 32],
}

#[derive(Clone, Copy, NoUninit, CheckedBitPattern)]
#[repr(C, align(64))]
pub struct ReportData(pub [u8; 64]);

#[derive(Clone, Copy, NoUninit, CheckedBitPattern)]
#[repr(C)]
pub struct ReportType {
    pub ty: u8,
    pub sub_type: u8,
    pub version: u8,
    _reserved: Reserved<1>,
}

#[derive(Clone, Copy, NoUninit, CheckedBitPattern)]
#[repr(C)]
pub struct TeeTcbInfo {
    pub valid: [u8; 8],
    pub tee_tcb_svn: TeeTcbSvn,
    pub mr_seam: [u8; 48],
    pub mr_signer_seam: [u8; 48],
    pub attributes: [u8; 8],
    pub tee_tcb_svn2: TeeTcbSvn,
    _reserved: Reserved<95>,
}

#[derive(Clone, Copy, NoUninit, CheckedBitPattern, PartialEq, Eq)]
#[repr(C)]
pub struct TeeTcbSvn {
    pub tdx_module_svn_minor: u8,
    pub tdx_module_svn_major: u8,
    pub seam_last_patch_svn: u8,
    _reserved: Reserved<13>,
}

impl TeeTcbSvn {
    pub fn new(
        tdx_module_svn_minor: u8,
        tdx_module_svn_major: u8,
        seam_last_patch_svn: u8,
    ) -> Self {
        Self {
            tdx_module_svn_minor,
            tdx_module_svn_major,
            seam_last_patch_svn,
            _reserved: Reserved::default(),
        }
    }
}

impl PartialOrd for TeeTcbSvn {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let this_bytes = bytes_of(self);
        let other_bytes = bytes_of(other);
        if self == other {
            Some(Ordering::Equal)
        } else if this_bytes
            .iter()
            .copied()
            .zip(other_bytes.iter().copied())
            .all(|(this, other)| this >= other)
        {
            Some(Ordering::Greater)
        } else if this_bytes
            .iter()
            .copied()
            .zip(other_bytes.iter().copied())
            .all(|(this, other)| this <= other)
        {
            Some(Ordering::Less)
        } else {
            None
        }
    }
}

impl fmt::Debug for TeeTcbSvn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeeTcbSvn")
            .field("tdx_module_svn_minor", &self.tdx_module_svn_minor)
            .field("tdx_module_svn_major", &self.tdx_module_svn_major)
            .field("seam_last_patch_svn", &self.seam_last_patch_svn)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, NoUninit, CheckedBitPattern)]
#[repr(C)]
pub struct CpuSvn([u8; 16]);

#[derive(Clone, Copy, NoUninit, CheckedBitPattern)]
#[repr(C)]
pub struct TdInfo {
    pub base: TdInfoBase,
    _reserved: Reserved<64>,
}

#[derive(Clone, Copy, NoUninit, CheckedBitPattern)]
#[repr(C)]
pub struct TdInfoBase {
    pub attributes: u64,
    pub xfam: u64,
    pub mr_td: [u8; 48],
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_owner_config: [u8; 48],
    pub rtmr: [[u8; 48]; 4],
    pub servtd_hash: [u8; 48],
}
