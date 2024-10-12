#[derive(Clone, Copy)]
#[repr(C, align(1024))]
pub struct TdReport {
    pub report_mac: ReportMac,
    pub tee_tcb_info: TeeTcbInfo,
    _reserved: [u8; 17],
    pub td_info: TdInfo,
}

#[derive(Clone, Copy)]
#[repr(C, align(256))]
pub struct ReportMac {
    pub report_type: ReportType,
    _reserved1: [u8; 12],
    pub cpu_svn: CpuSvn,
    pub tee_tcb_info_hash: [u8; 48],
    pub tee_info_hash: [u8; 48],
    pub report_data: ReportData,
    _reserved2: [u8; 32],
    pub mac: [u8; 32],
}

#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct ReportData(pub [u8; 64]);

#[derive(Clone, Copy)]
pub struct ReportType {
    pub ty: u8,
    pub sub_type: u8,
    pub version: u8,
    _reserved: u8,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TeeTcbInfo {
    pub valid: [u8; 8],
    pub tee_tcb_svn: TeeTcbSvn,
    pub mr_seam: [u8; 48],
    pub mr_signer_seam: [u8; 48],
    pub attributes: [u8; 8],
    pub tee_tcb_svn2: TeeTcbSvn,
    pub _reserved: [u8; 95],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TeeTcbSvn {
    pub tdx_module_svn_minor: u8,
    pub tdx_module_svn_major: u8,
    pub seam_last_patch_svn: u8,
    reserved: [u8; 13],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct CpuSvn([u8; 16]);

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TdInfo {
    pub base: TdInfoBase,
    _reserved: [u8; 64],
}

#[derive(Clone, Copy)]
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
