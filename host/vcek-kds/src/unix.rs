use std::{
    fs::File,
    io::{Error, Result},
    os::fd::AsRawFd,
};

use bytemuck::{CheckedBitPattern, checked::try_pod_read_unaligned};
use nix::ioctl_readwrite;
use snp_types::attestation::TcbVersion;

use crate::VcekParameters;

impl VcekParameters {
    /// Determine the parameters of the current platform.
    pub fn current_parameters() -> Result<Self> {
        let product = Self::current_product()?;
        let sev_file = File::open("/dev/sev")?;
        let chip_id = chip_id(&sev_file)?;
        let tcb = reported_tcb(&sev_file)?;
        Ok(Self {
            product,
            chip_id,
            tcb,
        })
    }
}

unsafe fn sev_issue_cmd(file: &File, payload: SevIssueCmdPayload<'_>) -> Result<()> {
    let mut cmd = SevIssueCmd { payload, error: 0 };

    ioctl_readwrite!(sev_issue_cmd, b'S', 0x0, SevIssueCmd);
    unsafe {
        sev_issue_cmd(file.as_raw_fd(), &mut cmd)?;
    }

    Ok(())
}

pub fn chip_id(file: &File) -> Result<[u8; 64]> {
    let mut buffer = [0; 64];
    let mut sev_user_data_get_id2 = SevUserDataGetId2 {
        address: buffer.as_mut_ptr(),
        length: 64,
    };

    unsafe {
        sev_issue_cmd(
            file,
            SevIssueCmdPayload::SevUserDataGetId2(SevUserDataGetId2Payload(
                &mut sev_user_data_get_id2,
            )),
        )?;
    };

    Ok(buffer)
}

pub fn reported_tcb(file: &File) -> Result<TcbVersion> {
    let mut snp_platform_status_buffer = [0; 32];

    unsafe {
        sev_issue_cmd(
            file,
            SevIssueCmdPayload::SnpPlatformStatus(SnpPlatformStatusPayload(
                &mut snp_platform_status_buffer,
            )),
        )?;
    }

    let snp_platform_status_buffer =
        try_pod_read_unaligned::<SnpPlatformStatusBuffer>(&snp_platform_status_buffer)
            .map_err(|err| Error::new(std::io::ErrorKind::InvalidData, err))?;

    Ok(snp_platform_status_buffer.reported_tcb)
}

#[repr(C, packed)]
struct SevIssueCmd<'a> {
    payload: SevIssueCmdPayload<'a>,
    error: u32,
}

#[allow(dead_code)]
#[repr(C, u32)]
enum SevIssueCmdPayload<'a> {
    SevUserDataGetId2(SevUserDataGetId2Payload<'a>) = 8,
    SnpPlatformStatus(SnpPlatformStatusPayload<'a>),
}

#[repr(C, packed)]
struct SevUserDataGetId2Payload<'a>(&'a mut SevUserDataGetId2);

#[repr(C, packed)]
struct SevUserDataGetId2 {
    address: *mut u8,
    length: u32,
}

#[repr(C, packed)]
struct SnpPlatformStatusPayload<'a>(&'a mut [u8; 0x20]);

#[derive(Clone, Copy, CheckedBitPattern)]
#[repr(C)]
struct SnpPlatformStatusBuffer {
    api_major: u8,
    api_minor: u8,
    state: u8,
    is_rmp_init: u8,
    build_id: u32,
    features: u32,
    guest_count: u32,
    tcb_version: TcbVersion,
    reported_tcb: TcbVersion,
}
