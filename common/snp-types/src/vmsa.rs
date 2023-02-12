use bitflags::bitflags;
use bytemuck::{CheckedBitPattern, Pod, Zeroable};

use crate::{Reserved, Uninteresting};

#[derive(Clone, Copy, Debug, CheckedBitPattern, Zeroable)]
#[repr(C, align(4096))]
pub struct Vmsa {
    pub es: Segment,
    pub cs: Segment,
    pub ss: Segment,
    pub ds: Segment,
    pub fs: Segment,
    pub gs: Segment,
    pub gdtr: Segment,
    pub ldtr: Segment,
    pub idtr: Segment,
    pub tr: Segment,
    pub pl0_ssp: u64,
    pub pl1_ssp: u64,
    pub pl2_ssp: u64,
    pub pl3_ssp: u64,
    pub ucet: u64,
    pub _reserved1: Reserved<2>,
    pub vpml: u8,
    pub cpl: u8,
    pub _reserved2: Reserved<4>,
    pub efer: u64,
    pub _reserved3: Reserved<104>,
    pub xss: u64,
    pub cr4: u64,
    pub cr3: u64,
    pub cr0: u64,
    pub dr7: u64,
    pub dr6: u64,
    pub rflags: u64,
    pub rip: u64,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr0_addr_mask: u64,
    pub dr1_addr_mask: u64,
    pub dr2_addr_mask: u64,
    pub dr3_addr_mask: u64,
    pub _reserved4: Reserved<24>,
    pub rsp: u64,
    pub s_cet: u64,
    pub ssp: u64,
    pub isst_addr: u64,
    pub rax: u64,
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub sfmask: u64,
    pub kernel_gs_base: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub cr2: u64,
    pub _reserved5: Reserved<32>,
    pub g_pat: u64,
    pub dbgctl: u64,
    pub br_from: u64,
    pub br_to: u64,
    pub lsat_excp_from: u64,
    pub last_excp_to: u64,
    pub _reserved6: Reserved<72>,
    pub _reserved7: Reserved<8>,
    pub pkru: u32,
    pub tsc_aux: u32,
    pub guest_tsc_scale: u64,
    pub guest_tsc_offset: u64,
    pub reg_prot_nonce: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub _reserved8: Reserved<8>,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub _reserved9: Reserved<16, false>,
    pub guest_exit_info1: u64,
    pub guest_exit_info2: u64,
    pub guest_exit_int_info: u64,
    pub guest_nrip: u64,
    pub sev_features: SevFeatures,
    pub vintr_ctrl: u64,
    pub guest_exit_code: u64,
    pub virtual_tom: u64,
    pub tlb_id: u64,
    pub pcpu_id: u64,
    pub event_inj: u64,
    pub xcr0: u64,
    pub _reserved10: Reserved<16>,
    pub x87_dp: u64,
    pub mxcsr: u32,
    pub x87_ftw: u16,
    pub x87_fsw: u16,
    pub x87_fcw: u16,
    pub x87_fop: u16,
    pub x87_ds: u16,
    pub x87_cs: u16,
    pub x87_rip: u64,
    pub fpreg_x87: Uninteresting<[u8; 80]>,
    pub fpreg_xmm: Uninteresting<[u8; 256]>,
    pub fpreg_ymm: Uninteresting<[u8; 256]>,
    pub lbr_stack_state: Uninteresting<[u8; 256]>,
    pub lbr_select: u64,
    pub ibs_fetch_ctl: u64,
    pub ibs_fetch_linaddr: u64,
    pub ibs_op_ctl: u64,
    pub ibs_op_rip: u64,
    pub ibs_op_data: u64,
    pub ibs_op_data2: u64,
    pub ibs_op_data3: u64,
    pub ibs_dc_linaddr: u64,
    pub bp_ibstgt_rip: u64,
    pub ic_ibs_extd_ctl: u64,
    pub _padding: Reserved<2104>,
}

#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct Segment {
    pub selector: u16,
    pub attrib: u16,
    pub limit: u32,
    pub base: u64,
}

bitflags! {
    #[derive(Pod, Zeroable)]
    #[repr(transparent)]
    pub struct SevFeatures: u64 {
        const SNP_ACTIVE = 1 << 0;
        const V_TOM = 1 << 1;
        const REFLECT_VC = 1 << 2;
        const RESTRICTED_INJECTION = 1 << 3;
        const ALTERNATE_INJECTION = 1 << 4;
        const DEBUG_SWAP = 1 << 5;
        const PREVENT_HOST_IBS = 1 << 6;
        const BTB_ISOLATION = 1 << 7;
        const VMPL_SSSS = 1 << 8;
        const SECURE_TSC = 1 << 9;
        const VMGEXIT_PARAMETER = 1 << 10;
        const IBS_VIRTUALIZATION = 1 << 12;
        const VMSA_REG_PROT = 1 << 14;
        const SMT_PROTECTION = 1 << 15;
    }
}
