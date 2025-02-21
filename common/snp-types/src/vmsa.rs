//! Related to the VMSA. The VMSA type is aware of VMSA register protection.

use bit_field::BitArray;
use bitflags::bitflags;
use bytemuck::{CheckedBitPattern, Pod, Zeroable, bytes_of_mut};
use paste::paste;
use x86_64::registers::{
    control::{Cr0Flags, Cr4Flags, EferFlags},
    debug::{Dr6Flags, Dr7Flags},
    mxcsr::MxCsr,
    rflags::RFlags,
    xcontrol::XCr0Flags,
};

use crate::{Reserved, Uninteresting};

use core::{
    fmt::{self, Debug},
    mem::{offset_of, size_of},
};

macro_rules! vmsa_field_accessor {
    ($ident:ident: $ty:ty) => {
        // Don't emit anything if $vis is empty (default -> private).
    };
    // Setters for these fields should be unsafe.
    ($vis:vis vmpl: $ty:ty) => { vmsa_field_unsafe_accessor!($vis vmpl: $ty); };
    ($vis:vis sev_features: $ty:ty) => { vmsa_field_unsafe_accessor!($vis sev_features: $ty); };
    ($vis:vis efer: $ty:ty) => { vmsa_field_unsafe_accessor!($vis efer: $ty); };
    // Emit safe accessors for all other fields.
    ($vis:vis $ident:ident: $ty:ty) => { vmsa_field_safe_accessor!($vis $ident: $ty); };
}

macro_rules! vmsa_field_safe_accessor {
    ($vis:vis $ident:ident: $ty:ty) => {
        paste! {
            #[inline(always)]
            $vis const fn $ident(&self, tweak_bitmap: &VmsaTweakBitmap) -> $ty {
                let mut buffer = [0; size_of::<$ty>()];
                self.read(offset_of!(Self, $ident), &mut buffer, tweak_bitmap);
                unsafe { core::mem::transmute(buffer) }
            }

            #[inline(always)]
            $vis const fn [<set_ $ident>](&mut self, value: $ty, tweak_bitmap: &VmsaTweakBitmap) {
                let buffer: [u8; size_of::<$ty>()] = unsafe { core::mem::transmute(value) };
                self.write(offset_of!(Self, $ident), &buffer, tweak_bitmap);
            }
        }
    };
}

macro_rules! vmsa_field_unsafe_accessor {
    ($vis:vis $ident:ident: $ty:ty) => {
        paste! {
            #[inline(always)]
            $vis const fn $ident(&self, tweak_bitmap: &VmsaTweakBitmap) -> $ty {
                let mut buffer = [0; size_of::<$ty>()];
                self.read(offset_of!(Self, $ident), &mut buffer, tweak_bitmap);
                unsafe { core::mem::transmute(buffer) }
            }

            #[inline(always)]
            #[allow(clippy::missing_safety_doc)]
            $vis const unsafe fn [<set_ $ident>](&mut self, value: $ty, tweak_bitmap: &VmsaTweakBitmap) {
                let buffer: [u8; size_of::<$ty>()] = unsafe { core::mem::transmute(value) };
                self.write(offset_of!(Self, $ident), &buffer, tweak_bitmap);
            }
        }
    };
}

macro_rules! vmsa_def {
    (
        $($vis:vis $ident:ident: $ty:ty = $default:expr,)*
    ) => {
        #[derive(Clone, Copy, Pod, Zeroable)]
        #[repr(C, align(4096))]
        pub struct Vmsa {
            $($ident: [u8; size_of::<$ty>()],)*
        }

        #[expect(dead_code, clippy::missing_transmute_annotations, clippy::transmute_num_to_bytes)]
        impl Vmsa {
            pub const fn new() -> Self {
                Self {
                    $($ident: unsafe { core::mem::transmute::<$ty, _>($default) },)*
                }
            }

            $(
                vmsa_field_accessor!($vis $ident: $ty);
            )*
        }

        impl Default for Vmsa {
            fn default() -> Self {
                Self::new()
            }
        }

        struct DebugVmsa<'a> {
            bitmap: &'a VmsaTweakBitmap,
            vmsa: &'a Vmsa,
        }

        impl Debug for DebugVmsa<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut f = f.debug_struct("Vmsa");
                $(
                    f.field(::core::stringify!($ident), &self.vmsa.$ident(self.bitmap));
                )*
                f.finish()
            }
        }
    };
}

impl Vmsa {
    /// Read bytes from the VMSA and deobfuscate protected registers.
    #[inline(always)]
    const fn read(&self, mut offset: usize, mut buffer: &mut [u8], tweak_bitmap: &VmsaTweakBitmap) {
        while let Some((b, new_buffer)) = buffer.split_first_mut() {
            *b = unsafe { core::ptr::from_ref(self).cast::<u8>().add(offset).read() };
            self.apply_reg_prot_nonce(offset, b, tweak_bitmap);
            buffer = new_buffer;
            offset += 1;
        }
    }

    /// Write bytes to the VMSA and obfuscate protected registers.
    #[inline(always)]
    const fn write(
        &mut self,
        mut offset: usize,
        mut buffer: &[u8],
        tweak_bitmap: &VmsaTweakBitmap,
    ) {
        while let Some((b, new_buffer)) = buffer.split_first() {
            let mut b = *b;
            self.apply_reg_prot_nonce(offset, &mut b, tweak_bitmap);
            unsafe {
                core::ptr::from_mut(self).cast::<u8>().add(offset).write(b);
            }
            buffer = new_buffer;
            offset += 1;
        }
    }

    #[inline(always)]
    const fn apply_reg_prot_nonce(
        &self,
        offset: usize,
        value: &mut u8,
        tweak_bitmap: &VmsaTweakBitmap,
    ) {
        let bitmap_idx = offset / 8;
        let byte_idx = bitmap_idx / 8;
        let bit_offset = bitmap_idx % 8;
        let bitmap_byte = tweak_bitmap.bitmap[byte_idx];
        let bit = (bitmap_byte >> bit_offset) & 1 != 0;
        if bit {
            *value ^= self.reg_prot_nonce[offset % 8];
        }
    }

    /// Update the nonce and reencrypt all values in place.
    pub fn update_nonce(&mut self, new_nonce: u64, tweak_bitmap: &VmsaTweakBitmap) {
        let old_nonce = u64::from_ne_bytes(self.reg_prot_nonce);
        let nonce_update_xor = old_nonce ^ new_nonce;
        let nonce_update_xor = (nonce_update_xor).to_ne_bytes();
        self.reg_prot_nonce = new_nonce.to_ne_bytes();

        for (i, b) in bytes_of_mut(self).iter_mut().enumerate() {
            if tweak_bitmap.bitmap.get_bit(i / 8) {
                *b ^= nonce_update_xor[i % 8];
            }
        }
    }

    pub fn debug<'a>(&'a self, bitmap: &'a VmsaTweakBitmap) -> impl Debug + 'a {
        DebugVmsa { bitmap, vmsa: self }
    }
}

vmsa_def! {
    pub es: Segment = Segment::DATA,
    pub cs: Segment = Segment::CODE16,
    pub ss: Segment = Segment::DATA,
    pub ds: Segment = Segment::DATA,
    pub fs: Segment = Segment::FS_GS,
    pub gs: Segment = Segment::FS_GS,
    pub gdtr: Segment = Segment::NULL,
    pub ldtr: Segment = Segment::NULL,
    pub idtr: Segment = Segment::NULL,
    pub tr: Segment = Segment::NULL,
    pub pl0_ssp: u64 = 0,
    pub pl1_ssp: u64 = 0,
    pub pl2_ssp: u64 = 0,
    pub pl3_ssp: u64 = 0,
    pub ucet: u64 = 0,
    reserved1: Reserved<2, false> = Reserved::ZERO,
    pub vmpl: u8 = 0,
    pub cpl: u8 = 0,
    reserved2: Reserved<4, false> = Reserved::ZERO,
    pub efer: EferFlags = EferFlags::SECURE_VIRTUAL_MACHINE_ENABLE,
    reserved3: Reserved<104, false> = Reserved::ZERO,
    pub xss: u64 = 0,
    pub cr4: Cr4Flags = Cr4Flags::MACHINE_CHECK_EXCEPTION,
    pub cr3: u64 = 0,
    pub cr0: Cr0Flags = Cr0Flags::EXTENSION_TYPE,
    pub dr7: Dr7Flags = Dr7Flags::GENERAL_DETECT_ENABLE,
    pub dr6: Dr6Flags = Dr6Flags::from_bits_retain(0xffff0ff0),
    pub rflags: RFlags = RFlags::from_bits_retain(2),
    pub rip: u64 = 0xfff0,
    pub dr0: u64 = 0,
    pub dr1: u64 = 0,
    pub dr2: u64 = 0,
    pub dr3: u64 = 0,
    pub dr0_addr_mask: u64 = 0,
    pub dr1_addr_mask: u64 = 0,
    pub dr2_addr_mask: u64 = 0,
    pub dr3_addr_mask: u64 = 0,
    reserved4: Reserved<24, false> = Reserved::ZERO,
    pub rsp: u64 = 0,
    pub s_cet: u64 = 0,
    pub ssp: u64 = 0,
    pub isst_addr: u64 = 0,
    pub rax: u64 = 0,
    pub star: u64 = 0,
    pub lstar: u64 = 0,
    pub cstar: u64 = 0,
    pub sfmask: u64 = 0,
    pub kernel_gs_base: u64 = 0,
    pub sysenter_cs: u64 = 0,
    pub sysenter_esp: u64 = 0,
    pub sysenter_eip: u64 = 0,
    pub cr2: u64 = 0,
    reserved5: Reserved<32, false> = Reserved::ZERO,
    pub g_pat: u64 = 0x7040600070406,
    pub dbgctl: u64 = 0,
    pub br_from: u64 = 0,
    pub br_to: u64 = 0,
    pub lsat_excp_from: u64 = 0,
    pub last_excp_to: u64 = 0,
    reserved6: Reserved<72, false> = Reserved::ZERO,
    reserved7: Reserved<8, false> = Reserved::ZERO,
    pub pkru: u32 = 0,
    pub tsc_aux: u32 = 0,
    pub guest_tsc_scale: u64 = 0,
    pub guest_tsc_offset: u64 = 0,
    reg_prot_nonce: u64 = 0,
    pub rcx: u64 = 0,
    pub rdx: u64 = 0,
    pub rbx: u64 = 0,
    reserved8: Reserved<8, false> = Reserved::ZERO,
    pub rbp: u64 = 0,
    pub rsi: u64 = 0,
    pub rdi: u64 = 0,
    pub r8: u64 = 0,
    pub r9: u64 = 0,
    pub r10: u64 = 0,
    pub r11: u64 = 0,
    pub r12: u64 = 0,
    pub r13: u64 = 0,
    pub r14: u64 = 0,
    pub r15: u64 = 0,
    reserved9: Reserved<16, false> = Reserved::ZERO,
    pub guest_exit_info1: u64 = 0,
    pub guest_exit_info2: u64 = 0,
    pub guest_exit_int_info: u64 = 0,
    pub guest_nrip: u64 = 0,
    pub sev_features: SevFeatures = SevFeatures::SNP_ACTIVE,
    pub vintr_ctrl: u64 = 0,
    pub guest_exit_code: u64 = 0,
    pub virtual_tom: u64 = 0,
    pub tlb_id: u64 = 0,
    pub pcpu_id: u64 = 0,
    pub event_inj: u64 = 0,
    pub xcr0: XCr0Flags = XCr0Flags::X87,
    reserved10: Reserved<16, false> = Reserved::ZERO,
    pub x87_dp: u64 = 0,
    pub mxcsr: MxCsr = MxCsr::from_bits_retain(0x1f80),
    pub x87_ftw: u16 = 0,
    pub x87_fsw: u16 = 0,
    pub x87_fcw: u16 = 0x37f,
    pub x87_fop: u16 = 0,
    pub x87_ds: u16 = 0,
    pub x87_cs: u16 = 0,
    pub x87_rip: u64 = 0,
    pub fpreg_x87: Uninteresting<[u8; 80]> = Uninteresting::new([0; 80]),
    pub fpreg_xmm: Uninteresting<[u8; 256]> = Uninteresting::new([0; 256]),
    pub fpreg_ymm: Uninteresting<[u8; 256]> = Uninteresting::new([0; 256]),
    pub lbr_stack_state: Uninteresting<[u8; 256]> = Uninteresting::new([0; 256]),
    pub lbr_select: u64 = 0,
    pub ibs_fetch_ctl: u64 = 0,
    pub ibs_fetch_linaddr: u64 = 0,
    pub ibs_op_ctl: u64 = 0,
    pub ibs_op_rip: u64 = 0,
    pub ibs_op_data: u64 = 0,
    pub ibs_op_data2: u64 = 0,
    pub ibs_op_data3: u64 = 0,
    pub ibs_dc_linaddr: u64 = 0,
    pub bp_ibstgt_rip: u64 = 0,
    pub ic_ibs_extd_ctl: u64 = 0,
    padding: Reserved<2104, false> = Reserved::ZERO,
}

#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct Segment {
    pub selector: u16,
    pub attrib: u16,
    pub limit: u32,
    pub base: u64,
}

impl Segment {
    const DATA: Self = Self {
        selector: 0x10,
        attrib: 0xc93,
        limit: 0xffffffff,
        base: 0,
    };

    const CODE16: Self = Self {
        selector: 0xf000,
        attrib: 0x9a,
        limit: 0xffff,
        base: 0xffff0000,
    };

    pub const CODE64: Self = Self {
        selector: 0x08,
        attrib: 0x29b,
        limit: 0xffffffff,
        base: 0,
    };

    const FS_GS: Self = Self {
        selector: 0,
        attrib: 0x92,
        limit: 0xffff,
        base: 0,
    };

    const NULL: Self = Self {
        selector: 0,
        attrib: 0,
        limit: 0,
        base: 0,
    };
}

bitflags! {
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
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

/// The VMSA tweak bitmap
///
/// VMSA register protection will obfuscate some values in the VMSA by xor'ing
/// it with a nonce. This bitmap contains a bit for each quardword in the VMSA
/// describing whether register protection applies for the quadword.
#[derive(Debug, Clone, Copy, CheckedBitPattern)]
#[repr(transparent)]
pub struct VmsaTweakBitmap {
    bitmap: [u8; 0x40],
}

impl VmsaTweakBitmap {
    pub const ZERO: Self = Self { bitmap: [0; 0x40] };

    /// Returns if the field at `offset` is tweaked with the register
    /// protection nonce.
    pub fn is_tweaked(&self, offset: usize) -> bool {
        self.bitmap.get_bit(offset / 8)
    }
}
