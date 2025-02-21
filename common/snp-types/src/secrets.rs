use bytemuck::CheckedBitPattern;

use crate::{Reserved, vmsa::VmsaTweakBitmap};

#[derive(Debug, Clone, Copy, CheckedBitPattern)]
#[repr(u32, align(4096))]
pub enum Secrets {
    V3(SecretsV3) = 3,
}

#[derive(Debug, Clone, Copy, CheckedBitPattern)]
#[repr(C)]
pub struct SecretsV3 {
    pub imi_en: bool,
    _reserved1: Reserved<3>,
    pub fms: u32,
    _reserved2: Reserved<4>,
    pub gosvw: [u8; 16],
    pub vmpck0: [u8; 32],
    pub vmpck1: [u8; 32],
    pub vmpck2: [u8; 32],
    pub vmpck3: [u8; 32],
    _reserved3: Reserved<96>,
    pub vmsa_tweak_bitmap: VmsaTweakBitmap,
    _reserved4: Reserved<32>,
    pub tsc_factor: u32,
    _reserved5: Reserved<3740>,
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::Secrets;

    #[test]
    fn test_size() {
        assert_eq!(size_of::<Secrets>(), 0x1000);
        assert_eq!(align_of::<Secrets>(), 0x1000);
    }
}
