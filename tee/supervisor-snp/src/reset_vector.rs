use core::{arch::global_asm, mem::MaybeUninit};

use constants::{ApIndex, MAX_APS_COUNT};
use snp_types::vmsa::{SevFeatures, Vmsa, VmsaTweakBitmap};
use x86_64::{VirtAddr, registers::model_specific::FsBase};

use crate::{main, per_cpu::PerCpu};

pub const STACK_SIZE: usize = 16;

global_asm!(
    include_str!("reset_vector.s"),
    MAX_APS_COUNT = const MAX_APS_COUNT,
    STACK_SIZE = const STACK_SIZE * 0x1000,
);

#[unsafe(export_name = "_start")]
extern "sysv64" fn premain(vcpu_index: ApIndex) {
    // Setup a `PerCpu` instance for the current cpu.
    let mut per_cpu = MaybeUninit::uninit();
    let ptr = per_cpu.as_mut_ptr();
    per_cpu.write(PerCpu::new(ptr, vcpu_index));
    FsBase::write(VirtAddr::from_ptr(ptr));

    main();
}

#[unsafe(link_section = ".supervisor_vmsas")]
#[used]
static VMSAS: [Vmsa; MAX_APS_COUNT as usize] = {
    let mut vmsas = [const { Vmsa::new() }; MAX_APS_COUNT as usize];
    let tweak_bitmap = &VmsaTweakBitmap::ZERO;

    let mut i = 0;
    while i < MAX_APS_COUNT {
        let vmsa = &mut vmsas[i as usize];

        unsafe {
            vmsa.set_sev_features(
                SevFeatures::from_bits_retain(
                    SevFeatures::SNP_ACTIVE.bits()
                        | SevFeatures::RESTRICTED_INJECTION.bits()
                        | SevFeatures::SECURE_TSC.bits()
                        | SevFeatures::VMSA_REG_PROT.bits(),
                ),
                tweak_bitmap,
            );
        }
        vmsa.set_guest_tsc_scale(0x1_0000_0000, tweak_bitmap);
        vmsa.set_rsi(i as u64, tweak_bitmap);

        i += 1;
    }

    vmsas
};
