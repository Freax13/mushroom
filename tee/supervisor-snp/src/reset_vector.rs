use core::arch::{global_asm, naked_asm};

use snp_types::vmsa::{SevFeatures, Vmsa, VmsaTweakBitmap};

use crate::main;

global_asm!(include_str!("reset_vector.s"));

#[export_name = "_start"]
#[naked]
extern "sysv64" fn start() -> ! {
    const STACK_SIZE: usize = 32 * 4096;
    #[link_section = ".stack"]
    static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

    unsafe {
        naked_asm!(
            "lea rsp, [rip + {STACK} + {STACK_SIZE}]",
            "and rsp, ~15",
            "call {PREMAIN}",
            "int3",
            STACK = sym STACK,
            STACK_SIZE = const STACK_SIZE,
            PREMAIN = sym premain,
        );
    }
}

extern "sysv64" fn premain() {
    main();
}

#[link_section = ".supervisor_vmsas"]
#[used]
static VMSA: Vmsa = {
    let mut vmsa = Vmsa::new();
    let tweak_bitmap = &VmsaTweakBitmap::ZERO;
    vmsa.set_sev_features(
        SevFeatures::from_bits_retain(
            SevFeatures::SNP_ACTIVE.bits()
                | SevFeatures::RESTRICTED_INJECTION.bits()
                | SevFeatures::SECURE_TSC.bits()
                | SevFeatures::VMSA_REG_PROT.bits(),
        ),
        tweak_bitmap,
    );
    vmsa.set_guest_tsc_scale(0x1_0000_0000, tweak_bitmap);
    vmsa
};
