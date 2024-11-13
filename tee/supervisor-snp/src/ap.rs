use core::cell::Cell;

use constants::{ApIndex, FIRST_AP, KICK_AP_PORT};
use snp_types::vmsa::SevFeatures;

use crate::{
    ghcb::{create_ap, ioio_write, vmsa_tweak_bitmap},
    FakeSync,
};

use self::vmsa::InitializedVmsa;

mod vmsa;

const SEV_FEATURES: SevFeatures = SevFeatures::from_bits_truncate(
    SevFeatures::SNP_ACTIVE.bits()
        | SevFeatures::V_TOM.bits()
        | SevFeatures::RESTRICTED_INJECTION.bits()
        | SevFeatures::VMSA_REG_PROT.bits(),
);

pub fn start_next_ap() {
    static APIC_COUNTER: FakeSync<Cell<u8>> = FakeSync::new(Cell::new(0));
    let counter = APIC_COUNTER.get();
    let Some(apic_id) = ApIndex::try_new(counter) else {
        return;
    };
    APIC_COUNTER.set(counter + 1);

    // Initialize the VMSA.
    let mut vmsa = InitializedVmsa::new(vmsa_tweak_bitmap(), u32::from(apic_id.as_u8()));
    unsafe {
        vmsa.set_runnable(true);
    }

    // Tell the host about the new VMSA.
    let vmsa_pa = vmsa.phys_addr();
    create_ap(u32::from(FIRST_AP + apic_id.as_u8()), vmsa_pa, SEV_FEATURES);

    // Start the AP.
    kick(apic_id);
}

pub fn kick(apic_id: ApIndex) {
    ioio_write(KICK_AP_PORT, u32::from(FIRST_AP + apic_id.as_u8()));
}
