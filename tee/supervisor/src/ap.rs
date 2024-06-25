use core::cell::RefCell;

use constants::{FIRST_AP, KICK_AP_PORT, MAX_APS_COUNT};
use log::{debug, info};
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

pub static APS: FakeSync<[RefCell<Ap>; MAX_APS_COUNT as usize]> =
    FakeSync::new([const { RefCell::new(Ap::new()) }; MAX_APS_COUNT as usize]);

pub enum Ap {
    Uninitialized,
    Initialized(Initialized),
}

impl Ap {
    pub const fn new() -> Self {
        Self::Uninitialized
    }

    pub fn start(&mut self, apic_id: u8) {
        debug!("initializing vcpu {apic_id}");

        assert!(matches!(self, Ap::Uninitialized));

        *self = Self::Initialized(Initialized::new(apic_id));

        let Self::Initialized(initialized) = self else {
            unreachable!();
        };
        initialized.boot();
    }
}

pub struct Initialized {
    apic_id: u8,
    vmsa: InitializedVmsa,
}

impl Initialized {
    pub fn new(apic_id: u8) -> Self {
        Initialized {
            apic_id,
            vmsa: InitializedVmsa::new(vmsa_tweak_bitmap(), u32::from(apic_id - FIRST_AP)),
        }
    }

    pub fn boot(&mut self) {
        unsafe {
            self.vmsa.set_runnable(true);
        }

        let vmsa_pa = self.vmsa.phys_addr();
        create_ap(u32::from(self.apic_id), vmsa_pa, SEV_FEATURES);

        self.kick();
    }

    pub fn kick(&mut self) {
        let apic_id = self.apic_id;
        ioio_write(KICK_AP_PORT, u32::from(apic_id));
    }
}

pub fn start_bsp() {
    info!("booting first AP");
    let mut first_ap = APS[0].borrow_mut();
    first_ap.start(FIRST_AP);
    drop(first_ap);
}
