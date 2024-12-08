use core::sync::atomic::Ordering;

use constants::ApIndex;
use snp_types::{intercept::VMEXIT_VMGEXIT, vmsa::SevFeatures};
use x86_64::instructions::hlt;

use crate::{
    exception::{eoi, pop_pending_event, send_ipi},
    ghcb::{create_ap, run_vmpl, vmsa_tweak_bitmap},
    per_cpu::PerCpu,
    scheduler::WAKE_UP_VECTOR,
    services::handle_commands,
};

use self::vmsa::Vmpl1Vmsa;

pub mod vmsa;

const SEV_FEATURES: SevFeatures = SevFeatures::from_bits_truncate(
    SevFeatures::SNP_ACTIVE.bits()
        | SevFeatures::V_TOM.bits()
        | SevFeatures::ALTERNATE_INJECTION.bits()
        | SevFeatures::VMSA_REG_PROT.bits(),
);

pub fn run_vcpu() -> ! {
    // Initialize the VMSA.
    let mut vmsa = unsafe { Vmpl1Vmsa::get() };
    unsafe {
        vmsa.set_runnable(true);
    }

    // Tell the host about the new VMSA.
    let vmsa_pa = vmsa.phys_addr();
    create_ap(vmsa_pa, SEV_FEATURES);

    let tweak_bitmap = vmsa_tweak_bitmap();

    loop {
        // Start the AP.
        run_vmpl(1);

        let guard = vmsa.modify();

        let mut resume = false;
        if guard.guest_exit_code(tweak_bitmap) == VMEXIT_VMGEXIT {
            handle_commands();
            resume |= guard.rax(tweak_bitmap) != 0;
        } else {
            resume = true;
        }

        loop {
            if PerCpu::get().interrupted.swap(false, Ordering::SeqCst) {
                resume = true;

                while let Some(vector) = pop_pending_event() {
                    match vector.get() {
                        WAKE_UP_VECTOR => eoi(),
                        vector => unimplemented!("unhandled vector: {vector}"),
                    }
                }
            }

            if resume {
                break;
            }

            hlt();
        }
    }
}

pub fn kick(apic_id: ApIndex) {
    send_ipi(u32::from(apic_id.as_u8()), WAKE_UP_VECTOR);
}
