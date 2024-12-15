use core::sync::atomic::Ordering;

use constants::ApIndex;
use snp_types::{
    intercept::{
        VMEXIT_CPUID, VMEXIT_INIT, VMEXIT_INTR, VMEXIT_INVALID, VMEXIT_NMI, VMEXIT_NPF,
        VMEXIT_PAUSE, VMEXIT_SMI, VMEXIT_VMMCALL,
    },
    vmsa::SevFeatures,
};
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
        | SevFeatures::VMSA_REG_PROT.bits()
        | SevFeatures::REFLECT_VC.bits(),
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
        // Run the AP.
        run_vmpl(1);

        // Handle the AP's #VC.

        let mut guard = vmsa.modify();

        // Take the exit code.
        let guest_exit_code = guard.guest_exit_code(tweak_bitmap);
        guard.set_guest_exit_code(VMEXIT_INVALID, tweak_bitmap);

        let mut resume = true;
        match guest_exit_code {
            VMEXIT_CPUID => {
                let eax = guard.rax(tweak_bitmap) as u32;
                let ecx = guard.rcx(tweak_bitmap) as u32;
                let (eax, ebx, ecx, edx) = emulate_cpuid(eax, ecx);
                guard.set_rax(u64::from(eax), tweak_bitmap);
                guard.set_rbx(u64::from(ebx), tweak_bitmap);
                guard.set_rcx(u64::from(ecx), tweak_bitmap);
                guard.set_rdx(u64::from(edx), tweak_bitmap);

                let next_rip = guard.guest_nrip(tweak_bitmap);
                guard.set_rip(next_rip, tweak_bitmap);
            }
            VMEXIT_VMMCALL => {
                handle_commands();
                resume = guard.rax(tweak_bitmap) != 0;

                let next_rip = guard.guest_nrip(tweak_bitmap);
                guard.set_rip(next_rip, tweak_bitmap);
            }
            VMEXIT_INTR | VMEXIT_NMI | VMEXIT_SMI | VMEXIT_INIT | VMEXIT_PAUSE | VMEXIT_NPF
            | VMEXIT_INVALID => {
                // We don't need to do anything for these. These are not really
                // reflected #VC events, but normal AE events. We occasionally
                // see these when there's an interrupt pending for VMPL0 and
                // the hypervisor enters VMPL0 even without a reflected #VC in
                // VMPL1.
            }
            unknown => unimplemented!("unknown exit code: {unknown:#x}"),
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

fn emulate_cpuid(eax: u32, ecx: u32) -> (u32, u32, u32, u32) {
    // These values are based on EPYC Milan.
    // TODO: Add support for other CPU models.
    match (eax, ecx) {
        (0x0000_0000, _) => (0x00000010, 0x68747541, 0x444d4163, 0x69746e65),
        (0x0000_0001, _) => (0x00a00f11, 0x51800800, 0x7eda320b, 0x178bfbff),
        (0x0000_0007, _) => (0x00000000, 0x219c95a9, 0x0040069c, 0x00000000),
        (0x0000_0008..=0x0000_000a, _) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (0x0000_000d, 0x00) => (0x00000207, 0x00000988, 0x00000988, 0x00000000),
        (0x0000_000d, 0x01) => (0x0000000f, 0x00000358, 0x00001800, 0x00000000),
        (0x0000_000d, 0x02) => (0x00000100, 0x00000240, 0x00000000, 0x00000000),
        (0x0000_000d, 0x03) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (0x0000_000d, 0x05) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (0x0000_000d, 0x06) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (0x0000_000d, 0x07) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (0x0000_000d, 0x0b) => (0x00000010, 0x00000000, 0x00000001, 0x00000000),
        (0x0000_000d, 0x0c) => (0x00000018, 0x00000000, 0x00000001, 0x00000000),
        (0x0000_000d, 0x0d..) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (0x0000_0011..=0x0000_ffff, _) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (0x8000_0000, _) => (0x80000023, 0x68747541, 0x444d4163, 0x69746e65),
        (0x8000_0001, _) => (0x00a00f11, 0x40000000, 0x75c237ff, 0x2fd3fbff),
        (0x8000_0007, _) => (0x00000000, 0x0000003b, 0x00000000, 0x00006799),
        (0x8000_0008, _) => (0x00003030, 0x91bef75f, 0x0000707f, 0x00010007),
        (0x8000_000a, _) => (0x00000001, 0x00008000, 0x00000000, 0x119b9cff),
        (0x8000_001d, _) => (0x00004121, 0x01c0003f, 0x0000003f, 0x00000000),
        (0x8000_0024..=0x8000_ffff, _) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        (eax, ecx) => todo!("unimplemented CPUID function eax={eax:#x}, ecx={ecx:#x}"),
    }
}
