use core::sync::atomic::Ordering;

use bit_field::BitField;
use constants::{ApIndex, AtomicApBitmap};
use snp_types::{
    intercept::{
        VMEXIT_CPUID, VMEXIT_INIT, VMEXIT_INTR, VMEXIT_INVALID, VMEXIT_MSR, VMEXIT_NMI, VMEXIT_NPF,
        VMEXIT_PAUSE, VMEXIT_SMI, VMEXIT_VMMCALL,
    },
    vmsa::SevFeatures,
};
use supervisor_services::{SlotIndex, SupervisorCallNr};
use x86_64::instructions::hlt;

use crate::{
    dynamic::{allocate_memory, deallocate_memory},
    exception::{eoi, pop_pending_event, send_ipi},
    ghcb::{create_ap, exit, run_vmpl, vmsa_tweak_bitmap},
    output,
    per_cpu::PerCpu,
    scheduler::{start_next_ap, TIMER_VECTOR, WAKE_UP_VECTOR},
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

static WAKEUP_TOKEN: AtomicApBitmap = AtomicApBitmap::empty();

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

    let mut halted = false;
    let mut requested_timer_irq = false;
    let mut in_service_timer_irq = false;
    loop {
        // Handle interrupts.
        if PerCpu::get().interrupted.swap(false, Ordering::SeqCst) {
            while let Some(vector) = pop_pending_event() {
                match vector.get() {
                    WAKE_UP_VECTOR => eoi(),
                    TIMER_VECTOR => {
                        requested_timer_irq = true;
                        eoi();
                    }
                    vector => unimplemented!("unhandled vector: {vector}"),
                }
            }
        }

        // Don't halt if we can a timer IRQ.
        if requested_timer_irq && !in_service_timer_irq {
            halted = false;
        }

        // See if the kernel was kicked.
        if halted && WAKEUP_TOKEN.get(PerCpu::current_vcpu_index()) {
            halted = false;
        }

        // Halt if the kernel requested to halt.
        if halted {
            hlt();
            continue;
        }

        // Inject pending timer IRQ if possible.
        if !in_service_timer_irq && requested_timer_irq {
            let mut guard = vmsa.modify();
            let mut vintr_ctrl = guard.vintr_ctrl(tweak_bitmap);
            // Check if V_IRQ is not already set.
            if !vintr_ctrl.get_bit(8) {
                // Set V_IRQ.
                vintr_ctrl.set_bit(8, true);
                // Set VGIF.
                vintr_ctrl.set_bit(9, true);
                // Set V_INTR_PRIO.
                vintr_ctrl.set_bits(16..=19, 2);
                // Clear V_IGN_TPR.
                vintr_ctrl.set_bit(20, false);
                // Set V_INTR_VECTOR.
                vintr_ctrl.set_bits(32..=39, u64::from(constants::TIMER_VECTOR));

                guard.set_vintr_ctrl(vintr_ctrl, tweak_bitmap);

                requested_timer_irq = false;
                in_service_timer_irq = true;
            }
        }

        // Run the AP.
        run_vmpl(1);

        let mut guard = vmsa.modify();

        // Check if the busy bit is set.
        let mut vintr_ctrl = guard.vintr_ctrl(tweak_bitmap);
        if vintr_ctrl.get_bit(63) {
            // Transfer the pending exception to the event_inj field.

            let guext_exit_int_info = guard.guest_exit_int_info(tweak_bitmap);
            assert!(guext_exit_int_info.get_bit(31)); // Make sure that event is valid.
            guard.set_guest_exit_int_info(0, tweak_bitmap);

            let event_inj = guard.event_inj(tweak_bitmap);
            assert_eq!(event_inj, 0); // Make sure there's not already an event that should be injected.
            guard.set_event_inj(guext_exit_int_info, tweak_bitmap);

            // Clear the busy bit.
            vintr_ctrl.set_bit(63, false);
            guard.set_vintr_ctrl(vintr_ctrl, tweak_bitmap);
            continue;
        }

        // Handle the AP's reflected #VC.

        // Take the exit code.
        let guest_exit_code = guard.guest_exit_code(tweak_bitmap);
        guard.set_guest_exit_code(VMEXIT_INVALID, tweak_bitmap);

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
            VMEXIT_MSR => {
                // Make sure that the MSR access was a write.
                assert_eq!(guard.guest_exit_info1(tweak_bitmap), 1);

                match guard.rcx(tweak_bitmap) as u32 {
                    0x80b => in_service_timer_irq = false, // EOI.
                    unknown => unimplemented!("unimplemented MSR write {unknown:#x}"),
                }

                let next_rip = guard.guest_nrip(tweak_bitmap);
                guard.set_rip(next_rip, tweak_bitmap);
            }
            VMEXIT_VMMCALL => {
                match guard.rax(tweak_bitmap) {
                    nr if nr == SupervisorCallNr::StartNextAp as u64 => start_next_ap(),
                    nr if nr == SupervisorCallNr::Halt as u64 => halted = true,
                    nr if nr == SupervisorCallNr::Kick as u64 => {
                        let apic_id = ApIndex::new(u8::try_from(guard.rdi(tweak_bitmap)).unwrap());
                        WAKEUP_TOKEN.set(apic_id);
                        send_ipi(u32::from(apic_id.as_u8()), WAKE_UP_VECTOR);
                    }
                    nr if nr == SupervisorCallNr::AllocateMemory as u64 => {
                        let slot_index = allocate_memory();
                        guard.set_rax(u64::from(slot_index.get()), tweak_bitmap);
                    }
                    nr if nr == SupervisorCallNr::DeallocateMemory as u64 => {
                        let slot_index = guard.rdi(tweak_bitmap);
                        let slot_index = SlotIndex::new(u16::try_from(slot_index).unwrap());
                        deallocate_memory(slot_index);
                    }
                    nr if nr == SupervisorCallNr::UpdateOutput as u64 => {
                        let chunk_len = guard.rdi(tweak_bitmap);
                        let xmm = guard.fpreg_xmm(tweak_bitmap);
                        let ymm = guard.fpreg_ymm(tweak_bitmap);

                        // The xmm and ymm registers are split into two
                        // buffers. Reassemble the values into a single
                        // contigous buffer.
                        let mut buffer = [0; 512];
                        for (dst, src) in buffer.chunks_mut(16).zip(
                            xmm.0
                                .chunks(16)
                                .zip(ymm.0.chunks(16))
                                .flat_map(|(lower, upper)| [lower, upper]),
                        ) {
                            dst.copy_from_slice(src);
                        }

                        let chunk = &buffer[..chunk_len as usize];
                        output::update_output(chunk);
                    }
                    nr if nr == SupervisorCallNr::FinishOutput as u64 => output::finish(),
                    nr if nr == SupervisorCallNr::FailOutput as u64 => {
                        output::fail();
                        exit()
                    }
                    nr => unimplemented!("unknown supervisor call: {nr}"),
                }

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
    }
}

fn emulate_cpuid(eax: u32, ecx: u32) -> (u32, u32, u32, u32) {
    // These values are based on EPYC Milan.
    // TODO: Add support for other CPU models.
    match (eax, ecx) {
        // basic range
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
        // extended range
        (0x8000_0000, _) => (0x80000023, 0x68747541, 0x444d4163, 0x69746e65),
        (0x8000_0001, _) => (0x00a00f11, 0x40000000, 0x75c237ff, 0x2fd3fbff),
        (0x8000_0007, _) => (0x00000000, 0x0000003b, 0x00000000, 0x00006799),
        (0x8000_0008, _) => (0x00003030, 0x91bef75f, 0x0000707f, 0x00010007),
        (0x8000_000a, _) => (0x00000001, 0x00008000, 0x00000000, 0x119b9cff),
        (0x8000_001d, _) => (0x00004121, 0x01c0003f, 0x0000003f, 0x00000000),
        (0x8000_0024..=0x8000_ffff, _) => (0x00000000, 0x00000000, 0x00000000, 0x00000000),
        // hypervisor/supervisor range
        (0x4000_0000, _) => (0x40000001, 0x4853554d, 0x4d4f4f52, 0x504e5320),
        (0x4000_0001, _) => (0x5352534d, 0, 0, 0),
        (eax, ecx) => todo!("unimplemented CPUID function eax={eax:#x}, ecx={ecx:#x}"),
    }
}
