use core::{
    arch::x86_64::__cpuid_count,
    cmp,
    sync::atomic::{AtomicUsize, Ordering},
};

use bit_field::BitField;
use constants::{ApIndex, MAX_APS_COUNT};
use tdx_types::{
    tdcall::{
        Apic, GuestState, InvdTranslations, MdFieldId, VmIndex, TDX_L2_EXIT_HOST_ROUTED_ASYNC,
        TDX_L2_EXIT_PENDING_INTERRUPT, TDX_PENDING_INTERRUPT, TDX_SUCCESS,
    },
    vmexit::{
        VMEXIT_REASON_CPUID_INSTRUCTION, VMEXIT_REASON_HLT_INSTRUCTION, VMEXIT_REASON_MSR_WRITE,
    },
};
use x86_64::{
    instructions::interrupts,
    registers::{
        control::{Cr0Flags, Cr4Flags, EferFlags},
        rflags::RFlags,
    },
};

use crate::{
    exception::{send_ipi, WAKEUP_VECTOR},
    per_cpu::PerCpu,
    services::handle,
    tdcall::{Tdcall, Vmcall},
};

static READY: AtomicUsize = AtomicUsize::new(0);

pub fn start_next() {
    let idx = READY.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    match idx.cmp(&usize::from(MAX_APS_COUNT)) {
        cmp::Ordering::Less => send_ipi(idx as u32 + 1, WAKEUP_VECTOR),
        cmp::Ordering::Equal => {} // Do nothing.
        cmp::Ordering::Greater => unreachable!(),
    }
}

/// Wait for the vCPU to be ready.
///
/// We start the vCPUs sequentially. The kernel will tell us when to start the
/// next vCPU.
pub fn wait_for_vcpu_start() {
    loop {
        interrupts::disable();

        let ready = READY.load(Ordering::Relaxed);
        if ready == usize::from(PerCpu::current_vcpu_index().as_u8()) {
            break;
        }

        Vmcall::instruction_hlt(false, true);
    }

    interrupts::enable();
}

/// Initialize the L2 VM.
pub fn init_vcpu() {
    // Enable access to the shared EPT.
    unsafe {
        Tdcall::vp_wr(
            MdFieldId::TDVPS_L2_CTLS1,
            u64::from(cfg!(not(feature = "harden"))),
            1,
        );
    }

    // Enable 64-bit mode.
    unsafe {
        Tdcall::vp_wr(MdFieldId::VMX_VM_ENTRY_CONTROL, 1 << 9, 1 << 9);
    }

    // Enabled mode-based execute control for EPT.
    unsafe {
        Tdcall::vp_wr(
            MdFieldId::VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED,
            1 << 22,
            1 << 22,
        );
    }

    // Adjust CS segment.
    unsafe {
        Tdcall::vp_wr(MdFieldId::VMX_GUEST_CS_ARBYTE, 0xa09b, !0);
    }

    let idx = PerCpu::current_vcpu_index();
    let apic = &APICS[idx];
    apic.set_id(u32::from(idx.as_u8()));
    unsafe {
        Tdcall::vp_wr(
            MdFieldId::VMX_VIRTUAL_APIC_PAGE_ADDRESS,
            apic as *const _ as u64,
            !0,
        );
    }

    unsafe {
        Tdcall::vp_wr(
            MdFieldId::VMX_GUEST_IA32_EFER,
            EferFlags::SYSTEM_CALL_EXTENSIONS.bits()
                | EferFlags::LONG_MODE_ENABLE.bits()
                | EferFlags::LONG_MODE_ACTIVE.bits()
                | EferFlags::NO_EXECUTE_ENABLE.bits(),
            !0,
        );
    }

    let cr4_flags = Cr4Flags::PHYSICAL_ADDRESS_EXTENSION.bits()
        | Cr4Flags::MACHINE_CHECK_EXCEPTION.bits()
        | Cr4Flags::PAGE_GLOBAL.bits()
        | Cr4Flags::OSFXSR.bits()
        | Cr4Flags::OSXMMEXCPT_ENABLE.bits()
        | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits()
        | Cr4Flags::FSGSBASE.bits()
        | Cr4Flags::PCID.bits()
        | Cr4Flags::OSXSAVE.bits()
        | Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION.bits()
        | Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION.bits();
    unsafe {
        Tdcall::vp_wr(MdFieldId::VMX_GUEST_CR4, cr4_flags, !0);
        Tdcall::vp_wr(MdFieldId::VMX_CR4_READ_SHADOW, cr4_flags, !0);
    }

    unsafe {
        Tdcall::vp_wr(MdFieldId::VMX_GUEST_CR3, 0x100_0000_1000, !0);
    }

    let cr0_flags = Cr0Flags::PROTECTED_MODE_ENABLE.bits()
        | Cr0Flags::MONITOR_COPROCESSOR.bits()
        | Cr0Flags::EXTENSION_TYPE.bits()
        | Cr0Flags::NUMERIC_ERROR.bits()
        | Cr0Flags::WRITE_PROTECT.bits()
        | Cr0Flags::PAGING.bits();
    unsafe {
        Tdcall::vp_wr(MdFieldId::VMX_GUEST_CR0, cr0_flags, !0);
        Tdcall::vp_wr(MdFieldId::VMX_CR0_READ_SHADOW, cr0_flags, !0);
    }

    unsafe {
        Tdcall::vp_wr(MdFieldId::STAR_WRITE, 0, MdFieldId::STAR_WRITE_MASK);
        Tdcall::vp_wr(MdFieldId::LSTAR_WRITE, 0, MdFieldId::LSTAR_WRITE_MASK);
        Tdcall::vp_wr(MdFieldId::SFMASK_WRITE, 0, MdFieldId::SFMASK_WRITE_MASK);
        Tdcall::vp_wr(
            MdFieldId::X2APIC_EOI_WRITE,
            0,
            MdFieldId::X2APIC_EOI_WRITE_MASK,
        );
    }
}

static APICS: [Apic; MAX_APS_COUNT as usize] = [const { Apic::new() }; MAX_APS_COUNT as usize];

pub fn run_vcpu() -> ! {
    let mut guest_state = GuestState {
        rax: 0,
        rcx: 0,
        rdx: 0,
        rbx: 0,
        rsp: 0xffff_8000_0400_3ff8,
        rbp: 0,
        rsi: 0,
        rdi: 0,
        r8: 0,
        r9: 0,
        r10: 0,
        r11: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rflags: RFlags::from_bits_retain(2),
        rip: 0xffff_8000_0000_0000,
        ssp: 0,
        guest_interrupt_status: 0,
    };

    let idx = PerCpu::current_vcpu_index();

    loop {
        interrupts::disable();

        // Update the RVI field.
        let rvi = APICS[idx].pending_vector().unwrap_or_default();
        guest_state
            .guest_interrupt_status
            .set_bits(0..8, u16::from(rvi));

        let vm_exit =
            Tdcall::vp_enter(VmIndex::One, InvdTranslations::None, &mut guest_state, true);

        match vm_exit.class {
            TDX_SUCCESS => {}
            TDX_L2_EXIT_HOST_ROUTED_ASYNC => continue,
            TDX_L2_EXIT_PENDING_INTERRUPT => continue,
            TDX_PENDING_INTERRUPT => continue,
            reason => unimplemented!("{reason:#010x}"),
        }

        match vm_exit.exit_reason {
            VMEXIT_REASON_CPUID_INSTRUCTION => {
                let result =
                    unsafe { __cpuid_count(guest_state.rax as u32, guest_state.rcx as u32) };
                guest_state.rax = u64::from(result.eax);
                guest_state.rbx = u64::from(result.ebx);
                guest_state.rcx = u64::from(result.ecx);
                guest_state.rdx = u64::from(result.edx);
                guest_state.rip += u64::from(vm_exit.vm_exit_instruction_length);
            }
            VMEXIT_REASON_HLT_INSTRUCTION => {
                interrupts::disable();
                let resume = guest_state.rax != 0 || APICS[idx].pending_vector().is_some();
                handle(resume);
                guest_state.rip += u64::from(vm_exit.vm_exit_instruction_length);
            }
            VMEXIT_REASON_MSR_WRITE => {
                let value = guest_state.rax.get_bits(..32) | (guest_state.rdx << 32);
                match guest_state.rcx {
                    // IA32_X2APIC_ICR
                    0x830 => {
                        // We don't support all options. Check that we support the fields.
                        assert_eq!(value.get_bits(8..11), 0); // Delivery Mode: Fixed
                        assert!(!value.get_bit(11)); // Destination Mode: Physical
                        assert!(value.get_bit(14)); // Level: Assert
                        assert_eq!(value.get_bits(18..20), 0b00); // Destination Shorthand: Destination

                        // Set the IRR bit in the APIC page.
                        let vector = value.get_bits(..8) as u8;
                        let destination = value.get_bits(32..) as u32;
                        let idx = ApIndex::new(destination as u8);
                        let was_set = APICS[idx].set_irr(vector);

                        // If the bit was not already set, send an IPI to the
                        // supervisor, so that it re-evaluates the RVI.
                        if !was_set {
                            send_ipi(destination, WAKEUP_VECTOR);
                        }
                    }
                    rcx => unimplemented!("MSR write: {rcx:#x}"),
                }
                guest_state.rip += u64::from(vm_exit.vm_exit_instruction_length);
            }
            unknown => panic!("{unknown:#x} {guest_state:x?} {vm_exit:x?}"),
        }
    }
}
