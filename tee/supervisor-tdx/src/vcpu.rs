use core::{
    arch::{
        asm,
        x86_64::{__cpuid, __cpuid_count, _rdtsc, CpuidResult},
    },
    cmp,
    sync::atomic::{AtomicUsize, Ordering},
};

use bit_field::BitField;
use constants::{ApIndex, MAX_APS_COUNT, TIMER_VECTOR};
use spin::Lazy;
use supervisor_services::{SlotIndex, SupervisorCallNr};
use tdx_types::{
    tdcall::{
        Apic, GuestState, InvdTranslations, MdFieldId, TDX_L2_EXIT_HOST_ROUTED_ASYNC,
        TDX_L2_EXIT_PENDING_INTERRUPT, TDX_PENDING_INTERRUPT, TDX_SUCCESS, VmIndex,
    },
    vmexit::{
        VMEXIT_REASON_CPUID_INSTRUCTION, VMEXIT_REASON_MSR_WRITE,
        VMEXIT_REASON_PREEMPTION_TIMER_EXPIRED, VMEXIT_REASON_VMCALL_INSTRUCTION,
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
    dynamic::{allocate_memory, deallocate_memory},
    exception::{WAKEUP_TOKEN, WAKEUP_VECTOR, send_ipi},
    input, output,
    per_cpu::PerCpu,
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

    // Enable HLAT, EPT paging-write, and guest-paging verification.
    unsafe {
        Tdcall::vp_wr(
            MdFieldId::VMX_VM_EXECUTION_CONTROL_TERTIARY_PROC_BASED,
            (1 << 1) | (1 << 2) | (1 << 3),
            (1 << 1) | (1 << 2) | (1 << 3),
        );
    }

    // Configure HLAT.
    unsafe {
        Tdcall::vp_wr(MdFieldId::VMX_HLAT_PREFIX_SIZE, 1, u64::from(u16::MAX));
        Tdcall::vp_wr(MdFieldId::VMX_HLATP, 0x100_0001_0000, !0);
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

    update_tsc_deadline();
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
                let result = match guest_state.rax as u32 {
                    0x4000_0000 => CpuidResult {
                        eax: 0x40000001,
                        ebx: 0x4853554d,
                        ecx: 0x4d4f4f52,
                        edx: 0x504e5320,
                    },
                    0x4000_0001 => CpuidResult {
                        eax: 0x5452534d,
                        ebx: 0,
                        ecx: 0,
                        edx: 0,
                    },
                    _ => __cpuid_count(guest_state.rax as u32, guest_state.rcx as u32),
                };
                guest_state.rax = u64::from(result.eax);
                guest_state.rbx = u64::from(result.ebx);
                guest_state.rcx = u64::from(result.ecx);
                guest_state.rdx = u64::from(result.edx);
                guest_state.rip += u64::from(vm_exit.vm_exit_instruction_length);
            }
            VMEXIT_REASON_VMCALL_INSTRUCTION => {
                match guest_state.rax {
                    nr if nr == SupervisorCallNr::StartNextAp as u64 => start_next(),
                    nr if nr == SupervisorCallNr::Halt as u64 => {
                        interrupts::disable();
                        let resume =
                            WAKEUP_TOKEN.take(idx) || APICS[idx].pending_vector().is_some();
                        if resume {
                            interrupts::enable();
                        } else {
                            Vmcall::instruction_hlt(false, true);
                        }
                    }
                    nr if nr == SupervisorCallNr::Kick as u64 => {
                        let apic_id = ApIndex::new(u8::try_from(guest_state.rdi).unwrap());
                        send_ipi(u32::from(apic_id.as_u8()), WAKEUP_VECTOR);
                    }
                    nr if nr == SupervisorCallNr::AllocateMemory as u64 => {
                        let slot_index = allocate_memory();
                        guest_state.rax = u64::from(slot_index.get());
                    }
                    nr if nr == SupervisorCallNr::DeallocateMemory as u64 => {
                        let slot_index = guest_state.rdi;
                        let slot_index = SlotIndex::new(u16::try_from(slot_index).unwrap());
                        deallocate_memory(slot_index);
                    }
                    nr if nr == SupervisorCallNr::ReleaseInput as u64 => input::release(),
                    nr if nr == SupervisorCallNr::UpdateOutput as u64 => {
                        let chunk_len = guest_state.rdi;

                        let mut buffer = [0u8; 512];
                        unsafe {
                            asm!(
                                "vmovdqu [{dst} + 32 * 0],  ymm0",
                                "vmovdqu [{dst} + 32 * 1],  ymm1",
                                "vmovdqu [{dst} + 32 * 2],  ymm2",
                                "vmovdqu [{dst} + 32 * 3],  ymm3",
                                "vmovdqu [{dst} + 32 * 4],  ymm4",
                                "vmovdqu [{dst} + 32 * 5],  ymm5",
                                "vmovdqu [{dst} + 32 * 6],  ymm6",
                                "vmovdqu [{dst} + 32 * 7],  ymm7",
                                "vmovdqu [{dst} + 32 * 8],  ymm8",
                                "vmovdqu [{dst} + 32 * 9],  ymm9",
                                "vmovdqu [{dst} + 32 * 10], ymm10",
                                "vmovdqu [{dst} + 32 * 11], ymm11",
                                "vmovdqu [{dst} + 32 * 12], ymm12",
                                "vmovdqu [{dst} + 32 * 13], ymm13",
                                "vmovdqu [{dst} + 32 * 14], ymm14",
                                "vmovdqu [{dst} + 32 * 15], ymm15",
                                dst = in(reg) buffer.as_mut_ptr(),
                                options(preserves_flags),
                            );
                        }

                        let chunk = &buffer[..chunk_len as usize];
                        output::update_output(chunk);
                    }
                    nr if nr == SupervisorCallNr::FinishOutput as u64 => output::finish(),
                    nr if nr == SupervisorCallNr::FailOutput as u64 => {
                        output::fail();
                        panic!()
                    }
                    nr => unimplemented!("unknown supervisor call: {nr}"),
                }

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
            VMEXIT_REASON_PREEMPTION_TIMER_EXPIRED => {
                APICS[PerCpu::current_vcpu_index()].set_irr(TIMER_VECTOR);
                update_tsc_deadline();
            }
            unknown => panic!("{unknown:#x} {guest_state:x?} {vm_exit:x?}"),
        }
    }
}

/// Returns `delta(TSC)/s`.
fn tsc_frequency() -> u64 {
    // Try to get the frequency from cpuid.
    let result = __cpuid(0x15);
    assert_ne!(result.ebx, 0);
    u64::from(result.ecx) * u64::from(result.ebx) / u64::from(result.eax)
}

const TIMER_HZ: u64 = 100;
static TIMER_INTERRUPT_PERIOD: Lazy<u64> = Lazy::new(|| tsc_frequency() / TIMER_HZ);

/// Set the deadline to `now + TIMER_INTERRUPT_PERIOD`.
fn update_tsc_deadline() {
    unsafe {
        Tdcall::vp_wr(
            MdFieldId::TDVPS_TSC_DEADLINE,
            _rdtsc() + *TIMER_INTERRUPT_PERIOD,
            !0,
        );
    }
}
