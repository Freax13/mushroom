use core::{
    arch::x86_64::__cpuid_count,
    cmp,
    sync::atomic::{AtomicUsize, Ordering},
};

use constants::MAX_APS_COUNT;
use tdx_types::{
    tdcall::{
        Apic, GuestState, InvdTranslations, MdFieldId, VmIndex, TDX_L2_EXIT_HOST_ROUTED_ASYNC,
        TDX_L2_EXIT_PENDING_INTERRUPT, TDX_PENDING_INTERRUPT, TDX_SUCCESS,
    },
    vmexit::{
        VMEXIT_REASON_CPUID_INSTRUCTION, VMEXIT_REASON_HLT_INSTRUCTION, VMEXIT_REASON_MSR_WRITE,
        VMEXIT_REASON_VMCALL_INSTRUCTION,
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
    tlb,
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
        if ready == PerCpu::current_vcpu_index() {
            break;
        }

        Vmcall::instruction_hlt(false, true);
    }

    interrupts::enable();
}

/// Initialize the L2 VM.
///
/// # Safety
///
/// The caller must ensure the `apic` is valid until the end of time.
pub unsafe fn init_vcpu(apic: &mut Apic) {
    let apic = core::ptr::from_mut(apic) as u64;

    // Enable access to the shared EPT.
    Tdcall::vp_wr(
        MdFieldId::TDVPS_L2_CTLS1,
        u64::from(cfg!(not(feature = "harden"))),
        1,
    );

    // Enable 64-bit mode.
    Tdcall::vp_wr(MdFieldId::VMX_VM_ENTRY_CONTROL, 1 << 9, 1 << 9);

    // Enabled mode-based execute control for EPT.
    Tdcall::vp_wr(
        MdFieldId::VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED,
        1 << 22,
        1 << 22,
    );

    // Adjust CS segment.
    Tdcall::vp_wr(MdFieldId::VMX_GUEST_CS_ARBYTE, 0xa09b, !0);

    Tdcall::vp_wr(MdFieldId::VMX_VIRTUAL_APIC_PAGE_ADDRESS, apic, !0);

    Tdcall::vp_wr(
        MdFieldId::VMX_GUEST_IA32_EFER,
        EferFlags::SYSTEM_CALL_EXTENSIONS.bits()
            | EferFlags::LONG_MODE_ENABLE.bits()
            | EferFlags::LONG_MODE_ACTIVE.bits()
            | EferFlags::NO_EXECUTE_ENABLE.bits(),
        !0,
    );

    Tdcall::vp_wr(
        MdFieldId::VMX_GUEST_CR4,
        Cr4Flags::PHYSICAL_ADDRESS_EXTENSION.bits()
            | Cr4Flags::MACHINE_CHECK_EXCEPTION.bits()
            | Cr4Flags::PAGE_GLOBAL.bits()
            | Cr4Flags::OSFXSR.bits()
            | Cr4Flags::OSXMMEXCPT_ENABLE.bits()
            | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits()
            | Cr4Flags::FSGSBASE.bits()
            | Cr4Flags::PCID.bits()
            | Cr4Flags::OSXSAVE.bits()
            | Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION.bits()
            | Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION.bits(),
        !0,
    );

    Tdcall::vp_wr(MdFieldId::VMX_GUEST_CR3, 0x100_0000_1000, !0);

    Tdcall::vp_wr(
        MdFieldId::VMX_GUEST_CR0,
        Cr0Flags::PROTECTED_MODE_ENABLE.bits()
            | Cr0Flags::MONITOR_COPROCESSOR.bits()
            | Cr0Flags::EXTENSION_TYPE.bits()
            | Cr0Flags::NUMERIC_ERROR.bits()
            | Cr0Flags::WRITE_PROTECT.bits()
            | Cr0Flags::PAGING.bits(),
        !0,
    );

    Tdcall::vp_wr(MdFieldId::STAR_WRITE, 0, MdFieldId::STAR_WRITE_MASK);
    Tdcall::vp_wr(MdFieldId::LSTAR_WRITE, 0, MdFieldId::LSTAR_WRITE_MASK);
}

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

    loop {
        interrupts::disable();
        tlb::pre_enter();
        let flush = if PerCpu::with(|per_cpu| per_cpu.pending_flushes.take()) {
            InvdTranslations::All
        } else {
            InvdTranslations::None
        };
        let (exit_reason, instruction_length) =
            Tdcall::vp_enter(VmIndex::One, flush, &mut guest_state, true);

        match (exit_reason >> 32) as u32 {
            TDX_SUCCESS => {}
            TDX_L2_EXIT_HOST_ROUTED_ASYNC => continue,
            TDX_L2_EXIT_PENDING_INTERRUPT => continue,
            TDX_PENDING_INTERRUPT => continue,
            reason => unimplemented!("{reason:#010x}"),
        }

        match exit_reason as u32 {
            VMEXIT_REASON_CPUID_INSTRUCTION => {
                let result =
                    unsafe { __cpuid_count(guest_state.rax as u32, guest_state.rcx as u32) };
                guest_state.rax = u64::from(result.eax);
                guest_state.rbx = u64::from(result.ebx);
                guest_state.rcx = u64::from(result.ecx);
                guest_state.rdx = u64::from(result.edx);
                guest_state.rip += u64::from(instruction_length);
            }
            VMEXIT_REASON_HLT_INSTRUCTION => {
                handle(guest_state.rax != 0);
                guest_state.rip += u64::from(instruction_length);
            }
            VMEXIT_REASON_VMCALL_INSTRUCTION => {
                // The kernel currently only executes vmcalls to flush the TLB.
                // Double-check this.
                assert_eq!(
                    guest_state.rcx, 0x10002,
                    "unsupported request: {:#x}",
                    guest_state.rcx
                );
                assert_eq!(
                    guest_state.rdx, 3,
                    "unsupported flags: {:#x}",
                    guest_state.rdx
                );

                tlb::flush();

                guest_state.rax = 0;
                guest_state.rip += u64::from(instruction_length);
            }
            VMEXIT_REASON_MSR_WRITE => {
                match guest_state.rcx {
                    0x40000000 => {
                        // Ignore writes to HV_X64_MSR_GUEST_OS_ID.
                    }
                    rcx => panic!("{rcx:#x}"),
                }
                guest_state.rip += u64::from(instruction_length);
            }
            unknown => panic!("{unknown:#x} {guest_state:x?}"),
        }
    }
}
