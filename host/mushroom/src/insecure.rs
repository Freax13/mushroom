//! This module makes it possible to run the mushroom kernel outside a SNP VM
//! and without the supervisor.

use core::{
    arch::x86_64::__cpuid_count,
    iter::{Iterator, repeat_with},
};
use std::{
    iter::once,
    os::unix::thread::JoinHandleExt,
    sync::{
        Arc, Condvar, LazyLock, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use bit_field::BitField;
use bytemuck::bytes_of;
use constants::{
    INSECURE_SUPERVISOR_CALL_PORT, MAX_APS_COUNT, TIMER_VECTOR,
    physical_address::{DYNAMIC_2MIB, kernel, supervisor},
};
use kvm_bindings::{
    CpuId, KVM_CAP_X86_USER_SPACE_MSR, KVM_MAX_CPUID_ENTRIES, Xsave, kvm_cpuid_entry2,
    kvm_enable_cap, kvm_interrupt, kvm_segment, kvm_userspace_memory_region, kvm_xcr, kvm_xcrs,
    kvm_xsave, kvm_xsave2,
};
use kvm_ioctls::{Cap, Kvm, VcpuExit, VcpuFd};
use loader::Input;
use mushroom_verify::{HashedInput, InputHash, OutputHash, forge_insecure_attestation_report};
use nix::{
    libc::{EFAULT, EINTR},
    sys::{
        mman::{MmapAdvise, madvise},
        pthread::pthread_kill,
        signal::SigEvent,
        time::TimeSpec,
        timer::{Timer, TimerSetTimeFlags},
    },
    time::ClockId,
    unistd::gettid,
};
use supervisor_services::{SlotIndex, SupervisorCallNr};
use tracing::info;
use vmm_sys_util::fam::FamStruct;
use x86_64::{
    registers::{
        control::{Cr0Flags, Cr4Flags},
        model_specific::EferFlags,
        xcontrol::XCr0Flags,
    },
    structures::paging::{PageSize, Size2MiB, Size4KiB},
};

use crate::{
    MushroomResult, OutputEvent, SIG_KICK, TSC_MHZ, install_signal_handler,
    logging::start_log_collection, slot::Slot,
};

static KVM_XSAVE_SIZE: OnceLock<usize> = OnceLock::new();
const XMM_OFFSET: usize = 0xa0;
static YMM_OFFSET: LazyLock<usize> = LazyLock::new(|| {
    let res = unsafe { __cpuid_count(0xd, 0x2) };
    assert_eq!(res.eax, 256, "CPU doesn't support AVX");
    res.ebx as usize
});

const TIMER_PERIOD: Duration = Duration::from_millis(10);

/// Create the VM, load the kernel, init & input and run the APs.
pub fn main(
    kvm: &Kvm,
    kernel: &[u8],
    init: &[u8],
    load_kasan_shadow_mappings: bool,
    inputs: &[Input<impl AsRef<[u8]>>],
    timeout: Duration,
) -> Result<MushroomResult> {
    let mut cpuid_entries = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
    let piafb = cpuid_entries
        .as_mut_slice()
        .iter_mut()
        .find(|entry| entry.function == 1 && entry.index == 0)
        .context("failed to find 'processor info and feature bits' entry")?;
    // Enable CPUID
    piafb.ecx.set_bit(21, true);

    let mut cpuid_entries = cpuid_entries.as_slice().to_vec();
    for entry in kvm
        .get_supported_hv_cpuid(KVM_MAX_CPUID_ENTRIES)?
        .as_slice()
        .iter()
        .copied()
    {
        if let Some(e) = cpuid_entries
            .iter_mut()
            .find(|e| e.function == entry.function && e.index == entry.index)
        {
            *e = entry;
        } else {
            cpuid_entries.push(entry);
        }
    }

    // Push CPUID entries advertising the insecure supervisor call interface.
    cpuid_entries.push(kvm_cpuid_entry2 {
        function: 0x4000_0100,
        index: 0,
        flags: 0,
        eax: 0x40000101,
        ebx: 0x4853554d,
        ecx: 0x4d4f4f52,
        edx: 0x534e4920,
        padding: [0; 3],
    });
    cpuid_entries.push(kvm_cpuid_entry2 {
        function: 0x4000_0101,
        index: 0,
        flags: 0,
        eax: 0x4952534d,
        ebx: 0,
        ecx: 0,
        edx: 0,
        padding: [0; 3],
    });

    let cpuid_entries = CpuId::from_entries(&cpuid_entries).unwrap();

    let vm = kvm.create_vm()?;
    let vm = Arc::new(vm);

    const KVM_MSR_EXIT_REASON_UNKNOWN: u64 = 1;
    const KVM_MSR_EXIT_REASON_FILTER: u64 = 2;
    vm.enable_cap(&kvm_enable_cap {
        cap: KVM_CAP_X86_USER_SPACE_MSR,
        args: [
            KVM_MSR_EXIT_REASON_UNKNOWN | KVM_MSR_EXIT_REASON_FILTER,
            0,
            0,
            0,
        ],
        ..Default::default()
    })
    .context("failed to enable user space MSR handling")?;

    vm.set_tsc_khz(TSC_MHZ * 1000)?;

    if KVM_XSAVE_SIZE.get().is_none() {
        let xsave_size = vm.check_extension_int(Cap::Xsave2);
        let fam_size = (xsave_size as usize - std::mem::size_of::<kvm_xsave>())
            .div_ceil(std::mem::size_of::<<kvm_xsave2 as FamStruct>::Entry>());
        let _ = KVM_XSAVE_SIZE.set(fam_size);
    }
    let (mut load_commands, _host_data) =
        loader::generate_load_commands(None, kernel, init, load_kasan_shadow_mappings, inputs);
    let mut memory_slots = Vec::new();
    while let Some(first_load_command) = load_commands.next() {
        let gpa = first_load_command.physical_address;

        // Figure out how big the next slot can be by counting pages with
        // contiguous GPAs.
        let num_pages = 1 + load_commands
            .clone()
            .zip(1..)
            .take_while(|(next, i)| next.physical_address == gpa + *i)
            .count();

        // Create and map the slot.
        let slot = Slot::new2(&vm, gpa, num_pages * Size4KiB::SIZE as usize, true, false)
            .context("failed to create slot")?;
        let slot_id = u16::try_from(memory_slots.len())?;
        let shared_mapping = slot.shared_mapping().unwrap();
        let memory_region = kvm_userspace_memory_region {
            slot: u32::from(slot_id),
            guest_phys_addr: gpa.start_address().as_u64(),
            memory_size: num_pages as u64 * Size4KiB::SIZE,
            userspace_addr: shared_mapping.as_ptr().as_ptr().addr() as u64,
            ..Default::default()
        };
        unsafe {
            vm.set_user_memory_region(memory_region)
                .context("failed to add memory region")?;
        }

        // Populate the slot's content.
        let pages = once(first_load_command)
            .chain(load_commands.by_ref())
            .take(num_pages);
        for command in pages {
            let ptr = slot.shared_ptr(command.physical_address.start_address())?;
            ptr.write(*command.payload.bytes());
        }

        memory_slots.push(slot);
    }

    let len =
        DYNAMIC_2MIB.end.start_address().as_u64() - DYNAMIC_2MIB.start.start_address().as_u64();
    let len = usize::try_from(len)?;
    let dynamic_slot = Slot::new2(&vm, DYNAMIC_2MIB.start, len, true, false)?;
    let slot_id = u16::try_from(memory_slots.len())?;
    let shared_mapping = dynamic_slot.shared_mapping().unwrap();
    let memory_region = kvm_userspace_memory_region {
        slot: u32::from(slot_id),
        guest_phys_addr: DYNAMIC_2MIB.start.start_address().as_u64(),
        memory_size: len as u64,
        userspace_addr: shared_mapping.as_ptr().as_ptr().addr() as u64,
        ..Default::default()
    };
    unsafe {
        vm.set_user_memory_region(memory_region)
            .context("failed to add memory region")?;
    }
    let dynamic_slot = Arc::new(dynamic_slot);

    info!("launched");

    install_signal_handler();

    // Create a bunch of APs.
    let dynamic_memory = Arc::new(Mutex::new(DynamicMemory::new()));
    let (sender, receiver) = mpsc::channel();
    let started = Arc::new(AtomicUsize::new(1));
    let run_states = repeat_with(RunState::default)
        .take(usize::from(MAX_APS_COUNT))
        .collect::<Arc<[_]>>();
    let aps = (0..MAX_APS_COUNT)
        .map(|i| {
            let ap = vm.create_vcpu(u64::from(i))?;
            ap.set_cpuid2(&cpuid_entries)?;
            Ok(ap)
        })
        .collect::<Result<Vec<_>>>()?;
    let threads = (0..MAX_APS_COUNT)
        .zip(aps)
        .map(|(i, ap)| {
            let sender = sender.clone();
            let dynamic_slot = dynamic_slot.clone();
            let dynamic_memory = dynamic_memory.clone();
            let started = started.clone();
            let run_states = run_states.clone();
            std::thread::spawn(move || {
                let res = run_kernel_vcpu(
                    i,
                    ap,
                    &sender,
                    &dynamic_slot,
                    &dynamic_memory,
                    &started,
                    &run_states,
                );
                if let Err(err) = res {
                    let _ = sender.send(OutputEvent::Fail(err));
                }
            })
        })
        .collect::<Vec<_>>();
    run_states[0].kick();
    start_log_collection(&memory_slots, kernel::LOG_BUFFER)?;
    start_log_collection(&memory_slots, supervisor::LOG_BUFFER)?;

    // Collect the output and report.
    let mut output: Vec<u8> = Vec::new();
    let res = loop {
        let res = receiver.recv_timeout(timeout);
        match res {
            Ok(event) => match event {
                OutputEvent::Write(mut vec) => output.append(&mut vec),
                OutputEvent::Finish(()) => {
                    let input_hash = InputHash::new(inputs.iter().map(HashedInput::new));
                    let output_hash = OutputHash::new(&output);
                    break Ok(forge_insecure_attestation_report(input_hash, output_hash));
                }
                OutputEvent::Fail(err) => break Err(err),
            },
            Err(err) => break Err(err).context("workload timed out"),
        }
    };

    // Stop all vCPUs.
    for run_state in run_states.iter() {
        run_state.stop();
    }

    // Force all threads to exit out of KVM_RUN, so that they can observe
    // that their run state has been marked as stopped and exit.
    for handle in threads {
        let _ = pthread_kill(handle.as_pthread_t(), SIG_KICK);
        handle.join().unwrap();
    }

    Ok(MushroomResult {
        output,
        attestation_report: res?,
    })
}

fn run_kernel_vcpu(
    id: u8,
    mut ap: VcpuFd,
    sender: &mpsc::Sender<OutputEvent<()>>,
    dynamic_slot: &Slot,
    dynamic_memory: &Mutex<DynamicMemory>,
    started: &AtomicUsize,
    run_states: &[RunState],
) -> Result<()> {
    let mut sregs = ap.get_sregs()?;
    sregs.es = DATA64;
    sregs.cs = CODE64;
    sregs.ss = DATA64;
    sregs.ds = DATA64;
    sregs.efer = EferFlags::SYSTEM_CALL_EXTENSIONS.bits()
        | EferFlags::LONG_MODE_ENABLE.bits()
        | EferFlags::LONG_MODE_ACTIVE.bits()
        | EferFlags::NO_EXECUTE_ENABLE.bits();
    sregs.cr4 = Cr4Flags::PHYSICAL_ADDRESS_EXTENSION.bits()
        | Cr4Flags::PAGE_GLOBAL.bits()
        | Cr4Flags::OSFXSR.bits()
        | Cr4Flags::OSXMMEXCPT_ENABLE.bits()
        | Cr4Flags::FSGSBASE.bits()
        | Cr4Flags::OSXSAVE.bits()
        | Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION.bits()
        | Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION.bits();
    sregs.cr3 = 0x100_0000_0000;
    sregs.cr0 = Cr0Flags::PROTECTED_MODE_ENABLE.bits()
        | Cr0Flags::MONITOR_COPROCESSOR.bits()
        | Cr0Flags::EXTENSION_TYPE.bits()
        | Cr0Flags::WRITE_PROTECT.bits()
        | Cr0Flags::PAGING.bits();
    ap.set_sregs(&sregs)?;
    let mut xcrs = kvm_xcrs {
        nr_xcrs: 1,
        ..Default::default()
    };
    xcrs.xcrs[0] = kvm_xcr {
        xcr: 0,
        value: XCr0Flags::X87.bits() | XCr0Flags::SSE.bits() | XCr0Flags::AVX.bits(),
        ..Default::default()
    };
    ap.set_xcrs(&xcrs)?;

    let mut regs = ap.get_regs()?;
    regs.rip = 0xffff_8000_0000_0000;
    regs.rsp = 0xffff_8000_0400_3ff8;
    ap.set_regs(&regs)?;

    let xsave_size = *KVM_XSAVE_SIZE.get().unwrap();

    let run_state = &run_states[usize::from(id)];
    run_state.wait(Duration::MAX);

    // Setup a timer to reguluarly kick the thread out of KVM_RUN.
    let mut timer = Timer::new(
        ClockId::CLOCK_MONOTONIC,
        SigEvent::new(nix::sys::signal::SigevNotify::SigevThreadId {
            signal: SIG_KICK,
            thread_id: gettid().as_raw(),
            si_value: 0,
        }),
    )?;
    timer.set(
        nix::sys::timer::Expiration::Interval(TimeSpec::from_duration(TIMER_PERIOD)),
        TimerSetTimeFlags::empty(),
    )?;
    let mut last_timer_injection = Instant::now();
    let mut in_service_timer_irq = false;

    while !run_state.is_stopped() {
        // Check if we need to inject a timer interrupt.
        if !in_service_timer_irq && last_timer_injection.elapsed() >= TIMER_PERIOD {
            let kvm_run = ap.get_kvm_run();
            let cr8 = kvm_run.cr8;
            if cr8 != 0 && cr8 <= u64::from(TIMER_VECTOR >> 4) {
                // The interrupt has been blocked out by the TPR. Don't ask to
                // be notified about the interrupt window for now.
                kvm_run.request_interrupt_window = 0;
            } else if kvm_run.ready_for_interrupt_injection != 0 {
                // The interrupt is ready.

                // Stop asking for the interrupt window.
                kvm_run.request_interrupt_window = 0;

                // Inject the interrupt.
                ap.interrupt(&kvm_interrupt {
                    irq: u32::from(TIMER_VECTOR),
                })?;

                last_timer_injection = Instant::now();
                in_service_timer_irq = true;
            } else {
                // Ask to be notified when the guest can receive an interrupt.
                kvm_run.request_interrupt_window = 1;
            }
        }

        // Run the AP.
        let res = ap.run();
        let exit = match res {
            Ok(exit) => exit,
            Err(err) if err.errno() == EINTR => continue,
            Err(err) if err.errno() == EFAULT => {
                // The VM has been shut down.
                break;
            }
            Err(err) => panic!("{err}"),
        };

        // Check the exit.
        match exit {
            VcpuExit::IoOut(port, _) if port == INSECURE_SUPERVISOR_CALL_PORT => {
                let mut regs = ap.get_regs()?;
                match regs.rax {
                    nr if nr == SupervisorCallNr::StartNextAp as u64 => {
                        let next_idx = started.fetch_add(1, Ordering::Relaxed);
                        if let Some(run_state) = run_states.get(next_idx) {
                            run_state.kick();
                        }
                    }
                    nr if nr == SupervisorCallNr::Halt as u64 => {
                        let timeout = TIMER_PERIOD.saturating_sub(last_timer_injection.elapsed());
                        run_state.wait(timeout);
                    }
                    nr if nr == SupervisorCallNr::Kick as u64 => {
                        let index = regs.rdi as usize;
                        run_states[index].kick();
                    }
                    nr if nr == SupervisorCallNr::AllocateMemory as u64 => {
                        let slot_idx = dynamic_memory
                            .lock()
                            .unwrap()
                            .allocate_slot_id()
                            .context("OOM")?;
                        regs.rax = u64::from(slot_idx.get());
                        ap.set_regs(&regs)?;
                    }
                    nr if nr == SupervisorCallNr::DeallocateMemory as u64 => {
                        let slot_idx = SlotIndex::new(u16::try_from(regs.rdi)?);
                        dynamic_memory.lock().unwrap().deallocate_slot_id(slot_idx);

                        // Remove the backing memory.
                        let shared_mapping = dynamic_slot.shared_mapping().unwrap();
                        let offset = usize::from(slot_idx.get()) * Size2MiB::SIZE as usize;
                        unsafe {
                            let addr = shared_mapping.as_ptr().byte_add(offset);
                            madvise(addr, Size2MiB::SIZE as usize, MmapAdvise::MADV_DONTNEED)?;
                        }
                    }
                    nr if nr == SupervisorCallNr::UpdateOutput as u64 => {
                        let chunk_len = regs.rdi as usize;

                        let mut xsave_buffer = Xsave::new(xsave_size)?;
                        unsafe {
                            ap.get_xsave2(&mut xsave_buffer)?;
                        }

                        let xsave = bytes_of(&xsave_buffer.as_fam_struct_ref().xsave.region);
                        let xmm = &xsave[XMM_OFFSET..][..16 * 16];
                        let ymm = &xsave[*YMM_OFFSET..][..16 * 16];

                        // The xmm and ymm registers are split into two
                        // buffers. Reassemble the values into a single
                        // contigous buffer.
                        let mut buffer = [0; 512];
                        for (dst, src) in buffer.chunks_mut(16).zip(
                            xmm.chunks(16)
                                .zip(ymm.chunks(16))
                                .flat_map(|(lower, upper)| [lower, upper]),
                        ) {
                            dst.copy_from_slice(src);
                        }

                        let chunk = &buffer[..chunk_len];
                        sender.send(OutputEvent::Write(chunk.to_owned()))?;
                    }
                    nr if nr == SupervisorCallNr::FinishOutput as u64 => {
                        sender.send(OutputEvent::Finish(()))?;
                        break;
                    }
                    nr if nr == SupervisorCallNr::FailOutput as u64 => {
                        bail!("workload failed");
                    }
                    nr => unimplemented!("unknown supervisor call: {nr}"),
                }
            }
            VcpuExit::X86Rdmsr(msr) => {
                const GUEST_TSC_FREQ: u32 = 0xC001_0134;
                match msr.index {
                    GUEST_TSC_FREQ => *msr.data = u64::from(TSC_MHZ),
                    _ => todo!(),
                }
            }
            VcpuExit::X86Wrmsr(msr) => match msr.index {
                // EOI.
                0x80b => in_service_timer_irq = false,
                index => unimplemented!("unimplemented MSR write to {index:#x}"),
            },
            VcpuExit::IrqWindowOpen => {}
            VcpuExit::Intr => {}
            VcpuExit::SetTpr => {}
            exit => panic!("unexpected exit {exit:?}"),
        }
    }

    Ok(())
}

#[derive(Default)]
struct RunState {
    running: Mutex<NextRunStateValue>,
    condvar: Condvar,
}

impl RunState {
    pub fn kick(&self) {
        let mut guard = self.running.lock().unwrap();
        if let NextRunStateValue::Halted = *guard {
            *guard = NextRunStateValue::Ready;
            drop(guard);
            self.condvar.notify_all();
        }
    }

    pub fn stop(&self) {
        *self.running.lock().unwrap() = NextRunStateValue::Stopped;
        self.condvar.notify_all();
    }

    pub fn is_stopped(&self) -> bool {
        *self.running.lock().unwrap() == NextRunStateValue::Stopped
    }

    pub fn wait(&self, timeout: Duration) {
        drop(
            self.condvar
                .wait_timeout_while(
                    self.running.lock().unwrap(),
                    timeout,
                    |state| match *state {
                        NextRunStateValue::Halted => {
                            // Keep waiting.
                            true
                        }
                        NextRunStateValue::Ready => {
                            // Consume the ready state and return.
                            *state = NextRunStateValue::Halted;
                            false
                        }
                        NextRunStateValue::Stopped => {
                            // Don't update the state, but return.
                            false
                        }
                    },
                )
                .unwrap(),
        );
    }
}

/// This enum describes the action of a vCPU *after* its next request to be halted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum NextRunStateValue {
    /// The vCPU has requested to be halted or hasn't been started yet.
    #[default]
    Halted,
    /// The vCPU can run.
    Ready,
    /// The VM has been stopped.
    Stopped,
}

const SLOTS: usize = 1 << 15;

struct DynamicMemory {
    in_use: [bool; SLOTS],
}

impl DynamicMemory {
    pub fn new() -> Self {
        Self {
            in_use: [false; SLOTS],
        }
    }

    pub fn allocate_slot_id(&mut self) -> Option<SlotIndex> {
        // Find a slot that's not in use.
        let slot_id = self.in_use.iter().position(|&in_use| !in_use)?;
        // Mark the slot as in-use.
        self.in_use[slot_id] = true;
        // Return the slot index.
        let slot_id = u16::try_from(slot_id).unwrap();
        Some(SlotIndex::new(slot_id))
    }

    pub fn deallocate_slot_id(&mut self, id: SlotIndex) {
        self.in_use[usize::from(id.get())] = false;
    }
}

const CODE64: kvm_segment = kvm_segment {
    base: 0,
    limit: 0xffff_ffff,
    selector: 0x10,
    type_: 0xb,
    present: 1,
    dpl: 0,
    db: 0,
    s: 1,
    l: 1,
    g: 1,
    avl: 0,
    unusable: 0,
    padding: 0,
};
const DATA64: kvm_segment = kvm_segment {
    base: 0,
    limit: 0xffff_ffff,
    selector: 0x10,
    type_: 0x3,
    present: 1,
    dpl: 0,
    db: 1,
    s: 1,
    l: 0,
    g: 1,
    avl: 0,
    unusable: 0,
    padding: 0,
};
