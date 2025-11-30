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
use constants::{
    INSECURE_SUPERVISOR_CALL_PORT, MAX_APS_COUNT, TIMER_VECTOR,
    physical_address::{DYNAMIC_2MIB, kernel, supervisor},
};
use loader::Input;
use mushroom_verify::{HashedInput, InputHash, OutputHash, forge_insecure_attestation_report};
use nix::{
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
use volatile::map_field;
use x86_64::{
    registers::{
        control::{Cr0Flags, Cr4Flags},
        model_specific::EferFlags,
        xcontrol::XCr0Flags,
    },
    structures::paging::{PageSize, Size2MiB},
};

use crate::{
    MushroomResult, OutputEvent, SIG_KICK, TSC_MHZ, install_signal_handler, is_efault,
    kvm::{KvmCap, KvmCpuidEntry2, KvmExit, KvmHandle, KvmSegment, VcpuHandle},
    logging::start_log_collection,
    slot::Slot,
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
    kvm_handle: &KvmHandle,
    kernel: &[u8],
    init: &[u8],
    load_kasan_shadow_mappings: bool,
    inputs: &[Input<impl AsRef<[u8]>>],
    timeout: Duration,
) -> Result<MushroomResult> {
    let mut cpuid_entries = kvm_handle.get_supported_cpuid()?;
    let piafb = cpuid_entries
        .iter_mut()
        .find(|entry| entry.function == 1 && entry.index == 0)
        .context("failed to find 'processor info and feature bits' entry")?;
    // Enable CPUID
    piafb.ecx.set_bit(21, true);

    let mut cpuid_entries = Vec::from(cpuid_entries);
    for entry in kvm_handle.get_supported_hv_cpuid()?.iter().copied() {
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
    cpuid_entries.push(KvmCpuidEntry2 {
        function: 0x4000_0100,
        index: 0,
        flags: 0,
        eax: 0x40000101,
        ebx: 0x4853554d,
        ecx: 0x4d4f4f52,
        edx: 0x534e4920,
        padding: [0; 3],
    });
    cpuid_entries.push(KvmCpuidEntry2 {
        function: 0x4000_0101,
        index: 0,
        flags: 0,
        eax: 0x4952534d,
        ebx: 0,
        ecx: 0,
        edx: 0,
        padding: [0; 3],
    });

    let vm = kvm_handle.create_vm()?;
    let vm = Arc::new(vm);

    const KVM_MSR_EXIT_REASON_UNKNOWN: u64 = 1;
    const KVM_MSR_EXIT_REASON_FILTER: u64 = 2;
    vm.enable_capability(
        KvmCap::X86_USER_SPACE_MSR,
        KVM_MSR_EXIT_REASON_UNKNOWN | KVM_MSR_EXIT_REASON_FILTER,
    )?;

    vm.set_tsc_khz(TSC_MHZ * 1000)?;

    if KVM_XSAVE_SIZE.get().is_none() {
        let xsave_size = kvm_handle.check_extension(KvmCap::XSAVE2)?;
        let xsave_size = xsave_size
            .context("KVM doesn't support KVM_CAP_XSAVE2")?
            .get() as usize;
        let _ = KVM_XSAVE_SIZE.set(xsave_size);
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
        let slot = Slot::new(&vm, gpa, num_pages * 0x1000, true, false)
            .context("failed to create slot")?;
        let slot_id = u16::try_from(memory_slots.len())?;
        unsafe {
            vm.map_encrypted_memory(slot_id, &slot)?;
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
    let dynamic_slot = Slot::new(&vm, DYNAMIC_2MIB.start, len, true, false)?;
    let slot_id = u16::try_from(memory_slots.len())?;
    unsafe {
        vm.map_encrypted_memory(slot_id, &dynamic_slot)?;
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
            let ap = vm.create_vcpu(i32::from(i))?;
            ap.set_cpuid(&cpuid_entries)?;
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
    ap: VcpuHandle,
    sender: &mpsc::Sender<OutputEvent<()>>,
    dynamic_slot: &Slot,
    dynamic_memory: &Mutex<DynamicMemory>,
    started: &AtomicUsize,
    run_states: &[RunState],
) -> Result<()> {
    let kvm_run = ap.get_kvm_run_block()?;
    let kvm_run = kvm_run.as_ptr();

    let mut sregs = ap.get_sregs()?;
    sregs.es = KvmSegment::DATA64;
    sregs.cs = KvmSegment::CODE64;
    sregs.ss = KvmSegment::DATA64;
    sregs.ds = KvmSegment::DATA64;
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
    ap.set_sregs(sregs)?;
    ap.set_xcr(
        0,
        XCr0Flags::X87.bits() | XCr0Flags::SSE.bits() | XCr0Flags::AVX.bits(),
    )?;

    let mut regs = ap.get_regs()?;
    regs.rip = 0xffff_8000_0000_0000;
    regs.rsp = 0xffff_8000_0400_3ff8;
    ap.set_regs(regs)?;

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
            let cr8 = map_field!(kvm_run.cr8).read();
            if cr8 != 0 && cr8 <= u64::from(TIMER_VECTOR >> 4) {
                // The interrupt has been blocked out by the TPR. Don't ask to
                // be notified about the interrupt window for now.
                map_field!(kvm_run.request_interrupt_window).write(0);
            } else if map_field!(kvm_run.ready_for_interrupt_injection).read() != 0 {
                // The interrupt is ready.

                // Stop asking for the interrupt window.
                map_field!(kvm_run.request_interrupt_window).write(0);

                // Inject the interrupt.
                ap.interrupt(TIMER_VECTOR)?;

                last_timer_injection = Instant::now();
                in_service_timer_irq = true;
            } else {
                // Ask to be notified when the guest can receive an interrupt.
                map_field!(kvm_run.request_interrupt_window).write(1);
            }
        }

        // Run the AP.
        let res = ap.run();
        match res {
            Ok(_) => {}
            Err(err) if is_efault(&err) => {
                // The VM has been shut down.
                break;
            }
            Err(err) => {
                panic!("{err}");
            }
        }

        // Check the exit.
        let kvm_run_value = kvm_run.read();
        let mut exit = kvm_run_value.exit();
        match exit {
            KvmExit::Io(io) if io.port == INSECURE_SUPERVISOR_CALL_PORT => {
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
                        ap.set_regs(regs)?;
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

                        let mut xsave_buffer = vec![0; xsave_size];
                        unsafe {
                            ap.get_xsave2(&mut xsave_buffer)?;
                        }

                        let xmm = &xsave_buffer[XMM_OFFSET..][..16 * 16];
                        let ymm = &xsave_buffer[*YMM_OFFSET..][..16 * 16];

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
            KvmExit::RdMsr(ref mut msr) => {
                const GUEST_TSC_FREQ: u32 = 0xC001_0134;
                match msr.index {
                    GUEST_TSC_FREQ => msr.data = TSC_MHZ,
                    _ => todo!(),
                }

                kvm_run.update(|mut k| {
                    k.set_exit(exit);
                    k
                });
            }
            KvmExit::WrMsr(msr) => match msr.index {
                // EOI.
                0x80b => in_service_timer_irq = false,
                index => unimplemented!("unimplemented MSR write to {index:#x}"),
            },
            KvmExit::IrqWindowOpen => {}
            KvmExit::Interrupted => {}
            KvmExit::SetTpr => {}
            exit => {
                let regs = ap.get_regs()?;
                println!("{:x}", regs.rip);

                panic!("unexpected exit {exit:?}");
            }
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
