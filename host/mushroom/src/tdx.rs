use std::{
    array,
    iter::once,
    os::unix::thread::JoinHandleExt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use bit_field::BitField;
use bytemuck::{bytes_of, checked::try_pod_read_unaligned, pod_read_unaligned};
use constants::{
    FINISH_OUTPUT_MSR, MAX_APS_COUNT, MEMORY_PORT, UPDATE_OUTPUT_MSR,
    physical_address::{DYNAMIC_2MIB, kernel, supervisor},
};
use loader::Input;
use nix::{
    fcntl::{FallocateFlags, fallocate},
    sys::{mman::madvise, pthread::pthread_kill},
};
use tdx_types::ghci::{MAP_GPA, VMCALL_SUCCESS};
use tracing::{debug, info};
use x86_64::{
    PhysAddr,
    structures::paging::{PageSize, PhysFrame, Size2MiB, Size4KiB},
};

use crate::{
    MushroomResult, OutputEvent, SIG_KICK, TSC_MHZ, find_slot, install_signal_handler,
    kvm::{
        KvmCap, KvmExit, KvmExitUnknown, KvmHandle, KvmMemoryAttributes, Page, SupportedGpaw,
        VcpuHandle, VmHandle,
    },
    logging::start_log_collection,
    profiler::{ProfileFolder, start_profile_collection},
    raise_file_no_limit,
    slot::Slot,
};

#[allow(clippy::too_many_arguments)]
pub fn main(
    kvm_handle: &KvmHandle,
    supervisor: &[u8],
    kernel: &[u8],
    init: &[u8],
    load_kasan_shadow_mappings: bool,
    inputs: &[Input<impl AsRef<[u8]>>],
    profiler_folder: Option<ProfileFolder>,
    cid: u32,
    port: u32,
    timeout: Duration,
) -> Result<MushroomResult> {
    // Prepare the VM.
    let (vm_context, vcpus) = VmContext::prepare_vm(
        supervisor,
        kernel,
        init,
        inputs,
        load_kasan_shadow_mappings,
        kvm_handle,
        profiler_folder,
    )?;

    // Spawn threads to run the vCPUs.
    let vm_context = Arc::new(vm_context);
    let (sender, receiver) = mpsc::channel();
    let done = Arc::new(AtomicBool::new(false));
    let threads = vcpus
        .into_iter()
        .map(|vcpu| {
            let vm_context = vm_context.clone();
            let done = done.clone();
            let sender = sender.clone();
            std::thread::spawn(move || {
                let res = vm_context.run_vcpu(&vcpu, done, &sender);
                if let Err(err) = res {
                    let _ = sender.send(OutputEvent::Fail(err));
                }
            })
        })
        .collect::<Vec<_>>();

    // Collect the output and report.
    let mut output: Vec<u8> = Vec::new();
    let res = loop {
        let res = receiver.recv_timeout(timeout);
        match res {
            Ok(event) => match event {
                OutputEvent::Write(mut vec) => output.append(&mut vec),
                OutputEvent::Finish(attestation_report) => break Ok(attestation_report),
                OutputEvent::Fail(err) => break Err(err),
            },
            Err(err) => break Err(err).context("workload timed out"),
        }
    };

    // Set the done flag.
    done.store(true, Ordering::SeqCst);
    // Force all threads to exit out of KVM_RUN, so that they can observe
    // `done` and exit.
    for thread in threads {
        pthread_kill(thread.as_pthread_t(), SIG_KICK)?;
        thread.join().unwrap();
    }

    let td_report = res?;

    // Convert the TD report into a TD quote.
    let report = try_pod_read_unaligned::<tdx_types::report::TdReport>(&td_report)?;
    let quote = qgs_client::generate_quote(cid, port, &report)?;

    Ok(MushroomResult {
        output,
        attestation_report: quote,
    })
}

struct VmContext {
    vm: VmHandle,
    memory_slots: Vec<Slot>,
    dynamic_slot: Slot,
    start: Instant,
}

impl VmContext {
    /// Create the VM, create the BSP and execute all launch commands.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_vm(
        supervisor: &[u8],
        kernel: &[u8],
        init: &[u8],
        inputs: &[Input<impl AsRef<[u8]>>],
        load_kasan_shadow_mappings: bool,
        kvm_handle: &KvmHandle,
        profiler_folder: Option<ProfileFolder>,
    ) -> Result<(Self, Vec<VcpuHandle>)> {
        let mut cpuid_entries = kvm_handle.get_supported_cpuid()?;
        let piafb = cpuid_entries
            .iter_mut()
            .find(|entry| entry.function == 1 && entry.index == 0)
            .context("failed to find 'processor info and feature bits' entry")?;
        // Enable CPUID
        piafb.ecx.set_bit(21, true);

        let xsave = cpuid_entries
            .iter_mut()
            .find(|entry| entry.function == 0xd && entry.index == 0x1)
            .context("failed to find 'xsave state components' entry")?;
        // Enable CET_U and CET_S.
        xsave.ecx.set_bit(11, true);
        xsave.ecx.set_bit(12, true);

        let vm = kvm_handle.create_tdx_vm()?;

        vm.enable_capability(KvmCap::MAX_VCPUS, u64::from(MAX_APS_COUNT))?;

        vm.enable_capability(KvmCap::X2APIC_API, 0)?;

        let tdx_capabilities = vm.tdx_capabilities()?;
        ensure!(
            tdx_capabilities
                .supported_gpaw
                .contains(SupportedGpaw::GPAW_52),
            "52-bit GPAW is not supported"
        );

        vm.create_irqchip()?;

        const KVM_MSR_EXIT_REASON_UNKNOWN: u64 = 1;
        const KVM_MSR_EXIT_REASON_FILTER: u64 = 2;
        vm.enable_capability(
            KvmCap::X86_USER_SPACE_MSR,
            KVM_MSR_EXIT_REASON_UNKNOWN | KVM_MSR_EXIT_REASON_FILTER,
        )?;

        vm.set_tsc_khz(TSC_MHZ * 1000)?;

        let (mut load_commands, host_data) = loader::generate_load_commands(
            Some(supervisor),
            kernel,
            init,
            load_kasan_shadow_mappings,
            inputs,
        );

        let mrconfigid = array::from_fn(|i| host_data.get(i).copied().unwrap_or_default());
        vm.tdx_init_vm(&cpuid_entries, mrconfigid)?;

        let vcpus = (0..MAX_APS_COUNT)
            .map(|i| {
                let cpu = vm.create_vcpu(i32::from(i))?;
                cpu.set_cpuid(&cpuid_entries)?;
                cpu.tdx_init_vcpu()?;
                Ok(cpu)
            })
            .collect::<Result<Vec<_>>>()?;

        let mut memory_slots = Vec::new();
        while let Some(first_load_command) = load_commands.next() {
            let gpa = first_load_command.physical_address;

            // Figure out how big the next slot can be by counting pages with
            // contiguous GPAs and identical shared and private mapping
            // requirements.
            let num_pages = 1 + load_commands
                .clone()
                .zip(1..)
                .take_while(|(next, i)| {
                    next.physical_address == gpa + *i
                        && next.shared == first_load_command.shared
                        && next.private == first_load_command.private
                })
                .count();

            // Create and map the slot.
            let slot = Slot::new(
                &vm,
                gpa,
                num_pages * 0x1000,
                first_load_command.shared,
                first_load_command.private,
            )
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
                let bytes = command.payload.bytes();
                if command.payload.page_type().is_some() {
                    // Private memory is added with MEM.PAGE.ADD and MR.EXTEND.

                    let gpa = command.physical_address.start_address().as_u64();

                    vm.set_memory_attributes(gpa, 0x1000, KvmMemoryAttributes::PRIVATE)?;

                    vcpus[0].memory_mapping(gpa, &[Page { bytes: *bytes }])?;

                    vm.tdx_extend_memory(gpa, 1)?;
                } else {
                    // Shared memory is added by coping directly into the shared mapping.
                    let ptr = slot.shared_ptr(command.physical_address.start_address())?;
                    ptr.write(*bytes);
                }
            }

            memory_slots.push(slot);
        }

        vm.tdx_finalize_vm()?;

        let len =
            DYNAMIC_2MIB.end.start_address().as_u64() - DYNAMIC_2MIB.start.start_address().as_u64();
        let len = usize::try_from(len)?;
        let dynamic_slot = Slot::new(&vm, DYNAMIC_2MIB.start, len, false, true)?;
        let slot_id = u16::try_from(memory_slots.len())?;
        unsafe {
            vm.map_encrypted_memory(slot_id, &dynamic_slot)?;
        }

        info!("launched");
        let start = Instant::now();

        start_log_collection(&memory_slots, kernel::LOG_BUFFER)?;
        start_log_collection(&memory_slots, supervisor::LOG_BUFFER)?;
        if let Some(profiler_folder) = profiler_folder {
            start_profile_collection(profiler_folder, &memory_slots)?;
        }

        install_signal_handler();
        raise_file_no_limit();

        Ok((
            Self {
                vm,
                memory_slots,
                dynamic_slot,
                start,
            },
            vcpus,
        ))
    }

    pub fn run_vcpu(
        &self,
        vcpu: &VcpuHandle,
        done: Arc<AtomicBool>,
        sender: &Sender<OutputEvent>,
    ) -> Result<()> {
        let kvm_run = vcpu.get_kvm_run_block()?;
        let kvm_run = kvm_run.as_ptr();

        while !done.load(Ordering::Relaxed) {
            let exit = kvm_run.read().exit();

            match exit {
                KvmExit::Unknown(KvmExitUnknown {
                    hardware_exit_reason: 0,
                }) => {}
                KvmExit::Tdx(mut tdx_exit) => {
                    assert_eq!({ tdx_exit.ty }, 1);

                    match tdx_exit.in_r11 {
                        MAP_GPA => {
                            let mut address = tdx_exit.in_r12;
                            let num_pages = tdx_exit.in_r13;
                            let private = !address.get_bit(51);
                            address.set_bit(51, false);

                            let mut attributes = KvmMemoryAttributes::empty();
                            attributes.set(KvmMemoryAttributes::PRIVATE, private);
                            self.vm.set_memory_attributes(
                                address,
                                num_pages * 0x1000,
                                attributes,
                            )?;

                            if private {
                                // Invalidate shared mapping.
                                for i in 0..num_pages {
                                    let gpa = PhysAddr::new(address + i * Size4KiB::SIZE);
                                    let slot = find_slot(
                                        PhysFrame::containing_address(gpa),
                                        &self.memory_slots,
                                    )?;
                                    let ptr = slot.shared_ptr::<Page>(gpa)?;
                                    let ptr = ptr.as_raw_ptr();
                                    unsafe {
                                        madvise(
                                            ptr.cast(),
                                            Size4KiB::SIZE as usize,
                                            nix::sys::mman::MmapAdvise::MADV_DONTNEED,
                                        )?;
                                    }
                                }
                            } else {
                                // Invalidate private mapping.
                                for i in 0..num_pages {
                                    let gpa = PhysAddr::new(address + i * Size4KiB::SIZE);
                                    let slot = find_slot(
                                        PhysFrame::containing_address(gpa),
                                        &self.memory_slots,
                                    )?;
                                    let restricted_fd = slot.restricted_fd().unwrap();
                                    let offset = gpa - slot.gpa().start_address();

                                    fallocate(
                                        restricted_fd,
                                        FallocateFlags::FALLOC_FL_KEEP_SIZE
                                            | FallocateFlags::FALLOC_FL_PUNCH_HOLE,
                                        offset as i64,
                                        Size4KiB::SIZE as i64,
                                    )?;
                                }
                            }

                            tdx_exit.out_r10 = VMCALL_SUCCESS;
                        }
                        sub_fn => unimplemented!("unimplemented vmcall sub_fn={sub_fn:x}"),
                    }

                    kvm_run.update(|mut run| {
                        run.set_exit(KvmExit::Tdx(tdx_exit));
                        run
                    });
                }
                KvmExit::Io(io) => {
                    assert_eq!(io.size, 4, "accesses to the ports should have size 4");

                    let raw_kvm_run = kvm_run.read();
                    let raw_kvm_run = bytes_of(&raw_kvm_run);
                    let value = pod_read_unaligned::<u32>(
                        &raw_kvm_run[io.data_offset as usize..][..usize::from(io.size)],
                    );

                    match io.port {
                        MEMORY_PORT => {
                            let slot_id = value.get_bits(0..31);
                            let enabled = value.get_bit(31);
                            let gpa = DYNAMIC_2MIB.start + u64::from(slot_id);
                            debug!(slot_id, enabled, gpa = %format_args!("{gpa:?}"), "updating slot status");

                            let mut attributes = KvmMemoryAttributes::empty();
                            attributes.set(KvmMemoryAttributes::PRIVATE, enabled);
                            self.vm.set_memory_attributes(
                                gpa.start_address().as_u64(),
                                Size2MiB::SIZE,
                                attributes,
                            )?;

                            // Remove the backing memory when memory is disabled.
                            if !enabled {
                                let restricted_fd = self.dynamic_slot.restricted_fd().unwrap();
                                fallocate(
                                    restricted_fd,
                                    FallocateFlags::FALLOC_FL_KEEP_SIZE
                                        | FallocateFlags::FALLOC_FL_PUNCH_HOLE,
                                    i64::from(slot_id) * Size2MiB::SIZE as i64,
                                    Size2MiB::SIZE as i64,
                                )?;
                            }
                        }
                        other => unimplemented!("unimplemented io port: {other}"),
                    }
                }
                KvmExit::Shutdown | KvmExit::SystemEvent(_) => bail!("no output was produced"),
                KvmExit::WrMsr(msr) => match msr.index {
                    UPDATE_OUTPUT_MSR => {
                        let gfn =
                            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(msr.data));
                        let len = ((msr.data & 0xfff) + 1) as usize;

                        let slot = find_slot(gfn, &self.memory_slots)?;
                        let output_buffer = slot.read::<[u8; 4096]>(gfn.start_address())?;

                        let output_slice = &output_buffer[..len];
                        sender
                            .send(OutputEvent::Write(output_slice.to_vec()))
                            .unwrap();
                    }
                    FINISH_OUTPUT_MSR => {
                        info!("finished after {:?}", self.start.elapsed());

                        let gfn =
                            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(msr.data));
                        let len = (msr.data & 0xfff) as usize;

                        let slot = find_slot(gfn, &self.memory_slots)?;
                        let attestation_report = slot.read::<[u8; 4096]>(gfn.start_address())?;

                        let attestation_report = attestation_report[..len].to_vec();
                        sender
                            .send(OutputEvent::Finish(attestation_report.to_vec()))
                            .unwrap();
                        return Ok(());
                    }
                    index => unimplemented!("unsupported MSR: {index:#08x}"),
                },
                KvmExit::Other { exit_reason } => {
                    unimplemented!("exit with type: {exit_reason}");
                }
                KvmExit::Interrupted => {}
                exit => {
                    panic!("unexpected exit: {exit:?}");
                }
            }

            vcpu.run()?;
        }

        Ok(())
    }
}
