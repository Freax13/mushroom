use std::{
    array,
    collections::{hash_map::Entry, HashMap},
    os::unix::thread::JoinHandleExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
        Arc, Mutex,
    },
    time::Instant,
};

use anyhow::{bail, ensure, Context, Result};
use bit_field::BitField;
use bytemuck::{bytes_of, checked::try_pod_read_unaligned, pod_read_unaligned};
use constants::{
    physical_address::{kernel, supervisor, DYNAMIC_2MIB},
    FINISH_OUTPUT_MSR, MAX_APS_COUNT, MEMORY_PORT, UPDATE_OUTPUT_MSR,
};
use loader::Input;
use nix::sys::pthread::pthread_kill;
use tdx_types::ghci::{MAP_GPA, VMCALL_SUCCESS};
use tracing::{debug, info};
use x86_64::{
    structures::paging::{PageSize, PhysFrame, Size2MiB, Size4KiB},
    PhysAddr,
};

use crate::{
    find_slot, install_signal_handler,
    kvm::{
        KvmCap, KvmExit, KvmExitUnknown, KvmHandle, KvmMemoryAttributes, Page, SupportedGpaw,
        VcpuHandle, VmHandle,
    },
    logging::start_log_collection,
    profiler::{start_profile_collection, ProfileFolder},
    raise_file_no_limit,
    slot::Slot,
    MushroomResult, OutputEvent, SIG_KICK, TSC_MHZ,
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
        let event = receiver.recv().unwrap();
        match event {
            OutputEvent::Write(mut vec) => output.append(&mut vec),
            OutputEvent::Finish(attestation_report) => break Ok(attestation_report),
            OutputEvent::Fail(err) => break Err(err),
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
        attestation_report: Some(quote),
    })
}

struct VmContext {
    vm: VmHandle,
    memory_slots: Mutex<HashMap<u16, Slot>>,
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

        let (load_commands, host_data) = loader::generate_load_commands(
            Some(supervisor),
            kernel,
            init,
            load_kasan_shadow_mappings,
            inputs,
        );
        let mut load_commands = load_commands.peekable();

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

        let mut num_launch_pages = 0;

        let mut memory_slots = HashMap::new();
        let mut pages = Vec::with_capacity(0xfffff);

        let mut slot_id = 0;
        while let Some(first_load_command) = load_commands.next() {
            let gpa = first_load_command.physical_address;
            let is_private_mem = first_load_command.payload.page_type().is_some();

            pages.push(Page {
                bytes: first_load_command.payload.bytes(),
            });

            // Coalesce multiple contigous load commands with the same page type.
            for i in 1.. {
                let following_load_command = load_commands.next_if(|next_load_segment| {
                    next_load_segment.physical_address > gpa
                        && next_load_segment.physical_address - gpa == i
                        && next_load_segment.payload.page_type().is_some() == is_private_mem
                });
                let Some(following_load_command) = following_load_command else {
                    break;
                };
                pages.push(Page {
                    bytes: following_load_command.payload.bytes(),
                });
            }

            let slot = Slot::for_launch_update(&vm, gpa, &pages, true)
                .context("failed to create slot for launch update")?;

            unsafe {
                vm.map_encrypted_memory(slot_id, &slot)?;
            }

            if is_private_mem {
                vm.set_memory_attributes(
                    gpa.start_address().as_u64(),
                    u64::try_from(slot.shared_mapping().len().get())?,
                    KvmMemoryAttributes::PRIVATE,
                )?;

                vcpus[0].memory_mapping(gpa.start_address().as_u64(), &pages)?;

                vm.tdx_extend_memory(gpa.start_address().as_u64(), u64::try_from(pages.len())?)?;

                num_launch_pages += pages.len();
            }

            memory_slots.insert(slot_id, slot);

            pages.clear();
            slot_id += 1;
        }

        vm.tdx_finalize_vm()?;

        info!(num_launch_pages, "launched");
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
                memory_slots: Mutex::new(memory_slots),
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
                            let slot_id = value.get_bits(0..15) as u16;
                            let enabled = value.get_bit(15);
                            let gpa = DYNAMIC_2MIB.start + u64::from(slot_id);
                            debug!(slot_id, enabled, gpa = %format_args!("{gpa:?}"), "updating slot status");

                            let base = 1 << 6;
                            let kvm_slot_id = base + slot_id;
                            let mut guard = self.memory_slots.lock().unwrap();
                            let entry = guard.entry(kvm_slot_id);
                            match entry {
                                Entry::Occupied(entry) => {
                                    assert!(
                                        !enabled,
                                        "tried to enable slot that's already enabled"
                                    );

                                    let slot = entry.remove();
                                    unsafe {
                                        self.vm.unmap_encrypted_memory(kvm_slot_id, &slot)?;
                                    }
                                }
                                Entry::Vacant(entry) => {
                                    assert!(
                                        enabled,
                                        "tried to disable slot that's already disabled"
                                    );

                                    let gfn = DYNAMIC_2MIB.start + u64::from(slot_id);
                                    let slot = Slot::new(&self.vm, gfn, true)
                                        .context("failed to create dynamic slot")?;

                                    unsafe {
                                        self.vm.map_encrypted_memory(kvm_slot_id, &slot)?;
                                    }

                                    self.vm.set_memory_attributes(
                                        gfn.start_address().as_u64(),
                                        Size2MiB::SIZE,
                                        KvmMemoryAttributes::PRIVATE,
                                    )?;

                                    entry.insert(slot);
                                }
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

                        let mut guard = self.memory_slots.lock().unwrap();
                        let slot = find_slot(gfn, &mut guard)?;
                        let output_buffer = slot.read::<[u8; 4096]>(gfn.start_address())?;
                        drop(guard);

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

                        let mut guard = self.memory_slots.lock().unwrap();
                        let slot = find_slot(gfn, &mut guard)?;
                        let attestation_report = slot.read::<[u8; 4096]>(gfn.start_address())?;
                        drop(guard);

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
