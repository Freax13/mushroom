use std::{
    iter::once,
    os::unix::thread::JoinHandleExt,
    sync::{
        Arc,
        atomic::{self, AtomicBool, Ordering},
        mpsc::{self, Sender},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use bit_field::BitField;
use bytemuck::{bytes_of, pod_read_unaligned};
use constants::{
    FINISH_OUTPUT_MSR, MAX_APS_COUNT, MEMORY_PORT, UPDATE_OUTPUT_MSR,
    physical_address::{DYNAMIC_2MIB, kernel, supervisor},
};
use loader::Input;
use mushroom_verify::snp::{LaunchDigest, create_signature, id_block};
use nix::{
    fcntl::{FallocateFlags, fallocate},
    sys::{mman::madvise, pthread::pthread_kill},
};
pub use snp_types::guest_policy::GuestPolicy;
use snp_types::id_block::{
    EcdsaP384PublicKey, EcdsaP384Sha384Signature, IdAuthInfo, KeyAlgo, PublicKey,
};
use tracing::{debug, info};
pub use vcek_kds::Vcek;
use x86_64::{
    PhysAddr,
    structures::paging::{PageSize, PhysFrame, Size2MiB, Size4KiB},
};

use crate::{
    MushroomResult, OutputEvent, SIG_KICK, TSC_MHZ, find_slot, install_signal_handler,
    kvm::{
        KVM_HC_MAP_GPA_RANGE, KvmCap, KvmExit, KvmExitHypercall, KvmExitUnknown, KvmHandle,
        KvmMemoryAttributes, MpState, Page, SevHandle, VcpuHandle, VmHandle,
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
    policy: GuestPolicy,
    vcek: Vcek,
    profiler_folder: Option<ProfileFolder>,
    timeout: Duration,
) -> Result<MushroomResult> {
    let sev_handle = SevHandle::new()?;

    let (vm_context, vcpus) = VmContext::prepare_vm(
        supervisor,
        kernel,
        init,
        inputs,
        load_kasan_shadow_mappings,
        policy,
        kvm_handle,
        &sev_handle,
        profiler_folder,
    )?;

    // Spawn threads to run the vCPUs.
    let vm_context = Arc::new(vm_context);
    let done = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel();
    let threads = vcpus
        .into_iter()
        .map(|vcpu| {
            let vm_context = vm_context.clone();
            let done = done.clone();
            let sender = sender.clone();
            std::thread::spawn(move || {
                let res = vm_context.run_vcpu(vcpu, done, &sender);
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
    done.store(true, atomic::Ordering::Relaxed);

    // Force all threads to exit out of KVM_RUN, so that they can observe
    // `done` and exit.
    for handle in threads {
        handle.thread().unpark();
        let _ = pthread_kill(handle.as_pthread_t(), SIG_KICK);
        handle.join().unwrap();
    }

    let mut attestation_report = res?;

    // Append the VCEK to the attestation report.
    attestation_report.extend_from_slice(vcek.raw());

    Ok(MushroomResult {
        output,
        attestation_report,
    })
}

struct VmContext {
    vm: Arc<VmHandle>,
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
        policy: GuestPolicy,
        kvm_handle: &KvmHandle,
        sev_handle: &SevHandle,
        profiler_folder: Option<ProfileFolder>,
    ) -> Result<(Self, Vec<VcpuHandle>)> {
        let mut cpuid_entries = kvm_handle.get_supported_cpuid()?;
        let piafb = cpuid_entries
            .iter_mut()
            .find(|entry| entry.function == 1 && entry.index == 0)
            .context("failed to find 'processor info and feature bits' entry")?;
        // Enable CPUID
        piafb.ecx.set_bit(21, true);
        let cpuid_entries = Arc::from(cpuid_entries);

        let vm = kvm_handle.create_snp_vm()?;
        let vm = Arc::new(vm);

        vm.enable_capability(KvmCap::EXIT_HYPERCALL, 1 << KVM_HC_MAP_GPA_RANGE)?;

        const KVM_MSR_EXIT_REASON_UNKNOWN: u64 = 1;
        const KVM_MSR_EXIT_REASON_FILTER: u64 = 2;
        vm.enable_capability(
            KvmCap::X86_USER_SPACE_MSR,
            KVM_MSR_EXIT_REASON_UNKNOWN | KVM_MSR_EXIT_REASON_FILTER,
        )?;

        vm.enable_capability(KvmCap::X2APIC_API, 0)?;

        vm.set_tsc_khz(TSC_MHZ * 1000)?;

        vm.create_irqchip()?;

        vm.sev_snp_init()?;

        vm.sev_snp_launch_start(policy, sev_handle)?;

        let vcpus = (0..MAX_APS_COUNT)
            .map(|i| {
                let vcpu = vm.create_vcpu(i32::from(i))?;
                vcpu.set_cpuid(&cpuid_entries)?;

                // Allow the kernel to query it's processor id through TSC_AUX.
                // This is needed on EPYC Milan, it's part of the VMSA on later
                // generations.
                const TSC_AUX: u32 = 0xc0000103;
                vcpu.set_msr(TSC_AUX, u64::from(i)).unwrap();

                vcpu.set_mp_state(MpState::Runnable)?;
                Result::Ok(vcpu)
            })
            .collect::<Result<Vec<_>>>()?;

        let (mut load_commands, host_data) = loader::generate_load_commands(
            Some(supervisor),
            kernel,
            init,
            load_kasan_shadow_mappings,
            inputs,
        );
        let mut launch_digest = LaunchDigest::new();
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
                if let Some(page_type) = command.payload.page_type() {
                    // Private memory is added with LAUNCH_UPDATE.

                    vm.set_memory_attributes(
                        command.physical_address.start_address().as_u64(),
                        0x1000,
                        KvmMemoryAttributes::PRIVATE,
                    )?;

                    vm.sev_snp_launch_update(
                        command.physical_address.start_address().as_u64(),
                        bytes.as_ptr() as u64,
                        0x1000,
                        page_type,
                        command.vcpu_id,
                        command.vmpl1_perms,
                        sev_handle,
                    )?;

                    launch_digest.add(&command);
                } else {
                    // Shared memory is added by coping directly into the shared mapping.
                    let ptr = slot.shared_ptr(command.physical_address.start_address())?;
                    ptr.write(*bytes);
                }
            }

            memory_slots.push(slot);
        }

        let launch_digest = launch_digest.finish();
        let id_block = id_block(launch_digest, policy);
        let (id_block_sig, id_key) = create_signature(&id_block);
        let id_block_sig = EcdsaP384Sha384Signature::from(id_block_sig);
        let id_key = PublicKey::P384(EcdsaP384PublicKey::from(id_key));
        let id_auth_info = IdAuthInfo::new(
            KeyAlgo::EcdsaP384Sha384,
            KeyAlgo::EcdsaP384Sha384,
            id_block_sig,
            id_key,
            EcdsaP384Sha384Signature::default(),
            PublicKey::default(),
        );

        vm.sev_snp_launch_finish(sev_handle, host_data, Some((&id_block, &id_auth_info)))?;

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
        vcpu: VcpuHandle,
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
                KvmExit::Hypercall(
                    mut hypercall @ KvmExitHypercall {
                        nr: KVM_HC_MAP_GPA_RANGE,
                        args: [address, num_pages, attrs, ..],
                        ..
                    },
                ) => {
                    let mut attributes = KvmMemoryAttributes::empty();
                    let private = attrs.get_bit(4);
                    attributes.set(KvmMemoryAttributes::PRIVATE, private);
                    self.vm
                        .set_memory_attributes(address, num_pages * 0x1000, attributes)?;

                    if private {
                        // Invalidate shared mapping.
                        for i in 0..num_pages {
                            let gpa = PhysAddr::new(address + i * Size4KiB::SIZE);
                            let slot =
                                find_slot(PhysFrame::containing_address(gpa), &self.memory_slots)?;
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
                        unimplemented!()
                    }

                    kvm_run.update(|mut run| {
                        hypercall.ret = 0;
                        run.set_exit(KvmExit::Hypercall(hypercall));
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

                            let gfn = DYNAMIC_2MIB.start + u64::from(slot_id);
                            let mut attributes = KvmMemoryAttributes::empty();
                            attributes.set(KvmMemoryAttributes::PRIVATE, enabled);
                            self.vm.set_memory_attributes(
                                gfn.start_address().as_u64(),
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
                KvmExit::MemoryFault(fault) => {
                    dbg!(fault);
                }
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
                KvmExit::Hlt => std::thread::park(),
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
