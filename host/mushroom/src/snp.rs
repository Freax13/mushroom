use std::{
    iter::once,
    os::{fd::AsRawFd, unix::thread::JoinHandleExt},
    ptr::addr_of,
    sync::{
        Arc,
        atomic::{self, AtomicBool, Ordering},
        mpsc::{self, Sender},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use bit_field::BitField;
use bytemuck::pod_read_unaligned;
use constants::{
    FINISH_OUTPUT_MSR, MAX_APS_COUNT, MEMORY_PORT, UPDATE_OUTPUT_MSR,
    physical_address::{DYNAMIC_2MIB, INPUT_FILE, kernel, supervisor},
};
use kvm_bindings::{
    KVM_CAP_EXIT_HYPERCALL, KVM_CAP_X2APIC_API, KVM_CAP_X86_USER_SPACE_MSR, KVM_MAX_CPUID_ENTRIES,
    KVM_MEM_GUEST_MEMFD, KVM_MEMORY_ATTRIBUTE_PRIVATE, KVM_MP_STATE_RUNNABLE,
    KVM_MSR_EXIT_REASON_FILTER, KVM_MSR_EXIT_REASON_UNKNOWN, KVM_X86_SNP_VM, Msrs, kvm_enable_cap,
    kvm_memory_attributes, kvm_msr_entry, kvm_sev_cmd, kvm_sev_init, kvm_sev_snp_launch_finish,
    kvm_sev_snp_launch_start, kvm_sev_snp_launch_update, kvm_userspace_memory_region2,
    sev_cmd_id_KVM_SEV_INIT2, sev_cmd_id_KVM_SEV_SNP_LAUNCH_FINISH,
    sev_cmd_id_KVM_SEV_SNP_LAUNCH_START,
};
use kvm_ioctls::{HypercallExit, Kvm, VcpuExit, VcpuFd, VmFd};
use loader::Input;
use mushroom_verify::snp::{LaunchDigest, create_signature, id_block};
use nix::{
    fcntl::{FallocateFlags, fallocate},
    sys::{mman::madvise, pthread::pthread_kill},
};
pub use snp_types::guest_policy::GuestPolicy;
use snp_types::{
    id_block::{EcdsaP384PublicKey, EcdsaP384Sha384Signature, IdAuthInfo, KeyAlgo, PublicKey},
    vmsa::SevFeatures,
};
use tracing::{debug, info};
pub use vcek_kds::Vcek;
use x86_64::{
    PhysAddr,
    structures::paging::{PageSize, PhysFrame, Size2MiB, Size4KiB},
};

use crate::{
    MushroomResult, OutputEvent, SIG_KICK, TSC_MHZ, find_slot, install_signal_handler,
    kvm::{Page, SevHandle},
    logging::start_log_collection,
    profiler::{ProfileFolder, start_profile_collection},
    raise_file_no_limit,
    slot::Slot,
};

#[allow(clippy::too_many_arguments)]
pub fn main(
    kvm_handle: &Kvm,
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
    vm: Arc<VmFd>,
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
        kvm: &Kvm,
        sev_handle: &SevHandle,
        profiler_folder: Option<ProfileFolder>,
    ) -> Result<(Self, Vec<VcpuFd>)> {
        let mut cpuid_entries = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
        let piafb = cpuid_entries
            .as_mut_slice()
            .iter_mut()
            .find(|entry| entry.function == 1 && entry.index == 0)
            .context("failed to find 'processor info and feature bits' entry")?;
        // Enable CPUID
        piafb.ecx.set_bit(21, true);
        let cpuid_entries = Arc::from(cpuid_entries);

        let vm = kvm
            .create_vm_with_type(u64::from(KVM_X86_SNP_VM))
            .context("failed to create SNP VM")?;
        let vm = Arc::new(vm);

        vm.enable_cap(&kvm_enable_cap {
            cap: KVM_CAP_EXIT_HYPERCALL,
            args: [1 << KVM_HC_MAP_GPA_RANGE, 0, 0, 0],
            ..Default::default()
        })
        .context("failed to enable hypercall exits")?;

        vm.enable_cap(&kvm_enable_cap {
            cap: KVM_CAP_X86_USER_SPACE_MSR,
            args: [
                u64::from(KVM_MSR_EXIT_REASON_UNKNOWN | KVM_MSR_EXIT_REASON_FILTER),
                0,
                0,
                0,
            ],
            ..Default::default()
        })
        .context("failed to enable user space MSR handling")?;

        vm.enable_cap(&kvm_enable_cap {
            cap: KVM_CAP_X2APIC_API,
            ..Default::default()
        })
        .context("failed to enable x2APIC")?;

        vm.set_tsc_khz(TSC_MHZ * 1000)?;

        vm.create_irq_chip().context("failed to create IRQ chip")?;

        let sev_init = kvm_sev_init {
            vmsa_features: (SevFeatures::RESTRICTED_INJECTION | SevFeatures::VMSA_REG_PROT).bits(),
            ghcb_version: 2,
            ..Default::default()
        };
        vm.encrypt_op_sev(&mut kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_INIT2,
            data: addr_of!(sev_init).addr() as u64,
            ..Default::default()
        })
        .context("failed to initialize SNP")?;

        let sev_snp_launch_start = kvm_sev_snp_launch_start {
            policy: policy.bits(),
            ..Default::default()
        };
        vm.encrypt_op_sev(&mut kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_SNP_LAUNCH_START,
            data: addr_of!(sev_snp_launch_start).addr() as u64,
            sev_fd: sev_handle.as_raw_fd() as u32,
            ..Default::default()
        })
        .context("failed to start sev snp launch")?;

        let vcpus = (0..MAX_APS_COUNT)
            .map(|i| {
                let vcpu = vm.create_vcpu(u64::from(i))?;

                vcpu.set_cpuid2(&cpuid_entries)?;

                // Allow the kernel to query it's processor id through TSC_AUX.
                // This is needed on EPYC Milan, it's part of the VMSA on later
                // generations.
                const TSC_AUX: u32 = 0xc0000103;
                let msrs = Msrs::from_entries(&[kvm_msr_entry {
                    index: TSC_AUX,
                    data: u64::from(i),
                    ..Default::default()
                }])
                .unwrap();
                vcpu.set_msrs(&msrs)?;

                vcpu.set_mp_state(kvm_bindings::kvm_mp_state {
                    mp_state: KVM_MP_STATE_RUNNABLE,
                })?;

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
            let slot = Slot::new2(
                &vm,
                gpa,
                num_pages * Size4KiB::SIZE as usize,
                first_load_command.shared,
                first_load_command.private,
            )
            .context("failed to create slot")?;
            let slot_id = u16::try_from(memory_slots.len())?;

            let mut memory_region = kvm_userspace_memory_region2 {
                slot: u32::from(slot_id),
                guest_phys_addr: gpa.start_address().as_u64(),
                memory_size: num_pages as u64 * Size4KiB::SIZE,
                ..Default::default()
            };
            if let Some(shared_mapping) = slot.shared_mapping() {
                memory_region.userspace_addr = shared_mapping.as_ptr().as_ptr().addr() as u64;
            }
            if let Some(restricted_fd) = slot.restricted_fd() {
                memory_region.flags |= KVM_MEM_GUEST_MEMFD;
                memory_region.guest_memfd = restricted_fd.as_raw_fd() as u32;
            }
            unsafe {
                vm.set_user_memory_region2(memory_region)
                    .context("failed to add memory region")?;
            }

            // Populate the slot's content.
            let pages = once(first_load_command)
                .chain(load_commands.by_ref())
                .take(num_pages);
            for command in pages {
                let bytes = command.payload.bytes();
                if let Some(page_type) = command.payload.page_type() {
                    // Private memory is added with LAUNCH_UPDATE.

                    vm.set_memory_attributes(kvm_memory_attributes {
                        address: command.physical_address.start_address().as_u64(),
                        size: Size4KiB::SIZE,
                        attributes: u64::from(KVM_MEMORY_ATTRIBUTE_PRIVATE),
                        ..Default::default()
                    })?;

                    let launch_update = kvm_sev_snp_launch_update_vmpls {
                        lu: kvm_sev_snp_launch_update {
                            gfn_start: command.physical_address.start_address().as_u64() >> 12,
                            uaddr: bytes.as_ptr() as u64,
                            len: Size4KiB::SIZE,
                            type_: page_type as u8,
                            pad1: command.vcpu_id,
                            ..Default::default()
                        },
                        vmpl1_perms: command.vmpl1_perms.bits(),
                        ..Default::default()
                    };
                    vm.encrypt_op_sev(&mut kvm_sev_cmd {
                        id: sev_cmd_id_KVM_SEV_SNP_LAUNCH_UPDATE_VMPLS,
                        data: addr_of!(launch_update).addr() as u64,
                        sev_fd: sev_handle.as_raw_fd() as u32,
                        ..Default::default()
                    })
                    .context("failed to update launch measurement")?;

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

        let launch_finish = kvm_sev_snp_launch_finish {
            id_block_uaddr: addr_of!(id_block).addr() as u64,
            id_auth_uaddr: addr_of!(id_auth_info).addr() as u64,
            id_block_en: u8::from(true),
            auth_key_en: u8::from(false),
            vcek_disabled: u8::from(false),
            host_data,
            ..Default::default()
        };
        vm.encrypt_op_sev(&mut kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_SNP_LAUNCH_FINISH,
            data: addr_of!(launch_finish).addr() as u64,
            sev_fd: sev_handle.as_raw_fd() as u32,
            ..Default::default()
        })
        .context("failed to finish launch")?;

        let len =
            DYNAMIC_2MIB.end.start_address().as_u64() - DYNAMIC_2MIB.start.start_address().as_u64();
        let dynamic_slot = Slot::new2(&vm, DYNAMIC_2MIB.start, usize::try_from(len)?, true, true)?;
        let slot_id = u16::try_from(memory_slots.len())?;
        let mut memory_region = kvm_userspace_memory_region2 {
            slot: u32::from(slot_id),
            flags: KVM_MEM_GUEST_MEMFD,
            guest_phys_addr: dynamic_slot.gpa().start_address().as_u64(),
            memory_size: len,
            ..Default::default()
        };
        let shared_mapping = dynamic_slot.shared_mapping().unwrap();
        memory_region.userspace_addr = shared_mapping.as_ptr().as_ptr().addr() as u64;
        let restricted_fd = dynamic_slot.restricted_fd().unwrap();
        memory_region.guest_memfd = restricted_fd.as_raw_fd() as u32;
        unsafe {
            vm.set_user_memory_region2(memory_region)
                .context("failed to add memory region")?;
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
        mut vcpu: VcpuFd,
        done: Arc<AtomicBool>,
        sender: &Sender<OutputEvent>,
    ) -> Result<()> {
        while !done.load(Ordering::Relaxed) {
            match vcpu.run()? {
                VcpuExit::Unknown => {}
                VcpuExit::Hypercall(HypercallExit {
                    nr: KVM_HC_MAP_GPA_RANGE,
                    args: [address, num_pages, attrs, ..],
                    ret,
                    ..
                }) => {
                    assert!(INPUT_FILE.start.start_address().as_u64() <= address);
                    assert!(
                        address + num_pages * Size4KiB::SIZE
                            < (INPUT_FILE.end + 1).start_address().as_u64()
                    );

                    let private = attrs.get_bit(4);
                    let attributes = if private {
                        KVM_MEMORY_ATTRIBUTE_PRIVATE
                    } else {
                        0
                    };
                    self.vm.set_memory_attributes(kvm_memory_attributes {
                        address,
                        size: num_pages * Size4KiB::SIZE,
                        attributes: u64::from(attributes),
                        ..Default::default()
                    })?;

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

                    *ret = 0;
                }
                VcpuExit::IoOut(port, value) => {
                    assert_eq!(value.len(), 4, "accesses to the ports should have size 4");
                    let value = pod_read_unaligned::<u32>(value);
                    match port {
                        MEMORY_PORT => {
                            let slot_id = value.get_bits(0..15) as u16;
                            let enabled = value.get_bit(15);
                            let gpa = DYNAMIC_2MIB.start + u64::from(slot_id);
                            debug!(slot_id, enabled, gpa = %format_args!("{gpa:?}"), "updating slot status");

                            let gfn = DYNAMIC_2MIB.start + u64::from(slot_id);
                            let attributes = if enabled {
                                KVM_MEMORY_ATTRIBUTE_PRIVATE
                            } else {
                                0
                            };
                            self.vm.set_memory_attributes(kvm_memory_attributes {
                                address: gfn.start_address().as_u64(),
                                size: Size2MiB::SIZE,
                                attributes: u64::from(attributes),
                                ..Default::default()
                            })?;

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
                VcpuExit::Shutdown | VcpuExit::SystemEvent(..) => bail!("no output was produced"),
                VcpuExit::X86Wrmsr(msr) => match msr.index {
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
                VcpuExit::Hlt => std::thread::park(),
                VcpuExit::Intr => {}
                exit => panic!("unexpected exit: {exit:?}"),
            }
        }

        Ok(())
    }
}

const KVM_HC_MAP_GPA_RANGE: u64 = 12;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
struct kvm_sev_snp_launch_update_vmpls {
    lu: kvm_sev_snp_launch_update,
    vmpl3_perms: u8,
    vmpl2_perms: u8,
    vmpl1_perms: u8,
}

#[expect(non_upper_case_globals)]
const sev_cmd_id_KVM_SEV_SNP_LAUNCH_UPDATE_VMPLS: u32 = 103;
