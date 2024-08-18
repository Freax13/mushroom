#![feature(new_uninit)]

use std::{
    collections::{hash_map::Entry, HashMap},
    mem::size_of,
    ptr::NonNull,
    sync::Arc,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use bit_field::BitField;
use bytemuck::NoUninit;
use constants::{
    physical_address::{kernel, supervisor, DYNAMIC_2MIB},
    FINISH_OUTPUT_MSR, FIRST_AP, KICK_AP_PORT, MAX_APS_COUNT, MEMORY_PORT, UPDATE_OUTPUT_MSR,
};
use kvm::{KvmCpuidEntry2, KvmExitHypercall, KvmHandle, Page, VcpuHandle, KVM_HC_MAP_GPA_RANGE};
use logging::start_log_collection;
use profiler::ProfileFolder;
use snp_types::{guest_policy::GuestPolicy, PageType};
use tracing::{debug, info};
use volatile::{
    access::{ReadOnly, Readable},
    map_field, VolatilePtr,
};
use x86_64::{
    structures::paging::{PageSize as _, PhysFrame, Size2MiB, Size4KiB},
    PhysAddr,
};

use crate::{
    kvm::{KvmCap, KvmExit, KvmExitUnknown, KvmMemoryAttributes, SevHandle, VmHandle},
    profiler::start_profile_collection,
    slot::Slot,
};

pub mod insecure;
mod kvm;
mod logging;
pub mod profiler;
mod slot;

pub fn main(
    supervisor: &[u8],
    kernel: &[u8],
    init: &[u8],
    load_kasan_shadow_mappings: bool,
    input: &[u8],
    policy: GuestPolicy,
    profiler_folder: Option<ProfileFolder>,
) -> Result<MushroomResult> {
    let kvm_handle = KvmHandle::new()?;
    let sev_handle = SevHandle::new()?;

    let mut vm_context = VmContext::prepare_vm(
        supervisor,
        kernel,
        init,
        input,
        load_kasan_shadow_mappings,
        policy,
        &kvm_handle,
        &sev_handle,
        profiler_folder,
    )?;
    vm_context.run_supervisor()
}

struct VmContext {
    vm: Arc<VmHandle>,
    bsp: VcpuHandle,
    ap_threads: HashMap<u8, JoinHandle<()>>,
    memory_slots: HashMap<u16, Slot>,
    start: Instant,
}

impl VmContext {
    /// Create the VM, create the BSP and execute all launch commands.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_vm(
        supervisor: &[u8],
        kernel: &[u8],
        init: &[u8],
        input: &[u8],
        load_kasan_shadow_mappings: bool,
        policy: GuestPolicy,
        kvm_handle: &KvmHandle,
        sev_handle: &SevHandle,
        profiler_folder: Option<ProfileFolder>,
    ) -> Result<Self> {
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

        vm.sev_snp_init()?;

        vm.sev_snp_launch_start(policy, sev_handle)?;

        let (load_commands, host_data) = loader::generate_load_commands(
            Some(supervisor),
            kernel,
            init,
            load_kasan_shadow_mappings,
            input,
        );
        let mut load_commands = load_commands.peekable();

        let mut num_launch_pages = 0;
        let mut num_data_pages = 0;
        let mut total_launch_duration = Duration::ZERO;

        let mut memory_slots = HashMap::new();
        let mut pages = Vec::with_capacity(0xfffff);

        let mut slot_id = 0;
        while let Some(first_load_command) = load_commands.next() {
            let gpa = first_load_command.physical_address;
            let first_page_type = first_load_command.payload.page_type();
            let first_vmpl1_perms = first_load_command.vmpl1_perms;

            pages.push(Page {
                bytes: first_load_command.payload.bytes(),
            });

            // Coalesce multiple contigous load commands with the same page type.
            for i in 1.. {
                let following_load_command = load_commands.next_if(|next_load_segment| {
                    next_load_segment.physical_address > gpa
                        && next_load_segment.physical_address - gpa == i
                        && next_load_segment.payload.page_type() == first_page_type
                        && next_load_segment.vmpl1_perms == first_vmpl1_perms
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

            if let Some(first_page_type) = first_page_type {
                let update_start = Instant::now();

                vm.set_memory_attributes(
                    gpa.start_address().as_u64(),
                    u64::try_from(slot.shared_mapping().len().get())?,
                    KvmMemoryAttributes::PRIVATE,
                )?;

                vm.sev_snp_launch_update(
                    gpa.start_address().as_u64(),
                    u64::try_from(slot.shared_mapping().as_ptr().as_ptr() as usize)?,
                    slot.shared_mapping().len().get() as u64,
                    first_page_type,
                    first_vmpl1_perms,
                    sev_handle,
                )?;

                num_launch_pages += pages.len();
                total_launch_duration += update_start.elapsed();
                if first_page_type == PageType::Normal {
                    num_data_pages += pages.len();
                }
            }

            memory_slots.insert(slot_id, slot);

            pages.clear();
            slot_id += 1;
        }

        let bsp = vm.create_vcpu(0)?;
        bsp.set_cpuid(&cpuid_entries)?;

        vm.sev_snp_launch_finish(sev_handle, host_data)?;

        info!(
            num_launch_pages,
            num_data_pages,
            ?total_launch_duration,
            "launched"
        );
        let start = Instant::now();

        // Create a bunch of APs.
        let aps = (0..MAX_APS_COUNT)
            .map(|i| {
                let id = FIRST_AP + i;
                let ap_thread = Self::run_kernel_vcpu(id, vm.clone(), cpuid_entries.clone());
                Ok((id, ap_thread))
            })
            .collect::<Result<_>>()?;

        start_log_collection(&memory_slots, kernel::LOG_BUFFER)?;
        start_log_collection(&memory_slots, supervisor::LOG_BUFFER)?;
        if let Some(profiler_folder) = profiler_folder {
            start_profile_collection(profiler_folder, &memory_slots)?;
        }

        Ok(Self {
            vm,
            bsp,
            ap_threads: aps,
            memory_slots,
            start,
        })
    }

    pub fn run_supervisor(&mut self) -> Result<MushroomResult> {
        let mut output = Vec::new();
        let kvm_run = self.bsp.get_kvm_run_block()?;

        loop {
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
                    attributes.set(KvmMemoryAttributes::PRIVATE, attrs.get_bit(4));
                    self.vm
                        .set_memory_attributes(address, num_pages * 0x1000, attributes)?;

                    kvm_run.update(|mut run| {
                        hypercall.ret = 0;
                        run.set_exit(KvmExit::Hypercall(hypercall));
                        run
                    });
                }
                KvmExit::Io(io) => {
                    assert_eq!(io.size, 4, "accesses to the ports should have size 4");

                    let data = volatile_bytes_of(kvm_run);
                    let data = data
                        .index(io.data_offset as usize..)
                        .index(..usize::from(io.size));
                    let mut buffer = [0; 4];
                    data.copy_into_slice(&mut buffer);
                    let value = u32::from_ne_bytes(buffer);

                    match io.port {
                        MEMORY_PORT => {
                            let slot_id = value.get_bits(0..15) as u16;
                            let enabled = value.get_bit(15);
                            let gpa = DYNAMIC_2MIB.start + u64::from(slot_id);
                            debug!(slot_id, enabled, gpa = %format_args!("{gpa:?}"), "updating slot status");

                            let base = 1 << 6;
                            let kvm_slot_id = base + slot_id;
                            let entry = self.memory_slots.entry(kvm_slot_id);
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
                        KICK_AP_PORT => {
                            let id = u8::try_from(value)?;
                            self.ap_threads
                                .get(&id)
                                .context("couldn't find AP thread")?
                                .thread()
                                .unpark();
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

                        let slot = find_slot(gfn, &mut self.memory_slots)?;
                        let output_buffer = slot.read::<[u8; 4096]>(gfn.start_address())?;

                        let output_slice = &output_buffer[..len];
                        output.extend_from_slice(output_slice);
                    }
                    FINISH_OUTPUT_MSR => {
                        info!("finished after {:?}", self.start.elapsed());

                        let gfn =
                            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(msr.data));
                        let len = (msr.data & 0xfff) as usize;

                        let slot = find_slot(gfn, &mut self.memory_slots)?;
                        let attestation_report = slot.read::<[u8; 4096]>(gfn.start_address())?;

                        let attestation_report = attestation_report[..len].to_vec();
                        return Ok(MushroomResult {
                            output,
                            attestation_report: Some(attestation_report),
                        });
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

            let run_res = self.bsp.run();

            run_res?;
        }
    }

    fn run_kernel_vcpu(
        id: u8,
        vm: Arc<VmHandle>,
        cpuid_entries: Arc<[KvmCpuidEntry2]>,
    ) -> JoinHandle<()> {
        let supervisor_thread = std::thread::current();

        std::thread::spawn(move || {
            let ap = vm.create_vcpu(i32::from(id)).unwrap();
            ap.set_cpuid(&cpuid_entries).unwrap();

            // Allow the kernel to query it's processor id through TSC_AUX.
            // Note that this doesn't do anything on EPYC Milan.
            const TSC_AUX: u32 = 0xc0000103;
            ap.set_msr(TSC_AUX, u64::from(id - FIRST_AP)).unwrap();

            // Work around a bug where KVM fails to enable LBR virtualization
            // for SEV-ES vCPUs creating using AP creation.
            const DEBUG_CTL: u32 = 0x000001d9;
            ap.set_msr(DEBUG_CTL, 1).unwrap();

            let kvm_run = ap.get_kvm_run_block().unwrap();

            std::thread::park();

            loop {
                map_field!(kvm_run.cr8).write(0);

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
                let kvm_run = kvm_run.read();
                match kvm_run.exit() {
                    KvmExit::Hlt => {
                        let resume = kvm_run.cr8.get_bit(0);

                        supervisor_thread.unpark();

                        if !resume {
                            std::thread::park();
                        }
                    }
                    exit => panic!("unexpected exit {exit:?}"),
                }
            }
        })
    }
}

fn find_slot(gpa: PhysFrame, slots: &mut HashMap<u16, Slot>) -> Result<&mut Slot> {
    slots
        .values_mut()
        .find(|slot| {
            let num_frames = u64::try_from(slot.shared_mapping().len().get() / 0x1000).unwrap();
            (slot.gpa()..slot.gpa() + num_frames).contains(&gpa)
        })
        .context("failed to find slot which contains ghcb")
}

/// The volatile equivalent of `bytemuck::bytes_of`.
fn volatile_bytes_of<T>(ptr: VolatilePtr<T, impl Readable>) -> VolatilePtr<[u8], ReadOnly>
where
    T: NoUninit,
{
    let data = ptr.as_raw_ptr().as_ptr().cast::<u8>();
    let ptr = core::ptr::slice_from_raw_parts_mut(data, size_of::<T>());
    let ptr = unsafe {
        // SAFETY: We got originially the pointer from a `NonNull` and only
        // casted it to another type and added size metadata.
        NonNull::new_unchecked(ptr)
    };
    unsafe {
        // SAFETY: `ptr` points to a valid `T` and its `NoUninit`
        // implementation promises us that it's safe to view the data as a
        // slice of bytes.
        VolatilePtr::new_read_only(ptr)
    }
}

pub struct MushroomResult {
    pub output: Vec<u8>,
    pub attestation_report: Option<Vec<u8>>,
}

fn is_efault(err: &anyhow::Error) -> bool {
    err.downcast_ref::<nix::Error>()
        .is_some_and(|&err| err == nix::Error::EFAULT)
}
