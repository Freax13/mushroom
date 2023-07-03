#![feature(pointer_byte_offsets)]

use std::{
    collections::{hash_map::Entry, HashMap},
    mem::size_of,
    ptr::NonNull,
    sync::Arc,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bit_field::BitField;
use bytemuck::NoUninit;
use constants::{
    physical_address::DYNAMIC, FINISH_OUTPUT_MSR, FIRST_AP, KICK_AP_PORT, LOG_PORT, MAX_APS_COUNT,
    MEMORY_PORT, UPDATE_OUTPUT_MSR,
};
use kvm::{KvmHandle, Page, VcpuHandle};
use snp_types::{
    ghcb::{
        self,
        msr_protocol::{GhcbInfo, PageOperation},
        Ghcb, PageSize, PageStateChangeEntry, PageStateChangeHeader,
    },
    guest_policy::GuestPolicy,
    PageType,
};
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
    kvm::{
        KvmCap, KvmExit, KvmExitUnknown, KvmExitVmgexit, KvmMemoryAttributes, SevHandle, VmHandle,
    },
    slot::Slot,
};

mod kvm;
mod slot;

pub fn main(
    supervisor: &[u8],
    kernel: &[u8],
    init: &[u8],
    input: &[u8],
    policy: GuestPolicy,
) -> Result<MushroomResult> {
    let kvm_handle = KvmHandle::new()?;
    let sev_handle = SevHandle::new()?;

    let mut vm_context = VmContext::prepare_vm(
        supervisor,
        kernel,
        init,
        input,
        policy,
        &kvm_handle,
        &sev_handle,
    )?;
    vm_context.run_bsp()
}

struct VmContext {
    vm: Arc<VmHandle>,
    bsp: VcpuHandle,
    ap_threads: HashMap<u8, JoinHandle<()>>,
    memory_slots: HashMap<u16, Slot>,
}

impl VmContext {
    /// Create the VM, create the BSP and execute all launch commands.
    pub fn prepare_vm(
        supervisor: &[u8],
        kernel: &[u8],
        init: &[u8],
        input: &[u8],
        policy: GuestPolicy,
        kvm_handle: &KvmHandle,
        sev_handle: &SevHandle,
    ) -> Result<Self> {
        let mut cpuid_entries = kvm_handle.get_supported_cpuid()?;
        let piafb = cpuid_entries
            .iter_mut()
            .find(|entry| entry.function == 1 && entry.index == 0)
            .context("failed to find 'processor info and feature bits' entry")?;
        // Enable CPUID
        piafb.ecx.set_bit(21, true);

        let vm = kvm_handle.create_vm(true)?;
        let vm = Arc::new(vm);

        const KVM_MSR_EXIT_REASON_UNKNOWN: u64 = 1;
        vm.enable_capability(KvmCap::X86_USER_SPACE_MSR, KVM_MSR_EXIT_REASON_UNKNOWN)?;

        vm.create_irqchip()?;

        vm.sev_snp_init()?;

        vm.sev_snp_launch_start(policy, sev_handle)?;

        let (load_commands, host_data) =
            loader::generate_load_commands(supervisor, kernel, init, input);
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
            for i in 1..0xfffff {
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

            let slot = Slot::for_launch_update(&vm, gpa, &pages)
                .context("failed to create slot for launch update")?;

            unsafe {
                vm.map_encrypted_memory(slot_id, &slot)?;
            }

            if let Some(first_page_type) = first_page_type {
                let update_start = Instant::now();

                vm.sev_snp_launch_update(
                    gpa.start_address().as_u64(),
                    u64::try_from(slot.shared_mapping().as_ptr().as_ptr() as usize)?,
                    u32::try_from(slot.shared_mapping().len().get())?,
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

        // Create a bunch of APs.
        let aps = (0..MAX_APS_COUNT)
            .map(|i| {
                let id = FIRST_AP + i;
                let ap_thread = Self::run_ap(id, vm.clone());
                Ok((id, ap_thread))
            })
            .collect::<Result<_>>()?;

        Ok(Self {
            vm,
            bsp,
            ap_threads: aps,
            memory_slots,
        })
    }

    pub fn run_bsp(&mut self) -> Result<MushroomResult> {
        let mut output = Vec::new();
        let kvm_run = self.bsp.get_kvm_run_block()?;

        loop {
            let exit = kvm_run.read().exit();

            match exit {
                KvmExit::Unknown(KvmExitUnknown {
                    hardware_exit_reason: 0,
                }) => {}
                KvmExit::Debug(_) => {}
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
                        LOG_PORT => {
                            let c = char::try_from(value).unwrap();
                            print!("{c}");
                        }
                        MEMORY_PORT => {
                            let slot_id = value.get_bits(0..15) as u16;
                            let enabled = value.get_bit(15);
                            let gpa = DYNAMIC.start() + u64::from(slot_id) * Size2MiB::SIZE;
                            debug!(slot_id, enabled, gpa = %format_args!("{gpa:#x}"), "updating slot status");

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

                                    let gpa = DYNAMIC.start() + u64::from(slot_id) * Size2MiB::SIZE;
                                    let gfn =
                                        PhysFrame::from_start_address(PhysAddr::new(gpa)).unwrap();
                                    let slot = Slot::new(&self.vm, gfn)
                                        .context("failed to create dynamic slot")?;

                                    unsafe {
                                        self.vm.map_encrypted_memory(kvm_slot_id, &slot)?;
                                    }

                                    let mut address = gpa;
                                    let mut size = Size2MiB::SIZE;
                                    self.vm.set_memory_attributes(
                                        &mut address,
                                        &mut size,
                                        KvmMemoryAttributes::PRIVATE,
                                    )?;
                                    ensure!(size == 0);

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
                KvmExit::Vmgexit(vmgexit) => {
                    let info = GhcbInfo::try_from(vmgexit.ghcb_msr)
                        .map_err(|_| anyhow!("invalid value in ghcb msr protocol"))?;
                    debug!(?info, "handling vmgexit");
                    match info {
                        GhcbInfo::GhcbGuestPhysicalAddress { address } => {
                            let ghcb_slot = find_slot(address, &mut self.memory_slots)?;
                            let ghcb = ghcb_slot.read::<Ghcb>(address.start_address())?;

                            let exit_code = ghcb.sw_exit_code;
                            debug!(exit_code = %format_args!("{exit_code:#010x}"), "handling ghcb request");

                            match exit_code {
                                0x8000_0010 => {
                                    let psc_desc = ghcb.sw_scratch;
                                    debug!(exit_code = %format_args!("{psc_desc:#018x}"), "handling psc request");

                                    let psc_desc_gpa = PhysAddr::try_new(psc_desc)
                                        .map_err(|_| anyhow!("psc desc is not a valid gpa"))?;
                                    let psc_desc_gfn = PhysFrame::containing_address(psc_desc_gpa);
                                    let psc_desc_slot =
                                        find_slot(psc_desc_gfn, &mut self.memory_slots)?;

                                    let header = psc_desc_slot
                                        .shared_ptr::<PageStateChangeHeader>(psc_desc_gpa)?;

                                    loop {
                                        let cur_entry = map_field!(header.cur_entry).read();
                                        if cur_entry > map_field!(header.end_entry).read() {
                                            break;
                                        }

                                        let entry = psc_desc_slot
                                            .shared_ptr::<PageStateChangeEntry>(
                                                psc_desc_gpa + 8u64 + u64::from(cur_entry) * 8,
                                            )?
                                            .read();

                                        match entry.page_operation() {
                                            Ok(ghcb::PageOperation::PageAssignmentShared) => {
                                                ensure!(
                                                    entry.page_size() == PageSize::Size4KiB,
                                                    "only 4kib pages are supported"
                                                );

                                                let mut address =
                                                    entry.gfn().start_address().as_u64();
                                                let mut size = 0x1000;
                                                self.vm.set_memory_attributes(
                                                    &mut address,
                                                    &mut size,
                                                    KvmMemoryAttributes::empty(),
                                                )?;
                                                ensure!(size == 0);
                                            }
                                            Ok(op) => bail!("unsupported page operation: {op:?}"),
                                            Err(op) => bail!("unknown page operation: {op:?}"),
                                        }

                                        map_field!(header.cur_entry).update(|cur| cur + 1);
                                    }
                                }
                                _ => bail!("unsupported exit code: {exit_code:#x}"),
                            }
                        }
                        GhcbInfo::SnpPageStateChangeRequest { operation, address } => {
                            let mut attributes = KvmMemoryAttributes::empty();
                            match operation {
                                PageOperation::PageAssignmentPrivate => {
                                    attributes |= KvmMemoryAttributes::PRIVATE;
                                }
                                PageOperation::PageAssignmentShared => {}
                            }
                            let mut address = address.start_address().as_u64();
                            let mut size = 0x1000;
                            self.vm
                                .set_memory_attributes(&mut address, &mut size, attributes)?;
                            ensure!(size == 0);

                            let response =
                                GhcbInfo::SnpPageStateChangeResponse { error_code: None };
                            kvm_run.update(|mut run| {
                                run.set_exit(KvmExit::Vmgexit(KvmExitVmgexit {
                                    ghcb_msr: response.into(),
                                    error: 0,
                                }));
                                run
                            });
                        }
                        _ => bail!("unsupported msr protocol value: {info:?}"),
                    }
                }
                KvmExit::Msr(msr) => match msr.index {
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
                        info!("finished");

                        let gfn =
                            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(msr.data));
                        let len = (msr.data & 0xfff) as usize;

                        let slot = find_slot(gfn, &mut self.memory_slots)?;
                        let attestation_report = slot.read::<[u8; 4096]>(gfn.start_address())?;

                        let attestation_report = attestation_report[..len].to_vec();
                        return Ok(MushroomResult {
                            output,
                            attestation_report,
                        });
                    }
                    index => unimplemented!("unsupported MSR: {index:#08x}"),
                },
                KvmExit::Other { exit_reason } => {
                    unimplemented!("exit with type: {exit_reason}");
                }
                KvmExit::Hlt => {
                    dbg!("hlt");
                }
                KvmExit::Interrupted => {}
                exit => {
                    panic!("unexpected exit: {exit:?}");
                }
            }

            let run_res = self.bsp.run();

            run_res?;
        }
    }

    fn run_ap(id: u8, vm: Arc<VmHandle>) -> JoinHandle<()> {
        std::thread::spawn(move || {
            let ap = vm.create_vcpu(i32::from(id)).unwrap();
            let kvm_run = ap.get_kvm_run_block().unwrap();

            loop {
                // Run the AP.
                let res = ap.run();

                res.unwrap();

                // Check the exit.
                let kvm_run = kvm_run.read();
                match kvm_run.exit() {
                    KvmExit::ReflectVc => {
                        // Notify the BSP about the Reflect #VC.
                        vm.signal_msi(0xfee0_0000, u32::from(id)).unwrap();

                        // Wait for the BSP to wake the AP back up.
                        std::thread::park();
                    }
                    exit => {
                        panic!("unexpected exit {exit:?}");
                    }
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
    pub attestation_report: Vec<u8>,
}
