//! This module makes it possible to run the mushroom kernel outside a SNP VM
//! and without the supervisor.

use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    sync::Arc,
    thread::Thread,
    time::{Duration, Instant},
};

use anyhow::{ensure, Context, Result};
use bit_field::BitField;
use constants::{
    physical_address::{kernel, supervisor, DYNAMIC_2MIB, SUPERVISOR_SERVICES},
    FIRST_AP, MAX_APS_COUNT,
};
use snp_types::PageType;
use supervisor_services::{
    allocation_buffer::{AllocationBuffer, SlotIndex},
    command_buffer::{CommandBufferReader, CommandHandler},
    SupervisorServices,
};
use tracing::info;
use x86_64::registers::{
    control::{Cr0Flags, Cr4Flags},
    model_specific::EferFlags,
    xcontrol::XCr0Flags,
};

use crate::{
    is_efault,
    kvm::{KvmCap, KvmCpuidEntry2, KvmExit, KvmHandle, KvmSegment, Page, VmHandle},
    logging::start_log_collection,
    slot::Slot,
    MushroomResult,
};

const TSC_MHZ: u64 = 100;

/// Create the VM, load the kernel, init & input and run the APs.
pub fn main(
    kernel: &[u8],
    init: &[u8],
    load_kasan_shadow_mappings: bool,
    input: &[u8],
) -> Result<MushroomResult> {
    let kvm_handle = KvmHandle::new()?;

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

    let vm = kvm_handle.create_vm()?;
    let vm = Arc::new(vm);

    const KVM_MSR_EXIT_REASON_UNKNOWN: u64 = 1;
    const KVM_MSR_EXIT_REASON_FILTER: u64 = 2;
    vm.enable_capability(
        KvmCap::X86_USER_SPACE_MSR,
        KVM_MSR_EXIT_REASON_UNKNOWN | KVM_MSR_EXIT_REASON_FILTER,
    )?;

    vm.set_tsc_khz(TSC_MHZ * 1000)?;

    let (load_commands, _host_data) =
        loader::generate_load_commands(None, kernel, init, load_kasan_shadow_mappings, input);
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

        let slot = Slot::for_launch_update(&vm, gpa, &pages, false)
            .context("failed to create slot for launch update")?;

        unsafe {
            vm.map_encrypted_memory(slot_id, &slot)?;
        }

        if let Some(first_page_type) = first_page_type {
            let update_start = Instant::now();

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

    info!(
        num_launch_pages,
        num_data_pages,
        ?total_launch_duration,
        "launched"
    );

    // Create a bunch of APs.
    let cpuid_entries = Arc::<[KvmCpuidEntry2]>::from(cpuid_entries);
    let ap_threads = (0..MAX_APS_COUNT)
        .map(|i| {
            let id = FIRST_AP + i;
            run_kernel_vcpu(id, vm.clone(), cpuid_entries.clone())
        })
        .collect::<Vec<_>>();
    ap_threads[0].unpark();
    start_log_collection(&memory_slots, kernel::LOG_BUFFER)?;
    start_log_collection(&memory_slots, supervisor::LOG_BUFFER)?;

    let supervisor_services = memory_slots
        .values()
        .find(|s| s.gpa() == SUPERVISOR_SERVICES.start)
        .context("couldn't find supervisor services region")?;
    let supervisor_services = supervisor_services.shared_mapping();
    ensure!(
        supervisor_services.len().get() >= size_of::<SupervisorServices>(),
        "supervisor services region is too small"
    );
    let supervisor_services = unsafe {
        supervisor_services
            .as_ptr()
            .cast::<SupervisorServices>()
            .as_ref()
    };

    let mut command_buffer_reader = CommandBufferReader::new(&supervisor_services.command_buffer);
    let mut handler = InsecureCommandHandler {
        allocation_buffer: &supervisor_services.allocation_buffer,
        dynamic_memory: DynamicMemory::new(vm),
        pending_aps: ap_threads.iter().skip(1).cloned().collect(),
        output: Vec::new(),
        finish_status: None,
    };
    let finish_status = loop {
        while command_buffer_reader.handle(&mut handler) {}

        for i in supervisor_services.notification_buffer.reset() {
            ap_threads[i].unpark();
        }

        if let Some(finish_status) = handler.finish_status {
            break finish_status;
        }

        std::thread::park();
    };
    ensure!(finish_status, "workload failed");

    Ok(MushroomResult {
        output: handler.output,
        attestation_report: None,
    })
}

fn run_kernel_vcpu(id: u8, vm: Arc<VmHandle>, cpuid_entries: Arc<[KvmCpuidEntry2]>) -> Thread {
    let supervisor_thread = std::thread::current();

    std::thread::spawn(move || {
        let ap = vm.create_vcpu(i32::from(id)).unwrap();
        ap.set_cpuid(&cpuid_entries).unwrap();

        let kvm_run = ap.get_kvm_run_block().unwrap();

        let mut sregs = ap.get_sregs().unwrap();
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
        ap.set_sregs(sregs).unwrap();
        ap.set_xcr(
            0,
            XCr0Flags::X87.bits() | XCr0Flags::SSE.bits() | XCr0Flags::AVX.bits(),
        )
        .unwrap();

        let mut regs = ap.get_regs().unwrap();
        regs.rip = 0xffff_8000_0000_0000;
        regs.rsp = 0xffff_8000_0400_3ff8;
        ap.set_regs(regs).unwrap();

        std::thread::park();

        loop {
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
                KvmExit::Hlt => {
                    let resume = kvm_run_value.cr8.get_bit(0);

                    supervisor_thread.unpark();

                    if !resume {
                        std::thread::park();
                    }
                }
                KvmExit::SetTpr => {}
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
                exit => {
                    let regs = ap.get_regs().unwrap();
                    println!("{:x}", regs.rip);

                    panic!("unexpected exit {exit:?}");
                }
            }
        }
    })
    .thread()
    .clone()
}

const SLOTS: usize = 1 << 15;

struct DynamicMemory {
    vm: Arc<VmHandle>,
    slots: HashMap<u16, Slot>,
}

impl DynamicMemory {
    pub fn new(vm: Arc<VmHandle>) -> Self {
        Self {
            vm,
            slots: HashMap::new(),
        }
    }

    pub fn allocate_slot_id(&mut self) -> Option<SlotIndex> {
        for slot_id in 0..SLOTS as u16 {
            if let Entry::Vacant(entry) = self.slots.entry(slot_id) {
                let gpa = DYNAMIC_2MIB.start + u64::from(slot_id);
                let slot = entry.insert(Slot::new(&self.vm, gpa, false).unwrap());

                let base = 1 << 6;
                let kvm_slot_id = base + slot_id;
                unsafe {
                    self.vm.map_encrypted_memory(kvm_slot_id, slot).unwrap();
                }

                return Some(SlotIndex::new(slot_id));
            }
        }

        None
    }

    pub fn deallcoate_slot_id(&mut self, id: SlotIndex) {
        let slot = self.slots.remove(&id.get()).unwrap();
        let base = 1 << 6;
        let kvm_slot_id = base + id.get();
        unsafe {
            self.vm.unmap_encrypted_memory(kvm_slot_id, &slot).unwrap();
        }
    }
}
struct InsecureCommandHandler<'a> {
    allocation_buffer: &'a AllocationBuffer,
    dynamic_memory: DynamicMemory,
    pending_aps: VecDeque<Thread>,
    output: Vec<u8>,
    finish_status: Option<bool>,
}

impl CommandHandler for InsecureCommandHandler<'_> {
    fn start_next_ap(&mut self) {
        let Some(pending_ap) = self.pending_aps.pop_front() else {
            return;
        };
        pending_ap.unpark();
    }

    fn allocate_memory(&mut self) {
        while let Some(entry) = self.allocation_buffer.find_free_entry() {
            let Some(slot_idx) = self.dynamic_memory.allocate_slot_id() else {
                break;
            };
            entry.set(slot_idx);
        }
    }

    fn deallocate_memory(&mut self, slot_idx: SlotIndex) {
        self.dynamic_memory.deallcoate_slot_id(slot_idx);
    }

    fn update_output(&mut self, output: &[u8]) {
        self.output.extend_from_slice(output);
    }

    fn finish_output(&mut self) {
        self.finish_status.get_or_insert(true);
    }

    fn fail_output(&mut self) {
        self.finish_status.get_or_insert(false);
    }
}
