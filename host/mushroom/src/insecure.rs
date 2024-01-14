//! This module makes it possible to run the mushroom kernel outside a SNP VM
//! and without the supervisor.

use std::{
    collections::{hash_map::Entry, HashMap},
    sync::{
        mpsc::{self, SyncSender},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bit_field::BitField;
use bytemuck::bytes_of;
use constants::{
    physical_address::DYNAMIC, FINISH_OUTPUT_MSR, FIRST_AP, MAX_APS_COUNT, MEMORY_MSR,
    UPDATE_OUTPUT_MSR,
};
use snp_types::PageType;
use tracing::{debug, info};
use x86_64::{
    registers::{
        control::{Cr0Flags, Cr4Flags},
        model_specific::EferFlags,
        xcontrol::XCr0Flags,
    },
    structures::paging::{PageSize as _, PhysFrame, Size2MiB, Size4KiB},
    PhysAddr,
};

use crate::{
    kvm::{KvmCap, KvmCpuidEntry2, KvmExit, KvmHandle, KvmSegment, Page, VmHandle},
    slot::Slot,
    MushroomResult,
};

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

    let vm = kvm_handle.create_vm()?;
    let vm = Arc::new(vm);

    const KVM_MSR_EXIT_REASON_UNKNOWN: u64 = 1;
    vm.enable_capability(KvmCap::X86_USER_SPACE_MSR, KVM_MSR_EXIT_REASON_UNKNOWN)?;

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
    let dynamic_memory_state = Arc::new(DynamicMemory::new(vm.clone()));
    let (tx, rx) = mpsc::sync_channel(0);

    for i in 0..MAX_APS_COUNT {
        let id = FIRST_AP + i;
        run_ap(
            id,
            vm.clone(),
            cpuid_entries.clone(),
            dynamic_memory_state.clone(),
            tx.clone(),
        );
    }

    let mut output = Vec::new();
    loop {
        match rx.recv().context("failed to receive output event")? {
            OutputEvent::Update(mut data) => output.append(&mut data),
            OutputEvent::Finish => {
                debug!("received finish event");
                break;
            }
        }
    }

    Ok(MushroomResult {
        output,
        attestation_report: None,
    })
}

fn run_ap(
    id: u8,
    vm: Arc<VmHandle>,
    cpuid_entries: Arc<[KvmCpuidEntry2]>,
    dynamic_memory: Arc<DynamicMemory>,
    tx: SyncSender<OutputEvent>,
) {
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
            | EferFlags::NO_EXECUTE_ENABLE.bits()
            | EferFlags::SECURE_VIRTUAL_MACHINE_ENABLE.bits();
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

        if id != FIRST_AP {
            std::thread::park();
        }

        loop {
            // Run the AP.
            ap.run().unwrap();

            // Check the exit.
            let exit = kvm_run.read().exit();
            match exit {
                KvmExit::Io(_) => {
                    let regs = ap.get_regs().unwrap();
                    let fpu = ap.get_fpu().unwrap();
                    let bytes = &bytes_of(&fpu.xmm)[..regs.rax as usize];
                    let str = String::from_utf8_lossy(bytes);
                    print!("{str}");
                }
                KvmExit::RdMsr(mut msr) => {
                    match msr.index {
                        MEMORY_MSR => {
                            msr.data = dynamic_memory.allocate_slot_id().unwrap();
                        }
                        idx => todo!("unimplemented MSR access: {idx:#010x}"),
                    }

                    kvm_run.update(|mut kvm_run| {
                        kvm_run.set_exit(KvmExit::RdMsr(msr));
                        kvm_run
                    });
                }
                KvmExit::WrMsr(msr) => match msr.index {
                    UPDATE_OUTPUT_MSR => {
                        let gfn =
                            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(msr.data));
                        let len = ((msr.data & 0xfff) + 1) as usize;

                        let data = dynamic_memory.read(gfn, len).unwrap();

                        tx.send(OutputEvent::Update(data)).unwrap();
                    }
                    FINISH_OUTPUT_MSR => {
                        tx.send(OutputEvent::Finish).unwrap();
                        return;
                    }
                    idx => todo!("unimplemented MSR access: {idx:#010x}"),
                },
                exit => {
                    let regs = ap.get_regs().unwrap();
                    println!("{:x}", regs.rip);

                    panic!("unexpected exit {exit:?}");
                }
            }
        }
    });
}

const SLOTS: usize = 1 << 15;

struct DynamicMemory {
    vm: Arc<VmHandle>,
    state: Mutex<HashMap<u16, Slot>>,
}

impl DynamicMemory {
    pub fn new(vm: Arc<VmHandle>) -> Self {
        Self {
            vm,
            state: Mutex::new(HashMap::new()),
        }
    }

    pub fn allocate_slot_id(&self) -> Option<u64> {
        let mut guard = self.state.lock().unwrap();
        for slot_id in 0..SLOTS as u16 {
            if let Entry::Vacant(entry) = guard.entry(slot_id) {
                let gpa = DYNAMIC.start() + u64::from(slot_id) * Size2MiB::SIZE;
                let slot = entry.insert(
                    Slot::new(
                        &self.vm,
                        PhysFrame::containing_address(PhysAddr::new(gpa)),
                        false,
                    )
                    .unwrap(),
                );

                let base = 1 << 6;
                let kvm_slot_id = base + slot_id;
                unsafe {
                    self.vm.map_encrypted_memory(kvm_slot_id, slot).unwrap();
                }

                return Some(gpa);
            }
        }

        None
    }

    fn read(&self, gfn: PhysFrame, len: usize) -> Option<Vec<u8>> {
        let mut guard = self.state.lock().unwrap();

        let slot = guard.values_mut().find(|slot| {
            let num_frames = u64::try_from(slot.shared_mapping().len().get() / 0x1000).unwrap();
            (slot.gpa()..slot.gpa() + num_frames).contains(&gfn)
        })?;

        let output_buffer = slot.read::<[u8; 4096]>(gfn.start_address()).ok()?;

        Some(output_buffer[..len].to_vec())
    }
}

enum OutputEvent {
    Update(Vec<u8>),
    Finish,
}
