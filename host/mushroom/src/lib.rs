#![feature(saturating_int_impl, slice_ptr_len, pointer_byte_offsets)]
// FIXME: Remove this once https://github.com/rust-lang/rust-clippy/pull/10321 lands on nightly.
#![allow(clippy::extra_unused_type_parameters)]

use std::{
    collections::{hash_map::Entry, HashMap},
    mem::size_of,
    num::Saturating,
    ptr::NonNull,
    sync::Arc,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bit_field::BitField;
use bytemuck::NoUninit;
use constants::{
    physical_address::DYNAMIC, FIRST_AP, KICK_AP_PORT, LOG_PORT, MAX_APS_COUNT, MEMORY_PORT,
};
use kvm::{KvmHandle, Page, VcpuHandle};
use snp_types::{
    ghcb::{
        self,
        msr_protocol::{GhcbInfo, PageOperation},
        Ghcb, PageSize, PageStateChangeEntry, PageStateChangeHeader,
    },
    guest_policy::GuestPolicy,
    vmsa::Vmsa,
    PageType,
};
use tracing::{debug, info};
use volatile::{
    access::{Access, ReadOnly, SafeAccess},
    map_field, map_field_mut, VolatilePtr,
};
use x86_64::{
    structures::paging::{PageSize as _, PhysFrame, Size2MiB},
    PhysAddr,
};

use crate::{
    kvm::{KvmExit, KvmExitUnknown, KvmMemoryAttributes, SevHandle, VmHandle},
    slot::Slot,
};

mod kvm;
mod slot;

pub fn main(init: &[u8], input: &[u8]) -> Result<()> {
    let kvm_handle = KvmHandle::new()?;
    let sev_handle = SevHandle::new()?;

    let mut vm_context = VmContext::prepare_vm(init, input, &kvm_handle, &sev_handle)?;
    vm_context.run_bsp()?;

    Ok(())
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
        init: &[u8],
        input: &[u8],
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

        vm.create_irqchip()?;

        vm.sev_snp_init()?;

        let policy = GuestPolicy::new(0, 0).with_allow_smt(true);
        // FIXME: Debug
        let policy = policy.with_allow_debugging(true);
        vm.sev_snp_launch_start(policy, sev_handle)?;

        let (load_commands, host_data) = loader::generate_load_commands(init, input);
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
                let Some(following_load_command) = following_load_command else { break; };
                pages.push(Page {
                    bytes: following_load_command.payload.bytes(),
                });
            }

            let slot = Slot::for_launch_update(gpa, &pages)
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

    pub fn run_bsp(&mut self) -> Result<()> {
        let kvm_run = self.bsp.get_kvm_run_block()?;

        let mut cooldown = Saturating(0u32);

        const DEBUG: bool = false;

        loop {
            let exit = kvm_run.read().exit();
            if DEBUG {
                dbg!(exit);
            }

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
                                    let slot =
                                        Slot::new(gfn).context("failed to create dynamic slot")?;

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
                KvmExit::Shutdown => break,
                KvmExit::MemoryFault(fault) => {
                    dbg!(fault);
                }
                KvmExit::Vmgexit(vmgexit) => {
                    let info = GhcbInfo::try_from(vmgexit.ghcb_msr)
                        .map_err(|_| anyhow!("invalid value in ghcb msr protocol"))?;
                    match info {
                        GhcbInfo::GhcbGuestPhysicalAddress { address } => {
                            let ghcb_slot = find_slot(address, &mut self.memory_slots)?;
                            let ghcb = ghcb_slot.read::<Ghcb>(ghcb_slot.gpa().start_address())?;

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

                                    dbg!(header);

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

                                        map_field_mut!(header.cur_entry).update(|cur| *cur += 1);
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
                        }
                        _ => bail!("unsupported msr protocol value: {info:?}"),
                    }
                }
                KvmExit::Other { exit_reason } => {
                    unimplemented!("exit with type: {exit_reason}");
                }
                KvmExit::Hlt => {
                    dbg!("hlt");
                }
                KvmExit::IrqWindowOpen => {
                    cooldown -= 1;
                    if cooldown.0 == 0 {
                        // dbg!(vcpu.queue_interrupt(NonZeroU8::new(step as u8).unwrap()));
                        cooldown = Saturating(10);
                    }
                }
                KvmExit::Interrupted => {}
                exit => {
                    panic!("unexpected exit: {exit:?}");
                }
            }

            let run_res = self.bsp.run();

            let ready_for_interrupt_injection =
                map_field!(kvm_run.ready_for_interrupt_injection).read();
            if DEBUG {
                dbg!(ready_for_interrupt_injection);
            }

            if DEBUG {
                let res = self.vm.sev_snp_dbg_decrypt_vmsa(0)?;
                let vmsa = bytemuck::checked::try_pod_read_unaligned::<Vmsa>(&res)?;
                dbg!(format_args!("{vmsa:#x?}"));
                dbg!(format_args!("{:#x?}", vmsa.rip));
            }

            if false {
                fn debug_page_table(vm_handle: &VmHandle) -> Result<()> {
                    let target_addr = 0xffff800003800000u64;

                    let c_bit_location = 51;

                    let res = vm_handle.sev_snp_dbg_decrypt_vmsa(0)?;
                    let vmsa = bytemuck::checked::try_pod_read_unaligned::<Vmsa>(&res)?;

                    let res = vm_handle.sev_snp_dbg_decrypt(vmsa.cr3.get_bits(12..=38))?;
                    let page_table = bytemuck::pod_read_unaligned::<[u64; 512]>(&res);
                    let entry = page_table[target_addr.get_bits(39..=47) as usize];
                    dbg!(format_args!("entry = {entry:#018x}"));
                    let mut gfn = entry.get_bits(12..=51);
                    gfn.set_bit(c_bit_location - 12, false);
                    dbg!(format_args!("{gfn:#018x}"));

                    let res = vm_handle.sev_snp_dbg_decrypt(gfn)?;
                    let page_table = bytemuck::pod_read_unaligned::<[u64; 512]>(&res);
                    let entry = page_table[target_addr.get_bits(30..=38) as usize];
                    dbg!(format_args!("entry = {entry:#018x}"));
                    let mut gfn = entry.get_bits(12..=51);
                    gfn.set_bit(c_bit_location - 12, false);
                    dbg!(format_args!("{gfn:#018x}"));

                    let res = vm_handle.sev_snp_dbg_decrypt(gfn)?;
                    let page_table = bytemuck::pod_read_unaligned::<[u64; 512]>(&res);
                    let entry = page_table[target_addr.get_bits(21..=29) as usize];
                    dbg!(format_args!("entry = {entry:#018x}"));
                    let mut gfn = entry.get_bits(12..=51);
                    gfn.set_bit(c_bit_location - 12, false);
                    dbg!(format_args!("{gfn:#018x}"));

                    let res = vm_handle.sev_snp_dbg_decrypt(gfn)?;
                    let page_table = bytemuck::pod_read_unaligned::<[u64; 512]>(&res);
                    let entry = page_table[target_addr.get_bits(12..=20) as usize];
                    dbg!(format_args!("entry = {entry:#018x}"));
                    let mut gfn = entry.get_bits(12..=51);
                    gfn.set_bit(c_bit_location - 12, false);
                    dbg!(format_args!("{gfn:#018x}"));

                    Ok(())
                }

                let _ = dbg!(debug_page_table(&self.vm));
            }

            if DEBUG {
                dbg!(run_res?);
            } else {
                run_res?;
            }
        }

        todo!()
    }

    fn run_ap(id: u8, vm: Arc<VmHandle>) -> JoinHandle<()> {
        std::thread::spawn(move || {
            let ap = vm.create_vcpu(i32::from(id)).unwrap();
            let kvm_run = ap.get_kvm_run_block().unwrap();

            loop {
                // Run the AP.
                let res = ap.run();

                if res.is_err() {
                    let res = vm.sev_snp_dbg_decrypt_vmsa(u32::from(id)).unwrap();
                    let vmsa = bytemuck::checked::try_pod_read_unaligned::<Vmsa>(&res).unwrap();
                    dbg!(format_args!("{vmsa:#x?}"));
                    dbg!(format_args!("{:#x?}", vmsa.rip));
                }

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
                        let res = vm.sev_snp_dbg_decrypt_vmsa(u32::from(id)).unwrap();
                        let vmsa = bytemuck::checked::try_pod_read_unaligned::<Vmsa>(&res).unwrap();
                        dbg!(format_args!("{vmsa:#x?}"));
                        dbg!(format_args!("{:#x?}", vmsa.rip));

                        fn debug_page_table(id: u8, vm: &VmHandle, addr: u64) -> Result<()> {
                            let c_bit_location = 51;

                            let res = vm.sev_snp_dbg_decrypt_vmsa(u32::from(id))?;
                            let vmsa = bytemuck::checked::try_pod_read_unaligned::<Vmsa>(&res)?;
                            let cr3 = vmsa.cr3.get_bits(12..=38);
                            dbg!(format_args!("{cr3:#018x}"));

                            let res = vm.sev_snp_dbg_decrypt(cr3)?;
                            let page_table = bytemuck::pod_read_unaligned::<[u64; 512]>(&res);
                            let entry = page_table[addr.get_bits(39..=47) as usize];
                            dbg!(format_args!("entry = {entry:#018x}"));
                            let mut gfn = entry.get_bits(12..=51);
                            gfn.set_bit(c_bit_location - 12, false);
                            dbg!(format_args!("{gfn:#018x}"));

                            let res = vm.sev_snp_dbg_decrypt(gfn)?;
                            let page_table = bytemuck::pod_read_unaligned::<[u64; 512]>(&res);
                            let entry = page_table[addr.get_bits(30..=38) as usize];
                            dbg!(format_args!("entry = {entry:#018x}"));
                            let mut gfn = entry.get_bits(12..=51);
                            gfn.set_bit(c_bit_location - 12, false);
                            dbg!(format_args!("{gfn:#018x}"));

                            let res = vm.sev_snp_dbg_decrypt(gfn)?;
                            let page_table = bytemuck::pod_read_unaligned::<[u64; 512]>(&res);
                            let entry = page_table[addr.get_bits(21..=29) as usize];
                            dbg!(format_args!("entry = {entry:#018x}"));
                            let mut gfn = entry.get_bits(12..=51);
                            gfn.set_bit(c_bit_location - 12, false);
                            dbg!(format_args!("{gfn:#018x}"));

                            let res = vm.sev_snp_dbg_decrypt(gfn)?;
                            let page_table = bytemuck::pod_read_unaligned::<[u64; 512]>(&res);
                            let entry = page_table[addr.get_bits(12..=20) as usize];
                            dbg!(format_args!("entry = {entry:#018x}"));
                            let mut gfn = entry.get_bits(12..=51);
                            gfn.set_bit(c_bit_location - 12, false);
                            dbg!(format_args!("{gfn:#018x}"));

                            Ok(())
                        }

                        let _ = dbg!(debug_page_table(id, &vm, vmsa.rip));

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
fn volatile_bytes_of<T, W>(
    ptr: VolatilePtr<T, Access<SafeAccess, W>>,
) -> VolatilePtr<[u8], ReadOnly>
where
    T: NoUninit,
{
    let data = ptr.as_ptr().as_ptr().cast::<u8>();
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
        VolatilePtr::new_generic(ptr)
    }
}
