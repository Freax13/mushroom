use core::{
    cell::{Cell, RefCell},
    mem::replace,
};

use bit_field::BitField;
use constants::{
    EXIT_PORT, FINISH_OUTPUT_MSR, FIRST_AP, HALT_PORT, KICK_AP_PORT, LOG_PORT, MAX_APS_COUNT,
    MEMORY_MSR, SCHEDULE_PORT, UPDATE_OUTPUT_MSR,
};
use log::{debug, info, trace};
use snp_types::{
    intercept::{VMEXIT_CPUID, VMEXIT_IOIO, VMEXIT_MSR},
    vmsa::{SevFeatures, Vmsa},
    VmplPermissions,
};
use x86_64::{
    instructions::hlt,
    structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame},
    PhysAddr,
};

use crate::{
    cpuid::get_cpuid_value,
    doorbell::DOORBELL,
    dynamic::HOST_ALLOCTOR,
    ghcb::{create_ap, eoi, exit, ioio_write},
    output::{self, update_output},
    pagetable::TEMPORARY_MAPPER,
    FakeSync,
};

use self::{log_buffer::LogBuffer, vmsa::InitializedVmsa};

mod log_buffer;
mod vmsa;

const SEV_FEATURES: SevFeatures = SevFeatures::from_bits_truncate(
    SevFeatures::SNP_ACTIVE.bits()
        | SevFeatures::V_TOM.bits()
        | SevFeatures::REFLECT_VC.bits()
        | SevFeatures::RESTRICTED_INJECTION.bits(),
);

static APS: FakeSync<[RefCell<Ap>; MAX_APS_COUNT as usize]> =
    FakeSync::new([const { RefCell::new(Ap::new()) }; MAX_APS_COUNT as usize]);

static SCHEDULE_COUNTER: FakeSync<Cell<u8>> = FakeSync::new(Cell::new(0));

#[allow(clippy::large_enum_variant)]
pub enum Ap {
    Uninitialized,
    Initialized(Initialized),
}

impl Ap {
    pub const fn new() -> Self {
        Self::Uninitialized
    }

    pub fn start(&mut self, apic_id: u8) {
        debug!("initializing vcpu {apic_id}");

        assert!(matches!(self, Ap::Uninitialized));

        *self = Self::Initialized(Initialized::new(apic_id));

        let Self::Initialized(initialized) = self else { unreachable!(); };
        initialized.boot();
    }
}

pub struct Initialized {
    halted: bool,
    apic_id: u8,
    log_buffer: LogBuffer,
    vmsa: InitializedVmsa,
}

impl Initialized {
    pub fn new(apic_id: u8) -> Self {
        Initialized {
            halted: false,
            apic_id,
            log_buffer: LogBuffer::new(),
            vmsa: InitializedVmsa::new(),
        }
    }

    pub fn boot(&mut self) {
        unsafe {
            self.vmsa.set_runnable(true);
        }

        let vmsa_pa = self.vmsa.phys_addr();
        create_ap(u32::from(self.apic_id), vmsa_pa, SEV_FEATURES);
    }

    pub fn handle_vc(&mut self) {
        // Set the VMSA as unrunnable. This will make sure that the host
        // doesn't try run the vCPU while we're handling the VC.
        // This will also fail if the vCPU is currently running.
        unsafe {
            self.vmsa.set_runnable(false);
        }

        let mut vmsa = self.vmsa.modify();
        // Replace the exit code to prevent the host to tell us to handle the
        // same exception twice.
        let guest_exit_code = replace(&mut vmsa.guest_exit_code, 0xffff_ffff);
        let guest_exit_info1 = vmsa.guest_exit_info1;
        let _guest_nrip = vmsa.guest_nrip;

        match guest_exit_code {
            VMEXIT_CPUID => handle_cpuid(&mut vmsa),
            VMEXIT_IOIO => handle_ioio_prot(
                guest_exit_info1,
                vmsa.rax,
                &mut vmsa,
                &mut self.log_buffer,
                &mut self.halted,
            ),
            VMEXIT_MSR => handle_msr_prot(
                guest_exit_info1,
                vmsa.rax as u32,
                vmsa.rcx as u32,
                vmsa.rdx as u32,
                &mut vmsa,
            ),
            _ => todo!("unhandled guest exit code: {guest_exit_code:#x}"),
        }

        // We're done handling the event. Mark the VMSA as runnable again.
        drop(vmsa);

        if !self.halted {
            self.kick();
        }
    }

    pub fn kick(&mut self) {
        let apic_id = self.apic_id;
        ioio_write(KICK_AP_PORT, u32::from(apic_id));
    }
}

fn handle_cpuid(vmsa: &mut Vmsa) {
    let eax = vmsa.rax as u32;
    let ecx = vmsa.rcx as u32;
    let xcr0 = vmsa.xcr0;
    let xss = vmsa.xss;

    let (eax, ebx, ecx, edx) = get_cpuid_value(eax, ecx, xcr0, xss);

    vmsa.rax = u64::from(eax);
    vmsa.rbx = u64::from(ebx);
    vmsa.rcx = u64::from(ecx);
    vmsa.rdx = u64::from(edx);

    // Advance RIP.
    vmsa.rip = vmsa.guest_nrip;
}

fn handle_ioio_prot(
    guest_exit_info1: u64,
    rax: u64,
    vmsa: &mut Vmsa,
    log_buffer: &mut LogBuffer,
    halted: &mut bool,
) {
    let port = guest_exit_info1.get_bits(16..=31) as u16;

    match port {
        EXIT_PORT => exit(),
        LOG_PORT => {
            // Verify the inputs.
            assert_eq!(guest_exit_info1.get_bits(10..=12), 0); // We don't support segments.
            assert!(guest_exit_info1.get_bit(9)); // We only support 64-bit addresses.
            assert!(guest_exit_info1.get_bit(6)); // We only support 32-bit accesses.
            assert!(!guest_exit_info1.get_bit(3)); // We don't support repeat access.
            assert!(!guest_exit_info1.get_bit(2)); // We don't support string based access.
            assert!(!guest_exit_info1.get_bit(0)); // We only support writes.

            let char = char::try_from(rax as u32).unwrap_or('?');
            log_buffer.write(char);
        }
        KICK_AP_PORT => {
            let apic_id = u8::try_from(rax).unwrap();

            let mut ap = APS[usize::from(apic_id)].borrow_mut();

            match &mut *ap {
                Ap::Uninitialized => ap.start(FIRST_AP + apic_id),
                Ap::Initialized(initialized) => initialized.kick(),
            }
        }
        SCHEDULE_PORT => {
            let old_schedule_counter = SCHEDULE_COUNTER.get();
            let new_schedule_counter =
                old_schedule_counter.saturating_add(u8::try_from(rax).unwrap_or(!0));
            SCHEDULE_COUNTER.set(new_schedule_counter);
        }
        HALT_PORT => {
            *halted = true;
        }
        _ => unimplemented!("write to unexpected port: {port:#x}"),
    }

    // Advance RIP.
    vmsa.rip = vmsa.guest_nrip;
}

fn handle_msr_prot(guest_exit_info1: u64, eax: u32, ecx: u32, edx: u32, vmsa: &mut Vmsa) {
    match guest_exit_info1 {
        0 => {
            // Read
            match ecx {
                MEMORY_MSR => {
                    let frame = (&HOST_ALLOCTOR).allocate_frame();

                    if let Some(frame) = frame {
                        // Create a temporary mapping.
                        let mut mapper = TEMPORARY_MAPPER.borrow_mut();
                        let mapping = mapper.create_temporary_mapping_2mib(frame, false);

                        // Make the frame accessible to VMPL 1.
                        unsafe {
                            mapping.rmpadjust(1, VmplPermissions::all(), false);
                        }
                    }

                    trace!("allocated {frame:?}");
                    let value = frame
                        .map(PhysFrame::start_address)
                        .map_or(0, PhysAddr::as_u64);
                    vmsa.rax = value.get_bits(..32);
                    vmsa.rdx = value.get_bits(32..);
                }
                _ => unimplemented!("unhandled MSR {ecx:#x}"),
            }
        }
        1 => {
            // Write
            let value = u64::from(edx) << 32 | u64::from(eax);
            match ecx {
                MEMORY_MSR => {
                    let addr = PhysAddr::new(value);
                    let frame = PhysFrame::from_start_address(addr).unwrap();
                    trace!("deallocating {frame:?}");
                    unsafe {
                        (&HOST_ALLOCTOR).deallocate_frame(frame);
                    }
                }
                UPDATE_OUTPUT_MSR => {
                    let frame = PhysFrame::containing_address(PhysAddr::new(value));
                    let len = ((value & 0xfff) + 1) as usize;

                    let mut buffer = [0; 0x1000];
                    let buffer = &mut buffer[..len];

                    {
                        let mut mapper = TEMPORARY_MAPPER.borrow_mut();
                        let mapping = mapper.create_temporary_mapping_4kib(frame, true, false);
                        mapping.read(buffer);
                    }

                    update_output(buffer);
                }
                FINISH_OUTPUT_MSR => {
                    if value == 0 {
                        panic!("init process failed");
                    }

                    // Create the attestation report.
                    output::finish();
                }
                _ => unimplemented!("unhandled MSR {ecx:#x}"),
            }
        }
        _ => unreachable!(),
    }

    // Advance RIP.
    vmsa.rip = vmsa.guest_nrip;
}

pub fn run_aps() {
    info!("booting first AP");
    let mut first_ap = APS[0].borrow_mut();
    first_ap.start(FIRST_AP);
    drop(first_ap);

    // Process events while there are still APs running.
    while !all_halted() {
        let pending_event = DOORBELL.fetch_pending_event();

        // If no AP requires assistance, sleep and try again.
        if pending_event.is_empty() {
            hlt();
            continue;
        }

        // These events shouldn't happen. Abort if they do.
        assert!(!pending_event.nmi());
        assert!(!pending_event.mc());

        // Assist the AP the host requested us to assist.
        let vector = pending_event.vector().unwrap().get();
        let idx = usize::from(vector - FIRST_AP);
        {
            let mut ap = APS[idx].borrow_mut();
            if let Ap::Initialized(initialized) = &mut *ap {
                initialized.handle_vc();
            } else {
                panic!("can't handle event for uninitialized ap");
            }
        }

        // We're done handling events.
        if DOORBELL.requires_eoi() {
            eoi().unwrap();
        }

        // Schedule additionals APs if previously requested.
        schedule_aps();
    }
}

pub fn schedule_aps() {
    let mut schedule_counter = SCHEDULE_COUNTER.get();

    while schedule_counter > 0 {
        if !schedule_one() {
            break;
        }
        schedule_counter -= 1;
    }

    SCHEDULE_COUNTER.set(schedule_counter);
}

/// Returns true if an AP was scheduled.
fn schedule_one() -> bool {
    for ap in APS.iter() {
        let mut ap = ap.borrow_mut();
        if let Ap::Initialized(initialized) = &mut *ap {
            if initialized.halted {
                debug!("kick core {}", initialized.apic_id - FIRST_AP);
                initialized.halted = false;
                initialized.kick();
                return true;
            }
        }
    }

    false
}

/// Returns true if all APs are halted.
pub fn all_halted() -> bool {
    for ap in APS.iter() {
        match &*ap.borrow() {
            Ap::Uninitialized => {}
            Ap::Initialized(i) => {
                if !i.halted {
                    return false;
                }
            }
        }
    }

    true
}
