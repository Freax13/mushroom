use core::{
    cell::SyncUnsafeCell,
    sync::atomic::{AtomicUsize, Ordering},
};

use constants::{physical_address::supervisor::snp::VMSAS, MAX_APS_COUNT};
use snp_types::{
    vmsa::{Segment, SevFeatures, Vmsa, VmsaTweakBitmap},
    VmplPermissions,
};
use x86_64::{
    registers::{
        control::{Cr0Flags, Cr4Flags},
        model_specific::EferFlags,
        xcontrol::XCr0Flags,
    },
    structures::paging::{Page, PhysFrame, Size4KiB},
    VirtAddr,
};

use crate::rmp::rmpadjust;

use super::SEV_FEATURES;

#[link_section = ".vmsas"]
static SLOTS: [SyncUnsafeCell<Vmsa>; MAX_APS_COUNT as usize] = {
    let tweak_bitmap = &VmsaTweakBitmap::ZERO;
    let mut vmsas = [const { SyncUnsafeCell::new(Vmsa::new()) }; MAX_APS_COUNT as usize];

    let mut i = 0;
    while i < MAX_APS_COUNT {
        let tsc_aux = i as u32;

        let mut vmsa = Vmsa::new();
        unsafe {
            vmsa.set_vmpl(1, tweak_bitmap);
            vmsa.set_efer(
                EferFlags::from_bits_retain(
                    EferFlags::SYSTEM_CALL_EXTENSIONS.bits()
                        | EferFlags::LONG_MODE_ENABLE.bits()
                        | EferFlags::LONG_MODE_ACTIVE.bits()
                        | EferFlags::NO_EXECUTE_ENABLE.bits()
                        | EferFlags::SECURE_VIRTUAL_MACHINE_ENABLE.bits(),
                ),
                tweak_bitmap,
            );
        }
        vmsa.set_virtual_tom(!0, tweak_bitmap);
        vmsa.set_cr4(
            Cr4Flags::from_bits_retain(
                Cr4Flags::PHYSICAL_ADDRESS_EXTENSION.bits()
                    | Cr4Flags::PAGE_GLOBAL.bits()
                    | Cr4Flags::OSFXSR.bits()
                    | Cr4Flags::OSXMMEXCPT_ENABLE.bits()
                    | Cr4Flags::FSGSBASE.bits()
                    | Cr4Flags::PCID.bits()
                    | Cr4Flags::OSXSAVE.bits()
                    | Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION.bits()
                    | Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION.bits(),
            ),
            tweak_bitmap,
        );
        vmsa.set_cr3(0x100_0000_0000, tweak_bitmap);
        vmsa.set_cr0(
            Cr0Flags::from_bits_retain(
                Cr0Flags::PROTECTED_MODE_ENABLE.bits()
                    | Cr0Flags::MONITOR_COPROCESSOR.bits()
                    | Cr0Flags::EXTENSION_TYPE.bits()
                    | Cr0Flags::WRITE_PROTECT.bits()
                    | Cr0Flags::PAGING.bits(),
            ),
            tweak_bitmap,
        );
        vmsa.set_xcr0(
            XCr0Flags::from_bits_retain(
                XCr0Flags::X87.bits() | XCr0Flags::SSE.bits() | XCr0Flags::AVX.bits(),
            ),
            tweak_bitmap,
        );
        vmsa.set_cs(Segment::CODE64, tweak_bitmap);
        vmsa.set_rip(0xffff_8000_0000_0000, tweak_bitmap);
        vmsa.set_rsp(0xffff_8000_0400_3ff8, tweak_bitmap);

        // Enable SecureTSC.
        let sev_features = SEV_FEATURES;
        unsafe {
            vmsa.set_sev_features(
                SevFeatures::from_bits_retain(sev_features.bits() | SevFeatures::SECURE_TSC.bits()),
                tweak_bitmap,
            );
        }
        // Set TSC scaling to 1.
        vmsa.set_guest_tsc_scale(0x01_00000000, tweak_bitmap);
        // Disable TSC offset.
        vmsa.set_guest_tsc_offset(0, tweak_bitmap);

        // If the supervisor is not hardened, setup the vCPU so that the kernel
        // can be profiled.
        if !cfg!(feature = "harden") {
            // Allow the kernel to share data with the host for debugging/profiling.
            vmsa.set_virtual_tom(0x80000000000, tweak_bitmap);

            // Allow the kernel to query it's processor id through TSC_AUX.
            // Note that this doesn't do anything on EPYC Milan.
            vmsa.set_tsc_aux(tsc_aux, tweak_bitmap);
        }

        // Note: If we ever want to provide confidentiality for the workloads,
        // we'll have to properly initialize the VMSA register protection
        // nonce with a random value (we obviously can't do that at compile
        // time).

        vmsas[i as usize] = SyncUnsafeCell::new(vmsa);
        i += 1;
    }

    vmsas
};

/// Allocate a VMSA out of a pool.
fn allocate_vmsa() -> *mut Vmsa {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    let idx = COUNTER.fetch_add(1, Ordering::SeqCst);
    let ptr = SLOTS[idx].get();

    // There's an erratum which says that 2MiB aligned VMSAs can cause spurious
    // #NPFs under certain conditions. For that reason the Linux kernel rejects
    // all AP Creation events with a 2MiB aligned VMSA.
    assert!(!ptr.is_aligned_to(0x200000));

    ptr
}

/// A wrapper around a reference to a VMSA.
pub struct InitializedVmsa {
    /// A reference to an VMSA allocated out of a pool.
    vmsa: *mut Vmsa,
}

impl InitializedVmsa {
    pub fn new() -> Self {
        Self {
            vmsa: allocate_vmsa(),
        }
    }

    pub fn phys_addr(&self) -> PhysFrame {
        let idx = unsafe { self.vmsa.offset_from(SLOTS.as_ptr().cast()) };
        let idx = u64::try_from(idx).unwrap();
        let base = VMSAS.start_address() + 0x1000;
        let vmsa_addr = base + idx * 0x1000;
        PhysFrame::from_start_address(vmsa_addr).unwrap()
    }

    /// Allow the VMSA to run.
    ///
    /// # Safety
    ///
    /// If `runnable` is true, the caller has to ensure that there are no
    /// references to the VMSA and that the VMSA is allowed to run (e.g. all
    /// reflected #VCs are handled).
    pub unsafe fn set_runnable(&mut self, runnable: bool) {
        let addr = VirtAddr::from_ptr(self.vmsa);
        let page = Page::<Size4KiB>::from_start_address(addr).unwrap();

        unsafe {
            rmpadjust(page, 1, VmplPermissions::empty(), runnable).unwrap();
        }
    }
}
