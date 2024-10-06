use core::{
    arch::x86_64::_rdrand64_step,
    cell::SyncUnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicUsize, Ordering},
};

use constants::{physical_address::supervisor::VMSAS, MAX_APS_COUNT};
use snp_types::{
    vmsa::{SevFeatures, Vmsa, VmsaTweakBitmap},
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
static SLOTS: [SyncUnsafeCell<MaybeUninit<Vmsa>>; MAX_APS_COUNT as usize] =
    [const { SyncUnsafeCell::new(MaybeUninit::uninit()) }; MAX_APS_COUNT as usize];

/// Allocate a VMSA out of a pool and initialize it.
fn allocate_vmsa(vmsa: Vmsa) -> *mut Vmsa {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    let idx = COUNTER.fetch_add(1, Ordering::SeqCst);
    let ptr = SLOTS[idx].get();

    // There's an erratum which says that 2MiB aligned VMSAs can cause spurious
    // #NPFs under certain conditions. For that reason the Linux kernel rejects
    // all AP Creation events with a 2MiB aligned VMSA.
    assert!(!ptr.is_aligned_to(0x200000));

    let vmsa_slot = unsafe { &mut *ptr };

    vmsa_slot.write(vmsa)
}

/// A wrapper around a reference to a VMSA.
pub struct InitializedVmsa {
    /// A reference to an VMSA allocated out of a pool.
    vmsa: *mut Vmsa,
}

impl InitializedVmsa {
    pub fn new(tweak_bitmap: &VmsaTweakBitmap, tsc_aux: u32) -> Self {
        let mut vmsa = Vmsa::default();
        vmsa.set_vmpl(1, tweak_bitmap);
        vmsa.set_virtual_tom(!0, tweak_bitmap);
        vmsa.set_efer(
            EferFlags::SYSTEM_CALL_EXTENSIONS.bits()
                | EferFlags::LONG_MODE_ENABLE.bits()
                | EferFlags::LONG_MODE_ACTIVE.bits()
                | EferFlags::NO_EXECUTE_ENABLE.bits()
                | EferFlags::SECURE_VIRTUAL_MACHINE_ENABLE.bits(),
            tweak_bitmap,
        );
        vmsa.set_cr4(
            Cr4Flags::PHYSICAL_ADDRESS_EXTENSION.bits()
                | Cr4Flags::PAGE_GLOBAL.bits()
                | Cr4Flags::OSFXSR.bits()
                | Cr4Flags::OSXMMEXCPT_ENABLE.bits()
                | Cr4Flags::FSGSBASE.bits()
                | Cr4Flags::PCID.bits()
                | Cr4Flags::OSXSAVE.bits()
                | Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION.bits()
                | Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION.bits(),
            tweak_bitmap,
        );
        vmsa.set_cr3(0x100_0000_0000, tweak_bitmap);
        vmsa.set_cr0(
            Cr0Flags::PROTECTED_MODE_ENABLE.bits()
                | Cr0Flags::MONITOR_COPROCESSOR.bits()
                | Cr0Flags::EXTENSION_TYPE.bits()
                | Cr0Flags::WRITE_PROTECT.bits()
                | Cr0Flags::PAGING.bits(),
            tweak_bitmap,
        );
        vmsa.set_xcr0(
            XCr0Flags::X87.bits() | XCr0Flags::SSE.bits() | XCr0Flags::AVX.bits(),
            tweak_bitmap,
        );
        vmsa.set_rip(0xffff_8000_0000_0000, tweak_bitmap);
        vmsa.set_rsp(0xffff_8000_0400_3ff8, tweak_bitmap);
        vmsa.set_sev_features(SEV_FEATURES, tweak_bitmap);

        // Enable SecureTSC.
        let sev_features = vmsa.sev_features(tweak_bitmap);
        vmsa.set_sev_features(sev_features | SevFeatures::SECURE_TSC, tweak_bitmap);
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

        // Randomize that starting nonce.
        vmsa.update_nonce(random(), tweak_bitmap);

        Self {
            vmsa: allocate_vmsa(vmsa),
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

/// Generate a random number.
fn random() -> u64 {
    const ATTEMPTS: usize = 100;

    // rdrand can fail. Limit the number of attempts.
    for _ in 0..ATTEMPTS {
        let mut new_nonce = 0;
        let res = unsafe { _rdrand64_step(&mut new_nonce) };
        if res == 1 {
            return new_nonce;
        }
    }

    panic!("failed to generate random number")
}
