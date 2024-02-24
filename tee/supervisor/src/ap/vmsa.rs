use core::{
    arch::x86_64::_rdrand64_step,
    cell::{SyncUnsafeCell, UnsafeCell},
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicUsize, Ordering},
};

use bit_field::BitField;
use constants::MAX_APS_COUNT;
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
    PhysAddr, VirtAddr,
};

use crate::{cpuid::c_bit_location, pagetable::ref_to_pa, rmp::rmpadjust};

use super::SEV_FEATURES;

/// Allocate a VMSA out of a pool and initialize it.
fn allocate_vmsa(vmsa: Vmsa) -> &'static UnsafeCell<Vmsa> {
    const fn unaligned_slots() -> usize {
        let potential_unaligned = 1;
        (MAX_APS_COUNT as usize) + (potential_unaligned as usize)
    }

    static SLOTS: [SyncUnsafeCell<MaybeUninit<Vmsa>>; unaligned_slots()] =
        [const { SyncUnsafeCell::new(MaybeUninit::uninit()) }; unaligned_slots()];
    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    let vmsa_slot = loop {
        let idx = COUNTER.fetch_add(1, Ordering::SeqCst);
        let ptr = SLOTS[idx].get();

        // Skips slots that are 2MiB aligned.
        //
        // There's an erratum which says that 2MiB aligned VMSAs can cause
        // spurious #NPFs under certain conditions. For that reason the Linux
        // kernel rejects all AP Creation events with a 2MiB aligned VMSA.
        if ptr.is_aligned_to(0x200000) {
            continue;
        }

        break unsafe { &mut *ptr };
    };

    let ptr = vmsa_slot.write(vmsa);
    let ptr = ptr as *const _ as *const UnsafeCell<Vmsa>;
    unsafe { &*ptr }
}

/// A wrapper around a reference to a VMSA.
pub struct InitializedVmsa {
    /// A reference to an VMSA allocated out of a pool.
    vmsa: &'static UnsafeCell<Vmsa>,
}

impl InitializedVmsa {
    pub fn new(tweak_bitmap: &VmsaTweakBitmap, tsc_aux: u32) -> Self {
        let mut vmsa = Vmsa::default();
        vmsa.set_vpml(1, tweak_bitmap);
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

        // If the supervisor is not hardened, setup the vCPU so that the kernel
        // can be profiled.
        if !cfg!(feature = "harden") {
            // Allow the kernel to share profiler data with the host.
            vmsa.set_virtual_tom(0x80000000000, tweak_bitmap);

            // Allow the kernel to query it's processor id through TSC_AUX.
            // Note that this doesn't do anything on EPYC Milan.
            vmsa.set_tsc_aux(tsc_aux, tweak_bitmap);

            // Enable SecureTSC.
            let sev_features = vmsa.sev_features(tweak_bitmap);
            vmsa.set_sev_features(sev_features | SevFeatures::SECURE_TSC, tweak_bitmap);
            // Set TSC scaling to 1.
            vmsa.set_guest_tsc_scale(0x01_00000000, tweak_bitmap);
            // Disable TSC offset.
            vmsa.set_guest_tsc_offset(0, tweak_bitmap);
        }

        // Randomize that starting nonce.
        vmsa.update_nonce(random(), tweak_bitmap);

        Self {
            vmsa: allocate_vmsa(vmsa),
        }
    }

    pub fn phys_addr(&self) -> PhysFrame {
        let vmsa_addr = ref_to_pa(self.vmsa).unwrap();
        let mut vmsa_addr = vmsa_addr.as_u64();
        vmsa_addr.set_bit(c_bit_location(), false);
        let vmsa_addr = PhysAddr::new(vmsa_addr);
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

    /// Sets the VMSA as unrunnable and returns a wrapper around mutable
    /// reference to it. This reference can be used to inspect and modify the
    /// VMSA.
    /// The VMSA will automatically be marked as runnable once the wrapper is
    /// dropped.
    pub fn modify(&mut self) -> VmsaModifyGuard {
        unsafe {
            self.set_runnable(false);
        }
        VmsaModifyGuard { vmsa: self }
    }
}

pub struct VmsaModifyGuard<'a> {
    vmsa: &'a mut InitializedVmsa,
}

impl Deref for VmsaModifyGuard<'_> {
    type Target = Vmsa;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.vmsa.vmsa.get() }
    }
}

impl DerefMut for VmsaModifyGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.vmsa.vmsa.get() }
    }
}

impl Drop for VmsaModifyGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            self.vmsa.set_runnable(true);
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
