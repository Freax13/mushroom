use core::{
    cell::SyncUnsafeCell,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU64, Ordering},
};

use constants::{MAX_APS_COUNT, physical_address::supervisor::snp::VMSAS};
use snp_types::{
    VmplPermissions,
    intercept::VMEXIT_INVALID,
    vmsa::{Segment, SevFeatures, Vmsa, VmsaTweakBitmap},
};
use x86_64::{
    VirtAddr,
    registers::{
        control::{Cr0Flags, Cr4Flags},
        model_specific::EferFlags,
        xcontrol::XCr0Flags,
    },
    structures::paging::{Page, PhysFrame, Size4KiB},
};

use crate::{ghcb::vmsa_tweak_bitmap, per_cpu::PerCpu, rmp::rmpadjust};

use super::SEV_FEATURES;

#[unsafe(link_section = ".vmsas")]
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
        vmsa.set_guest_exit_code(VMEXIT_INVALID, tweak_bitmap);

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

/// A wrapper around a reference to a VMSA.
pub struct Vmpl1Vmsa {
    /// A reference to an VMSA allocated out of a pool.
    vmsa: *mut Vmsa,
}

impl Vmpl1Vmsa {
    /// # Safety
    ///
    /// This function must only be called once per vCPU.
    pub unsafe fn get() -> Self {
        let vmsa = SLOTS[PerCpu::current_vcpu_index()].get();

        // There's an erratum which says that 2MiB aligned VMSAs can cause spurious
        // #NPFs under certain conditions. For that reason the Linux kernel rejects
        // all AP Creation events with a 2MiB aligned VMSA.
        assert!(!vmsa.is_aligned_to(0x200000));

        Self { vmsa }
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

    #[inline(always)]
    pub fn modify(&mut self) -> VmsaModifyGuard {
        // The following code would be much more complicated if the EFER MSR
        // was obfuscated with the register protection nonce. Make sure that's
        // not the case.
        assert!(!vmsa_tweak_bitmap().is_tweaked(0xd0));

        // Clear the SVME bit in the EFER MSR. This prevents the VMSA from
        // being executed.
        let prev = self.efer().fetch_and(
            !EferFlags::SECURE_VIRTUAL_MACHINE_ENABLE.bits(),
            Ordering::SeqCst,
        );

        // We can't rely on `VmsaModifyGuard`'s `drop` implementation to be
        // executed, so we need to make sure that the SVME bit isn't already
        // unset.
        assert_ne!(prev & EferFlags::SECURE_VIRTUAL_MACHINE_ENABLE.bits(), 0);

        VmsaModifyGuard { vmsa: self }
    }

    /// Return a reference to the EFER field in the VMSA.
    #[inline(always)]
    fn efer(&self) -> &AtomicU64 {
        unsafe { &*self.vmsa.byte_add(0xd0).cast::<AtomicU64>() }
    }
}

pub struct VmsaModifyGuard<'a> {
    vmsa: &'a mut Vmpl1Vmsa,
}

impl Deref for VmsaModifyGuard<'_> {
    type Target = Vmsa;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.vmsa.vmsa }
    }
}

impl DerefMut for VmsaModifyGuard<'_> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.vmsa.vmsa }
    }
}

impl Drop for VmsaModifyGuard<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        // Set the the SVME bit to make the VMSA usable again.
        self.vmsa.efer().fetch_or(
            EferFlags::SECURE_VIRTUAL_MACHINE_ENABLE.bits(),
            Ordering::SeqCst,
        );
    }
}
