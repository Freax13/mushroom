use core::{
    cell::{SyncUnsafeCell, UnsafeCell},
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicUsize, Ordering},
};

use bit_field::BitField;
use constants::MAX_APS_COUNT;
use snp_types::{
    vmsa::{Segment, Vmsa},
    Reserved, Uninteresting, VmplPermissions,
};
use x86_64::{
    registers::{
        control::{Cr0Flags, Cr4Flags},
        model_specific::EferFlags,
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
    pub fn new() -> Self {
        let data_segment = Segment {
            selector: 0x10,
            attrib: 0xc93,
            limit: 0xffffffff,
            base: 0,
        };
        let code_segment = Segment {
            selector: 0x08,
            attrib: 0x29b,
            limit: 0xffffffff,
            base: 0,
        };
        let fs_gs = Segment {
            selector: 0,
            attrib: 0x92,
            limit: 0xffff,
            base: 0,
        };
        let gdtr = Segment {
            selector: 0,
            attrib: 0,
            // FIXME: Fill in correct values.
            limit: 0x27,
            // FIXME: Fill in correct values.
            base: 0xfffff120,
        };
        let ldtr = Segment {
            selector: 0,
            attrib: 0x82,
            limit: 0xffff,
            base: 0,
        };
        let idtr = Segment {
            selector: 0,
            attrib: 0,
            limit: 0xfff,
            base: 0xffff800002000030,
        };
        let tr = Segment {
            selector: 0,
            attrib: 0x83,
            limit: 0xffff,
            base: 0,
        };

        let vmsa = Vmsa {
            es: data_segment,
            cs: code_segment,
            ss: data_segment,
            ds: data_segment,
            fs: fs_gs,
            gs: fs_gs,
            gdtr,
            ldtr,
            idtr,
            tr,
            pl0_ssp: 0,
            pl1_ssp: 0,
            pl2_ssp: 0,
            pl3_ssp: 0,
            ucet: 0,
            _reserved1: Reserved::ZERO,
            vpml: 1,
            cpl: 0,
            _reserved2: Reserved::ZERO,
            efer: EferFlags::SYSTEM_CALL_EXTENSIONS.bits()
                | EferFlags::LONG_MODE_ENABLE.bits()
                | EferFlags::LONG_MODE_ACTIVE.bits()
                | EferFlags::NO_EXECUTE_ENABLE.bits()
                | EferFlags::SECURE_VIRTUAL_MACHINE_ENABLE.bits(),
            _reserved3: Reserved::ZERO,
            xss: 0,
            cr4: Cr4Flags::PHYSICAL_ADDRESS_EXTENSION.bits()
                | Cr4Flags::PAGE_GLOBAL.bits()
                | Cr4Flags::FSGSBASE.bits()
                | Cr4Flags::PCID.bits()
                | Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION.bits()
                | Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION.bits(),
            // FIXME: Fill in correct values.
            cr3: 0x100_0000_0000,
            cr0: Cr0Flags::PROTECTED_MODE_ENABLE.bits()
                | Cr0Flags::EXTENSION_TYPE.bits()
                | Cr0Flags::WRITE_PROTECT.bits()
                | Cr0Flags::PAGING.bits(),
            dr7: 0x400,
            dr6: 0xffff0ff0,
            // FIXME: Fill in correct values.
            rflags: 2,
            // FIXME: Fill in correct values.
            rip: 0xffff_8000_0000_0000,
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr0_addr_mask: 0,
            dr1_addr_mask: 0,
            dr2_addr_mask: 0,
            dr3_addr_mask: 0,
            _reserved4: Reserved::ZERO,
            // FIXME: Fill in correct values.
            rsp: 0xffff800004003ff8,
            s_cet: 0,
            ssp: 0,
            isst_addr: 0,
            rax: 0,
            // FIXME: Fill in correct values.
            star: 0,
            // FIXME: Fill in correct values.
            lstar: 0,
            // FIXME: Fill in correct values.
            cstar: 0,
            // FIXME: Fill in correct values.
            sfmask: 0,
            kernel_gs_base: 0,
            // FIXME: Fill in correct values.
            sysenter_cs: 0,
            // FIXME: Fill in correct values.
            sysenter_esp: 0,
            // FIXME: Fill in correct values.
            sysenter_eip: 0,
            cr2: 0,
            _reserved5: Reserved::ZERO,
            // FIXME: Does this value make sense?
            g_pat: 0x7040600070406,
            dbgctl: 0,
            br_from: 0,
            br_to: 0,
            lsat_excp_from: 0,
            last_excp_to: 0,
            _reserved6: Reserved::ZERO,
            _reserved7: Reserved::ZERO,
            pkru: 0,
            tsc_aux: 0,
            guest_tsc_scale: 0,
            guest_tsc_offset: 0,
            reg_prot_nonce: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            _reserved8: Reserved::ZERO,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            _reserved9: Reserved::ZERO,
            guest_exit_info1: 0,
            guest_exit_info2: 0,
            guest_exit_int_info: 0,
            guest_nrip: 0,
            sev_features: SEV_FEATURES,
            vintr_ctrl: 0,
            guest_exit_code: 0,
            virtual_tom: !0,
            tlb_id: 0,
            pcpu_id: 0,
            event_inj: 0,
            // FIXME: Do we currently handle cpuid lookup correct? I think we're assuming 0.
            xcr0: 1,
            _reserved10: Reserved::ZERO,
            x87_dp: 0,
            mxcsr: 0,
            x87_ftw: 0,
            x87_fsw: 0,
            x87_fcw: 0x40,
            x87_fop: 0,
            x87_ds: 0,
            x87_cs: 0,
            x87_rip: 0,
            fpreg_x87: Uninteresting::new([0; 80]),
            fpreg_xmm: Uninteresting::new([0; 256]),
            fpreg_ymm: Uninteresting::new([0; 256]),
            lbr_stack_state: Uninteresting::new([0; 256]),
            lbr_select: 0,
            ibs_fetch_ctl: 0,
            ibs_fetch_linaddr: 0,
            ibs_op_ctl: 0,
            ibs_op_rip: 0,
            ibs_op_data: 0,
            ibs_op_data2: 0,
            ibs_op_data3: 0,
            ibs_dc_linaddr: 0,
            bp_ibstgt_rip: 0,
            ic_ibs_extd_ctl: 0,
            _padding: Reserved::ZERO,
        };

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
