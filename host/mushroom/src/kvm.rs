#![allow(dead_code)]

use std::{
    array::{self, from_fn},
    ffi::c_void,
    fmt,
    fs::OpenOptions,
    mem::{size_of, size_of_val},
    num::{NonZeroU32, NonZeroUsize},
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    ptr::NonNull,
};

use anyhow::{Context, Result, ensure};
use bitflags::bitflags;
use bytemuck::{Pod, Zeroable, bytes_of, pod_read_unaligned};
use nix::{
    errno::Errno,
    ioctl_none, ioctl_read, ioctl_readwrite, ioctl_write_int_bad, ioctl_write_ptr,
    request_code_none,
    sys::mman::{MapFlags, ProtFlags},
};
#[cfg(feature = "snp")]
use snp_types::{PageType, VmplPermissions, guest_policy::GuestPolicy, vmsa::SevFeatures};
use tracing::debug;
use volatile::VolatilePtr;

use crate::{kvm::hidden::KvmCpuid2, slot::Slot};

const KVMIO: u8 = 0xAE;
pub const KVM_HC_MAP_GPA_RANGE: u64 = 12;
const MAX_ENTRIES: usize = 256;

pub struct KvmHandle {
    fd: OwnedFd,
}

impl KvmHandle {
    pub fn new() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .open("/dev/kvm")
            .context("failed to open /dev/kvm")?;
        let fd = OwnedFd::from(file);

        ioctl_write_int_bad!(kvm_get_api_version, request_code_none!(KVMIO, 0x00));
        let res = unsafe { kvm_get_api_version(fd.as_raw_fd(), 0) };
        let version = res.context("failed to execute get_api_version")?;
        debug!(version, "determined kvm version");
        ensure!(version >= 12, "unsupported kvm api version ({version})");

        ioctl_write_int_bad!(kvm_get_vcpu_mmap_size, request_code_none!(KVMIO, 0x04));
        let res = unsafe { kvm_get_vcpu_mmap_size(fd.as_raw_fd(), 0) };
        let vcpu_mmap_size = res.context("failed to query vcpu mmap size")?;
        ensure!(
            usize::try_from(vcpu_mmap_size).unwrap() >= size_of::<KvmRun>(),
            "unexpected vcpu mmap size: got {vcpu_mmap_size}, expected {}",
            size_of::<KvmRun>()
        );

        Ok(Self { fd })
    }

    #[cfg(feature = "insecure")]
    pub(crate) fn create_vm(&self) -> Result<VmHandle> {
        debug!("creating vm");

        ioctl_write_int_bad!(kvm_create_vm, request_code_none!(KVMIO, 0x01));
        let res = unsafe { kvm_create_vm(self.fd.as_raw_fd(), 0) };
        let raw_fd = res.context("failed to create vm")?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        Ok(VmHandle { fd })
    }

    #[cfg(feature = "snp")]
    pub(crate) fn create_snp_vm(&self) -> Result<VmHandle> {
        debug!("creating vm");

        const KVM_X86_SNP_VM: i32 = 4;
        ioctl_write_int_bad!(kvm_create_vm, request_code_none!(KVMIO, 0x01));
        let res = unsafe { kvm_create_vm(self.fd.as_raw_fd(), KVM_X86_SNP_VM) };
        let raw_fd = res.context("failed to create vm")?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        Ok(VmHandle { fd })
    }

    #[cfg(feature = "tdx")]
    pub(crate) fn create_tdx_vm(&self) -> Result<VmHandle> {
        debug!("creating vm");

        const KVM_X86_TDX_VM: i32 = 2;
        ioctl_write_int_bad!(kvm_create_vm, request_code_none!(KVMIO, 0x01));
        let res = unsafe { kvm_create_vm(self.fd.as_raw_fd(), KVM_X86_TDX_VM) };
        let raw_fd = res.context("failed to create vm")?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        Ok(VmHandle { fd })
    }

    pub(crate) fn get_supported_cpuid(&self) -> Result<Box<[KvmCpuidEntry2]>> {
        let mut buffer = KvmCpuid2::<MAX_ENTRIES> {
            nent: MAX_ENTRIES as u32,
            _padding: 0,
            entries: [KvmCpuidEntry2 {
                function: 0,
                index: 0,
                flags: 0,
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
                padding: [0; 3],
            }; MAX_ENTRIES],
        };

        ioctl_readwrite!(kvm_get_supported_cpuid, KVMIO, 0x05, KvmCpuid2<0>);
        let res = unsafe {
            kvm_get_supported_cpuid(
                self.fd.as_raw_fd(),
                &mut buffer as *mut KvmCpuid2<MAX_ENTRIES> as *mut KvmCpuid2<0>,
            )
        };
        res.context("failed to query supported cpuid features")?;

        Ok(Box::from(buffer.entries[..buffer.nent as usize].to_vec()))
    }

    pub(crate) fn get_supported_hv_cpuid(&self) -> Result<Box<[KvmCpuidEntry2]>> {
        let mut buffer = KvmCpuid2::<MAX_ENTRIES> {
            nent: MAX_ENTRIES as u32,
            _padding: 0,
            entries: [KvmCpuidEntry2 {
                function: 0,
                index: 0,
                flags: 0,
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
                padding: [0; 3],
            }; MAX_ENTRIES],
        };

        ioctl_readwrite!(kvm_get_supported_cpuid, KVMIO, 0xc1, KvmCpuid2<0>);
        let res = unsafe {
            kvm_get_supported_cpuid(
                self.fd.as_raw_fd(),
                &mut buffer as *mut KvmCpuid2<MAX_ENTRIES> as *mut KvmCpuid2<0>,
            )
        };
        res.context("failed to query supported hv cpuid features")?;

        Ok(Box::from(buffer.entries[..buffer.nent as usize].to_vec()))
    }

    pub(crate) fn check_extension(&self, cap: KvmCap) -> Result<Option<NonZeroU32>> {
        ioctl_write_int_bad!(kvm_check_extension, request_code_none!(KVMIO, 0x03));

        let res = unsafe { kvm_check_extension(self.fd.as_raw_fd(), cap.0 as i32) };
        let val = res.context("failed to check extension")?;

        Ok(NonZeroU32::new(val as u32))
    }
}

pub struct VmHandle {
    fd: OwnedFd,
}

impl VmHandle {
    pub fn create_vcpu(&self, id: i32) -> Result<VcpuHandle> {
        debug!(id, "creating vcpu");

        ioctl_write_int_bad!(kvm_create_vcpu, request_code_none!(KVMIO, 0x41));
        let res = unsafe { kvm_create_vcpu(self.fd.as_raw_fd(), id) };
        let raw_fd = res.context("failed to create cpu")?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        Ok(VcpuHandle { fd })
    }

    pub fn enable_capability(&self, cap: KvmCap, arg0: u64) -> Result<()> {
        debug!("enabling capability");

        let enable_cap = KvmEnableCap {
            cap,
            flags: 0,
            args: [arg0, 0, 0, 0],
            _pad: [0; 64],
        };
        ioctl_write_ptr!(kvm_enable_cap, KVMIO, 0xa3, KvmEnableCap);
        let res = unsafe { kvm_enable_cap(self.fd.as_raw_fd(), &enable_cap) };
        res.context("failed to enable capability")?;
        Ok(())
    }

    pub unsafe fn set_user_memory_region(
        &self,
        slot: u16,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
    ) -> Result<()> {
        debug!("mapping memory");

        let region = KvmUserspaceMemoryRegion {
            slot: u32::from(slot),
            flags: KvmUserspaceMemoryRegionFlags::empty(),
            guest_phys_addr,
            memory_size,
            userspace_addr,
        };

        ioctl_write_ptr!(
            kvm_set_user_memory_region,
            KVMIO,
            0x46,
            KvmUserspaceMemoryRegion
        );
        let res = unsafe { kvm_set_user_memory_region(self.fd.as_raw_fd(), &region) };
        res.context("failed to map memory")?;
        Ok(())
    }

    pub unsafe fn map_private_memory(
        &self,
        slot: u16,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        restricted_fd: Option<BorrowedFd>,
        restricted_offset: u64,
    ) -> Result<()> {
        if restricted_fd.is_none() {
            return self.set_user_memory_region(slot, guest_phys_addr, memory_size, userspace_addr);
        }

        debug!("mapping private memory");

        let region = KvmUserspaceMemoryRegion2 {
            region: KvmUserspaceMemoryRegion {
                slot: u32::from(slot),
                flags: KvmUserspaceMemoryRegionFlags::KVM_MEM_PRIVATE,
                guest_phys_addr,
                memory_size,
                userspace_addr,
            },
            restricted_offset,
            restricted_fd,
            _pad1: 0,
            _pad2: [0; 14],
        };

        ioctl_write_ptr!(
            kvm_set_user_memory_region2,
            KVMIO,
            0x49,
            KvmUserspaceMemoryRegion2
        );
        let res = unsafe { kvm_set_user_memory_region2(self.fd.as_raw_fd(), &region) };
        res.context("failed to map private memory")?;

        Ok(())
    }

    pub unsafe fn map_encrypted_memory(&self, id: u16, slot: &Slot) -> Result<()> {
        debug!(id, guest_phys_addr = %format_args!("{:x?}", slot.gpa()), "mapping private memory");

        let shared_mapping = slot.shared_mapping();
        let restricted_fd = slot.restricted_fd();

        unsafe {
            self.map_private_memory(
                id,
                slot.gpa().start_address().as_u64(),
                u64::try_from(shared_mapping.len().get())?,
                u64::try_from(shared_mapping.as_ptr().as_ptr() as usize)?,
                restricted_fd,
                0,
            )?;
        }

        Ok(())
    }

    /// FIXME: This should take slot by owner.
    pub unsafe fn unmap_encrypted_memory(&self, id: u16, slot: &Slot) -> Result<()> {
        debug!(id, guest_phys_addr = %format_args!("{:x?}", slot.gpa()), "mapping private memory");

        unsafe {
            self.map_private_memory(id, slot.gpa().start_address().as_u64(), 0, 0, None, 0)?;
        }

        Ok(())
    }

    pub fn create_irqchip(&self) -> Result<()> {
        debug!("creating irqchip");

        ioctl_none!(kvm_create_irqchip, KVMIO, 0x60);
        let res = unsafe { kvm_create_irqchip(self.fd.as_raw_fd()) };
        res.context("failed to create irqchip")?;

        Ok(())
    }

    #[cfg(feature = "snp")]
    unsafe fn memory_encrypt_op<'a>(
        &self,
        payload: KvmSevCmdPayload<'a>,
        sev_handle: Option<&SevHandle>,
    ) -> Result<KvmSevCmdPayload<'a>> {
        debug!("executing memory encryption operation");

        let mut cmd = KvmSevCmd {
            payload,
            error: 0,
            sev_fd: sev_handle.map(|sev_handle| sev_handle.fd.as_fd()),
        };

        ioctl_readwrite!(kvm_memory_encrypt_op, KVMIO, 0xba, u64);
        let res =
            kvm_memory_encrypt_op(self.fd.as_raw_fd(), &mut cmd as *mut KvmSevCmd as *mut u64);
        ensure!(cmd.error == 0);
        res.context("failed to execute memory encryption operation")?;

        Ok(cmd.payload)
    }

    #[cfg(feature = "snp")]
    pub fn sev_snp_init(&self) -> Result<()> {
        let mut data = KvmSevInit {
            vmsa_features: SevFeatures::RESTRICTED_INJECTION | SevFeatures::VMSA_REG_PROT,
            flags: 0,
            ghcb_version: 2,
            _pad1: 0,
            _pad2: [0; 8],
        };
        let payload = KvmSevCmdPayload::KvmSevInit2 { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, None) };
        res.context("failed to initialize sev snp")?;
        Ok(())
    }

    #[cfg(feature = "snp")]
    pub fn sev_snp_launch_start(&self, policy: GuestPolicy, sev_handle: &SevHandle) -> Result<()> {
        debug!("starting snp launch");
        let mut data = KvmSevSnpLaunchStart {
            policy,
            gosvw: [0; 16],
            flags: 0,
            pad0: [0; 6],
            pad1: [0; 4],
        };
        let payload = KvmSevCmdPayload::KvmSevSnpLaunchStart { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, Some(sev_handle)) };
        res.context("failed to start sev snp launch")?;
        Ok(())
    }

    #[cfg(feature = "snp")]
    #[allow(clippy::too_many_arguments)]
    pub fn sev_snp_launch_update(
        &self,
        start_addr: u64,
        uaddr: u64,
        len: u64,
        page_type: PageType,
        vcpu_id: u32,
        vmpl1_perms: VmplPermissions,
        // FIXME: figure out if we need a sev handle for this operation
        sev_handle: &SevHandle,
    ) -> Result<()> {
        debug!("updating snp launch");

        ensure!(
            start_addr & 0xfff == 0,
            "start address is not properly aligned"
        );
        let gfn_start = start_addr >> 12;

        let mut data = KvmSevSnpLaunchUpdateVmpls {
            base: KvmSevSnpLaunchUpdate {
                gfn_start,
                uaddr,
                len,
                page_type: page_type as u8,
                pad0: 0,
                flags: 0,
                vcpu_id,
                pad2: [0; 4],
            },
            vmpl3_perms: VmplPermissions::empty(),
            vmpl2_perms: VmplPermissions::empty(),
            vmpl1_perms,
        };
        while data.base.len != 0 {
            let payload = KvmSevCmdPayload::KvmSevSnpLaunchUpdateVmpls { data: &mut data };
            let res = unsafe { self.memory_encrypt_op(payload, Some(sev_handle)) };
            res.context("failed to update sev snp launch")?;
        }
        Ok(())
    }

    #[cfg(feature = "snp")]
    pub fn sev_snp_launch_finish(
        &self,
        // FIXME: figure out if we need a sev handle for this operation
        sev_handle: &SevHandle,
        host_data: [u8; 32],
    ) -> Result<()> {
        debug!("finishing snp launch");

        let mut data = KvmSevSnpLaunchFinish {
            id_block_uaddr: 0,
            id_auth_uaddr: 0,
            id_block_en: 0,
            auth_key_en: 0,
            host_data,
            vcek_disabled: 0,
            pad0: [0; 3],
            flags: 0,
            pad1: [0; 4],
        };
        let payload = KvmSevCmdPayload::KvmSevSnpLaunchFinish { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, Some(sev_handle)) };
        res.context("failed to finish sev snp launch")?;
        Ok(())
    }

    #[cfg(feature = "tdx")]
    unsafe fn memory_encrypt_op_tdx<'a>(
        &self,
        payload: KvmTdxCmdPayload<'a>,
    ) -> Result<KvmTdxCmdPayload<'a>> {
        debug!("executing memory encryption operation");

        let mut cmd = KvmTdxCmd { payload, error: 0 };

        ioctl_readwrite!(kvm_memory_encrypt_op, KVMIO, 0xba, u64);
        let res =
            kvm_memory_encrypt_op(self.fd.as_raw_fd(), &mut cmd as *mut KvmTdxCmd as *mut u64);

        ensure!(cmd.error == 0);
        res.context("failed to execute memory encryption operation")?;

        Ok(cmd.payload)
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_capabilities(&self) -> Result<KvmTdxCapabilities> {
        let mut tdx_capabilities = KvmTdxCapabilities {
            attrs_fixed0: 0,
            attrs_fixed1: 0,
            xfam_fixed0: 0,
            xfam_fixed1: 0,
            supported_gpaw: SupportedGpaw::empty(),
            padding: 0,
            reserved: [0; 251],
            nr_cpuid_configs: MAX_ENTRIES as u32,
            cpuid_configs: [KvmTdxCpuidConfig {
                leaf: 0,
                sub_leaf: 0,
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            }; MAX_ENTRIES],
        };
        unsafe {
            self.memory_encrypt_op_tdx(KvmTdxCmdPayload::KvmTdxCapabilities(
                KvmTdxCapabilitiesPayload {
                    flags: 0,
                    data: &mut tdx_capabilities,
                },
            ))?;
        }
        Ok(tdx_capabilities)
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_init_vm(&self, entries: &[KvmCpuidEntry2], mrconfigid: [u8; 48]) -> Result<()> {
        ensure!(entries.len() <= MAX_ENTRIES);
        let entries = array::from_fn(|i| {
            entries.get(i).copied().unwrap_or(KvmCpuidEntry2 {
                function: 0,
                index: 0,
                flags: 0,
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
                padding: [0; 3],
            })
        });
        let tdx_init_vm = KvmTdxInitVm {
            attributes: 0,
            mrconfigid,
            mrowner: [0; 48],
            mrownerconfig: [0; 48],
            max_num_l2_vms: 1,
            reserved: [0; 1003],
            cpuid: KvmCpuid2 {
                nent: u32::try_from(entries.len())?,
                _padding: 0,
                entries,
            },
        };
        unsafe {
            self.memory_encrypt_op_tdx(KvmTdxCmdPayload::KvmTdxInitVm(KvmTdxInitVmPayload {
                flags: 0,
                data: &tdx_init_vm,
            }))?;
        }
        Ok(())
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_extend_memory(&self, gpa: u64, len: u64) -> Result<()> {
        debug!(
            gpa = format_args!("{gpa:#x}"),
            len = format_args!("{len:#x}"),
            "extending tdx memory"
        );

        ensure!(gpa & 0xfff == 0, "start address is not properly aligned");
        let gfn = gpa >> 12;

        let mut data = KvmMemoryMapping {
            base_gfn: gfn,
            nr_pages: len,
            flags: 0,
            source: 0,
        };
        while data.nr_pages != 0 {
            let payload = KvmTdxCmdPayload::KvmTdxExtendMemory(KvmTdxExtendMemoryPayload {
                flags: 0,
                data: &mut data,
            });
            let res = unsafe { self.memory_encrypt_op_tdx(payload) };
            res.context("failed to extend tdx memory")?;
        }
        Ok(())
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_finalize_vm(&self) -> Result<()> {
        unsafe {
            self.memory_encrypt_op_tdx(KvmTdxCmdPayload::KvmTdxFinalizeVm(
                KvmTdxFinalizeVmPayload { flags: 0, data: 0 },
            ))?;
        }
        Ok(())
    }

    pub fn set_memory_attributes(
        &self,
        address: u64,
        size: u64,
        attributes: KvmMemoryAttributes,
    ) -> Result<()> {
        debug!(?address, ?size, ?attributes, "setting memory attributes");

        let data = KvmSetMemoryAttributes {
            address,
            size,
            attributes,
            flags: 0,
        };
        ioctl_write_ptr!(
            kvm_set_memory_attributes,
            KVMIO,
            0xd2,
            KvmSetMemoryAttributes
        );
        let res = unsafe { kvm_set_memory_attributes(self.fd.as_raw_fd(), &data) };
        res.context("failed to set memory attributes")?;
        Ok(())
    }

    pub fn create_guest_memfd(&self, size: u64, flags: KvmGuestMemFdFlags) -> Result<OwnedFd> {
        debug!(size, ?flags, "creating guest memfd");

        #[repr(C)]
        pub struct KvmCreateGuestMemfd {
            size: u64,
            flags: KvmGuestMemFdFlags,
            reserved: [u64; 6],
        }

        let mut data = KvmCreateGuestMemfd {
            size,
            flags,
            reserved: [0; 6],
        };

        ioctl_readwrite!(kvm_create_guest_memfd, KVMIO, 0xd4, KvmCreateGuestMemfd);

        let res = unsafe { kvm_create_guest_memfd(self.fd.as_raw_fd(), &mut data) };
        let num = res.context("failed to create guest memory")?;
        Ok(unsafe { OwnedFd::from_raw_fd(num) })
    }

    pub fn set_tsc_khz(&self, tsc_khz: u64) -> Result<()> {
        ioctl_write_int_bad!(kvm_set_tsc_khz, request_code_none!(KVMIO, 0xa2));
        let res = unsafe { kvm_set_tsc_khz(self.fd.as_raw_fd(), tsc_khz as i32) };
        res.context("failed to set tsc khz")?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C, align(4096))]
pub struct Page {
    pub bytes: [u8; 4096],
}

impl Page {
    pub const ZERO: Page = Page { bytes: [0; 4096] };
}

impl Default for Page {
    fn default() -> Self {
        Self::ZERO
    }
}

pub struct VcpuHandle {
    fd: OwnedFd,
}

impl VcpuHandle {
    pub fn get_regs(&self) -> Result<KvmRegs> {
        let mut regs = KvmRegs {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rsp: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
        };
        ioctl_read!(kvm_get_regs, KVMIO, 0x81, KvmRegs);
        let res = unsafe { kvm_get_regs(self.fd.as_raw_fd(), &mut regs) };
        res.context("failed to get registers")?;
        Ok(regs)
    }

    pub fn set_regs(&self, regs: KvmRegs) -> Result<()> {
        ioctl_write_ptr!(kvm_set_regs, KVMIO, 0x82, KvmRegs);
        let res = unsafe { kvm_set_regs(self.fd.as_raw_fd(), &regs) };
        res.context("failed to set registers")?;
        Ok(())
    }

    pub fn get_sregs(&self) -> Result<KvmSregs> {
        const ZERO_SEGMENT: KvmSegment = KvmSegment {
            base: 0,
            limit: 0,
            selector: 0,
            ty: 0,
            present: 0,
            dpl: 0,
            db: 0,
            s: 0,
            l: 0,
            g: 0,
            avl: 0,
            unusable: 0,
            _padding: 0,
        };
        const ZERO_DTABLE: KvmDtable = KvmDtable {
            base: 0,
            limit: 0,
            _padding: [0; 3],
        };
        let mut regs = KvmSregs {
            cs: ZERO_SEGMENT,
            ds: ZERO_SEGMENT,
            es: ZERO_SEGMENT,
            fs: ZERO_SEGMENT,
            gs: ZERO_SEGMENT,
            ss: ZERO_SEGMENT,
            tr: ZERO_SEGMENT,
            ldt: ZERO_SEGMENT,
            gdt: ZERO_DTABLE,
            idt: ZERO_DTABLE,
            cr0: 0,
            cr2: 0,
            cr3: 0,
            cr4: 0,
            cr8: 0,
            efer: 0,
            apic_base: 0,
            interrupt_bitmap: from_fn(|_| 0),
        };
        ioctl_read!(kvm_get_sregs, KVMIO, 0x83, KvmSregs);
        let res = unsafe { kvm_get_sregs(self.fd.as_raw_fd(), &mut regs) };
        res.context("failed to get special registers")?;
        Ok(regs)
    }

    pub fn set_sregs(&self, regs: KvmSregs) -> Result<()> {
        ioctl_write_ptr!(kvm_set_sregs, KVMIO, 0x84, KvmSregs);
        let res = unsafe { kvm_set_sregs(self.fd.as_raw_fd(), &regs) };
        res.context("failed to set special registers")?;
        Ok(())
    }

    pub fn set_xcr(&self, xcr: u32, value: u64) -> Result<()> {
        let mut kvm_xcrs = KvmXcrs::zeroed();
        kvm_xcrs.nr_xcrs = 1;
        kvm_xcrs.xcrs[0].xcr = xcr;
        kvm_xcrs.xcrs[0].value = value;

        ioctl_write_ptr!(kvm_set_xcrs, KVMIO, 0xa7, KvmXcrs);
        let res = unsafe { kvm_set_xcrs(self.fd.as_raw_fd(), &kvm_xcrs) };
        res.context("failed to set xcr registers")?;
        Ok(())
    }

    pub fn set_msr(&self, index: u32, data: u64) -> Result<()> {
        let mut msrs = KvmMsrs {
            nmsrs: 1,
            pad: 0,
            entries: [KvmMsrEntry {
                index,
                reserved: 0,
                data,
            }],
        };
        ioctl_write_ptr!(kvm_set_msrs, KVMIO, 0x89, KvmMsrs<[KvmMsrEntry; 0]>);
        let res = unsafe {
            kvm_set_msrs(
                self.fd.as_raw_fd(),
                (&mut msrs) as *mut KvmMsrs<[KvmMsrEntry; 1]> as *mut KvmMsrs<[KvmMsrEntry; 0]>,
            )
        };
        res.context("failed to set msr")?;
        Ok(())
    }

    pub fn set_cpuid(&self, entries: &[KvmCpuidEntry2]) -> Result<()> {
        const MAX_ENTRIES: usize = 256;
        let mut buffer = KvmCpuid2::<MAX_ENTRIES> {
            nent: MAX_ENTRIES as u32,
            _padding: 0,
            entries: [KvmCpuidEntry2 {
                function: 0,
                index: 0,
                flags: 0,
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
                padding: [0; 3],
            }; MAX_ENTRIES],
        };

        buffer.nent = u32::try_from(entries.len()).unwrap();
        buffer.entries[..entries.len()].copy_from_slice(entries);

        ioctl_write_ptr!(kvm_get_supported_cpuid, KVMIO, 0x90, KvmCpuid2<0>);
        let res = unsafe {
            kvm_get_supported_cpuid(
                self.fd.as_raw_fd(),
                &mut buffer as *mut KvmCpuid2<MAX_ENTRIES> as *mut KvmCpuid2<0>,
            )
        };
        res.context("failed to set cpuid")?;

        Ok(())
    }

    pub fn set_mp_state(&self, mp_state: MpState) -> Result<()> {
        ioctl_write_ptr!(kvm_set_mp_state, KVMIO, 0x99, MpState);
        let res = unsafe { kvm_set_mp_state(self.fd.as_raw_fd(), &mp_state) };
        res.context("failed to set mp state")?;
        Ok(())
    }

    pub fn interrupt(&self, vector: u8) -> Result<()> {
        #[repr(transparent)]
        struct KvmInterrupt(u32);
        let kvm_interrupt_val = KvmInterrupt(u32::from(vector));

        ioctl_write_ptr!(kvm_interrupt, KVMIO, 0x86, KvmInterrupt);
        let res = unsafe { kvm_interrupt(self.fd.as_raw_fd(), &kvm_interrupt_val) };
        res.context("failed to interrupt")?;
        Ok(())
    }

    #[cfg(feature = "tdx")]
    unsafe fn memory_encrypt_op_tdx<'a>(
        &self,
        payload: KvmTdxCmdPayload<'a>,
    ) -> Result<KvmTdxCmdPayload<'a>> {
        debug!("executing memory encryption operation");

        let mut cmd = KvmTdxCmd { payload, error: 0 };

        ioctl_readwrite!(kvm_memory_encrypt_op, KVMIO, 0xba, u64);
        let res =
            kvm_memory_encrypt_op(self.fd.as_raw_fd(), &mut cmd as *mut KvmTdxCmd as *mut u64);

        ensure!(cmd.error == 0);
        res.context("failed to execute memory encryption operation")?;

        Ok(cmd.payload)
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_init_vcpu(&self) -> Result<()> {
        unsafe {
            self.memory_encrypt_op_tdx(KvmTdxCmdPayload::KvmTdxInitVcpu(KvmTdxInitVcpuPayload {
                flags: 0,
                initial_rcx: 0,
            }))?;
        }
        Ok(())
    }

    #[cfg(feature = "tdx")]
    pub fn memory_mapping(&self, gpa: u64, source: &[Page]) -> Result<()> {
        debug!(gpa, "memory mapping");

        let mut data = KvmMemoryMapping {
            base_gfn: gpa >> 12,
            nr_pages: u64::try_from(source.len())?,
            flags: 0,
            source: source.as_ptr() as u64,
        };

        ioctl_readwrite!(kvm_memory_mapping, KVMIO, 0xd5, KvmMemoryMapping);

        let res = unsafe { kvm_memory_mapping(self.fd.as_raw_fd(), &mut data) };
        res.context("failed to create memory mapping")?;
        Ok(())
    }

    /// # Safety
    ///
    /// The caller has to ensure that `buffer` is large enough.
    pub unsafe fn get_xsave2(&self, buffer: &mut [u8]) -> Result<()> {
        #[repr(transparent)]
        struct KvmXsave([u8; 4096]);
        ioctl_read!(kvm_get_xsave2, KVMIO, 0xcf, KvmXsave);

        let res = unsafe { kvm_get_xsave2(self.fd.as_raw_fd(), buffer.as_mut_ptr().cast()) };
        res.context("failed to get xsave area")?;
        Ok(())
    }

    pub fn get_kvm_run_block(&self) -> Result<KvmRunBox> {
        let res = unsafe {
            nix::sys::mman::mmap(
                None,
                NonZeroUsize::new(size_of::<KvmRun>()).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &self.fd,
                0,
            )
        };
        let ptr = res.context("failed to map vcpu kvm_run block")?;
        Ok(KvmRunBox { ptr })
    }

    /// Returns `true` if the cpu ran uninterrupted or returns `false` if the
    /// thread was interrupted by a signal.
    pub fn run(&self) -> Result<bool> {
        debug!("running vcpu");

        ioctl_write_int_bad!(kvm_run, request_code_none!(KVMIO, 0x80));

        loop {
            let res = unsafe { kvm_run(self.fd.as_raw_fd(), 0) };
            match res {
                Ok(_) => return Ok(true),
                Err(Errno::EAGAIN) => {}
                Err(Errno::EINTR) => return Ok(false),
                Err(e) => return Err(e).context("failed to run vcpu"),
            }
        }
    }
}

pub struct KvmRunBox {
    ptr: NonNull<c_void>,
}

impl KvmRunBox {
    pub fn as_ptr(&self) -> VolatilePtr<'_, KvmRun> {
        unsafe { VolatilePtr::new(self.ptr.cast()) }
    }
}

impl Drop for KvmRunBox {
    fn drop(&mut self) {
        let res = unsafe { nix::sys::mman::munmap(self.ptr, size_of::<KvmRun>()) };
        res.unwrap();
    }
}

#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct KvmRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

const KVM_NR_INTERRUPTS: usize = 256;

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmSregs {
    pub cs: KvmSegment,
    pub ds: KvmSegment,
    pub es: KvmSegment,
    pub fs: KvmSegment,
    pub gs: KvmSegment,
    pub ss: KvmSegment,
    pub tr: KvmSegment,
    pub ldt: KvmSegment,
    pub gdt: KvmDtable,
    pub idt: KvmDtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; KVM_NR_INTERRUPTS.div_ceil(64)],
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmSegment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub ty: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    _padding: u8,
}

impl KvmSegment {
    pub const CODE64: Self = Self {
        base: 0,
        limit: 0xffff_ffff,
        selector: 0x10,
        ty: 0xb,
        present: 1,
        dpl: 0,
        db: 0,
        s: 1,
        l: 1,
        g: 1,
        avl: 0,
        unusable: 0,
        _padding: 0,
    };
    pub const DATA64: Self = Self {
        base: 0,
        limit: 0xffff_ffff,
        selector: 0x10,
        ty: 0x3,
        present: 1,
        dpl: 0,
        db: 1,
        s: 1,
        l: 0,
        g: 1,
        avl: 0,
        unusable: 0,
        _padding: 0,
    };
}

impl std::fmt::Debug for KvmSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmSegment")
            .field("base", &self.base)
            .field("limit", &self.limit)
            .field("selector", &self.selector)
            .field("ty", &self.ty)
            .field("present", &self.present)
            .field("dpl", &self.dpl)
            .field("db", &self.db)
            .field("s", &self.s)
            .field("l", &self.l)
            .field("g", &self.g)
            .field("avl", &self.avl)
            .field("unusable", &self.unusable)
            .finish()
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmDtable {
    pub base: u64,
    pub limit: u16,
    _padding: [u16; 3],
}

impl std::fmt::Debug for KvmDtable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmDtable")
            .field("base", &self.base)
            .field("limit", &self.limit)
            .finish()
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct KvmCpuidEntry2 {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3],
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmRun {
    pub request_interrupt_window: u8,
    pub immediate_exit: u8,
    padding1: [u8; 6],

    pub exit_reason: u32,
    pub ready_for_interrupt_injection: u8,
    pub if_flag: u8,
    pub flags: u16,

    pub cr8: u64,
    pub apic_base: u64,

    pub exit_data: [u8; 256],

    pub kvm_valid_regs: u64,
    pub kvm_dirty_regs: u64,
    pub regs: KvmSyncRegs,

    padding2: [u8; 1744],

    space_for_data: [u8; 4096],
}

impl KvmRun {
    pub fn exit(&self) -> KvmExit {
        match self.exit_reason {
            0 => KvmExit::Unknown(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitUnknown>()],
            )),
            2 => KvmExit::Io(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitIo>()],
            )),
            3 => KvmExit::Hypercall(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitHypercall>()],
            )),
            4 => KvmExit::Debug(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitDebug>()],
            )),
            5 => KvmExit::Hlt,
            6 => KvmExit::Mmio(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitMmio>()],
            )),
            7 => KvmExit::IrqWindowOpen,
            8 => KvmExit::Shutdown,
            9 => KvmExit::FailEntry(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitFailEntry>()],
            )),
            10 => KvmExit::Interrupted,
            11 => KvmExit::SetTpr,
            17 => KvmExit::Internal(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitInternalError>()],
            )),
            24 => KvmExit::SystemEvent(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitSystemEvent>()],
            )),
            29 => KvmExit::RdMsr(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitMsr>()],
            )),
            30 => KvmExit::WrMsr(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitMsr>()],
            )),
            38 => KvmExit::MemoryFault(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitMemoryFault>()],
            )),
            #[cfg(feature = "tdx")]
            40 => KvmExit::Tdx(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmTdxExit>()],
            )),
            51 => KvmExit::ReflectVc,
            exit_reason => KvmExit::Other { exit_reason },
        }
    }

    pub fn set_exit(&mut self, exit: KvmExit) {
        match exit {
            KvmExit::Hypercall(hypercall) => {
                self.exit_reason = 3;
                self.exit_data[..size_of_val(&hypercall)].copy_from_slice(bytes_of(&hypercall));
            }
            KvmExit::RdMsr(msr) => {
                self.exit_reason = 29;
                self.exit_data[..size_of_val(&msr)].copy_from_slice(bytes_of(&msr));
            }
            #[cfg(feature = "tdx")]
            KvmExit::Tdx(msr) => {
                self.exit_reason = 40;
                self.exit_data[..size_of_val(&msr)].copy_from_slice(bytes_of(&msr));
            }
            _ => unimplemented!(),
        }
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmSyncRegs {
    pub regs: KvmRegs,
    pub sregs: KvmSregs,
    pub events: KvmVcpuEvents,
    _padding: [u8; 1528],
}

impl std::fmt::Debug for KvmSyncRegs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmSyncRegs")
            .field("regs", &self.regs)
            .field("sregs", &self.sregs)
            .field("events", &self.events)
            .finish()
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmVcpuEvents {
    pub exception: KvmVcpuEventsException,
    pub interrupt: KvmVcpuEventsInterrupt,
    pub nmi: KvmVcpuEventsNmi,
    pub sipi_vector: u32,
    pub flags: u32,
    pub smi: KvmVcpuEventsSmi,
    reserved: [u8; 27],
    pub exception_has_payload: u8,
    pub exception_payload: u64,
}

impl std::fmt::Debug for KvmVcpuEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmVcpuEvents")
            .field("exception", &self.exception)
            .field("interrupt", &self.interrupt)
            .field("nmi", &self.nmi)
            .field("sipi_vector", &self.sipi_vector)
            .field("flags", &self.flags)
            .field("smi", &self.smi)
            .field("exception_has_payload", &self.exception_has_payload)
            .field("exception_payload", &self.exception_payload)
            .finish()
    }
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmVcpuEventsException {
    pub injected: u8,
    pub nr: u8,
    pub has_error_code: u8,
    pub pending: u8,
    pub error_code: u32,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmVcpuEventsInterrupt {
    pub injected: u8,
    pub nr: u8,
    pub soft: u8,
    pub shadow: u8,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmVcpuEventsNmi {
    pub injected: u8,
    pub pending: u8,
    pub masked: u8,
    pub pad: u8,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmVcpuEventsSmi {
    pub smm: u8,
    pub pending: u8,
    pub smm_inside_nmi: u8,
    pub latched_init: u8,
}

#[derive(Clone, Copy, Debug)]
pub enum KvmExit {
    Unknown(KvmExitUnknown),
    Io(KvmExitIo),
    Hypercall(KvmExitHypercall),
    Debug(KvmExitDebug),
    Hlt,
    Mmio(KvmExitMmio),
    IrqWindowOpen,
    Shutdown,
    FailEntry(KvmExitFailEntry),
    Interrupted,
    SetTpr,
    Internal(KvmExitInternalError),
    SystemEvent(KvmExitSystemEvent),
    RdMsr(KvmExitMsr),
    WrMsr(KvmExitMsr),
    MemoryFault(KvmExitMemoryFault),
    #[cfg(feature = "tdx")]
    Tdx(KvmTdxExit),
    ReflectVc,
    Other {
        exit_reason: u32,
    },
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitUnknown {
    pub hardware_exit_reason: u64,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitIo {
    pub direction: u8,
    pub size: u8,
    pub port: u16,
    pub count: u32,
    /// relative to kvm_run start
    pub data_offset: u64,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmExitHypercall {
    pub nr: u64,
    pub args: [u64; 6],
    pub ret: u64,
    pub flags: u64,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitDebug {
    pub exception: u32,
    pub pad: u32,
    pub pc: u64,
    pub dr6: u64,
    pub dr7: u64,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitMmio {
    pub phys_addr: u64,
    pub data: [u8; 8],
    pub len: u32,
    pub is_write: u8,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitFailEntry {
    pub hardware_entry_failure_reason: u64,
    pub cpu: u32,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitInternalError {
    pub suberror: u32,
    pub ndata: u32,
    pub data: [u64; 16],
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitSystemEvent {
    pub ty: u32,
    pub ndata: u32,
    pub data: [u64; 16],
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitMsr {
    _error: u8, /* user -> kernel */
    _pad: [u8; 7],
    pub reason: KvmMsrExitReason, /* kernel -> user */
    pub index: u32,               /* kernel -> user */
    pub data: u64,                /* kernel <-> user */
}

bitflags! {
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    #[repr(transparent)]
    pub struct KvmMsrExitReason: u32 {
        const INVAL = 1 << 0;
        const UNKNOWN = 1 << 1;
        const FILTER = 1 << 2;
    }
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitMemoryFault {
    pub flags: KvmExitMemoryFaultFlags,
    pub gpa: u64,
    pub size: u64,
}

bitflags! {
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    #[repr(transparent)]
    pub struct KvmExitMemoryFaultFlags: u64 {
        const PRIVATE = 1 << 0;
    }
}

#[cfg(feature = "tdx")]
#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmTdxExit {
    pub ty: u32,
    _pad: u32,
    pub in_rcx: u64,
    pub in_r10: u64,
    pub in_r11: u64,
    pub in_r12: u64,
    pub in_r13: u64,
    pub in_r14: u64,
    pub in_r15: u64,
    pub in_rbx: u64,
    pub in_rdi: u64,
    pub in_rsi: u64,
    pub in_r8: u64,
    pub in_r9: u64,
    pub in_rdx: u64,
    pub out_r10: u64,
    pub out_r11: u64,
    pub out_r12: u64,
    pub out_r13: u64,
    pub out_r14: u64,
    pub out_r15: u64,
    pub out_rbx: u64,
    pub out_rdi: u64,
    pub out_rsi: u64,
    pub out_r8: u64,
    pub out_r9: u64,
    pub out_rdx: u64,
}

mod hidden {
    use super::KvmCpuidEntry2;

    #[repr(C)]
    pub struct KvmCpuid2<const N: usize> {
        pub nent: u32,
        pub _padding: u32,
        pub entries: [KvmCpuidEntry2; N],
    }
}

#[repr(C)]
pub struct KvmEnableCap {
    cap: KvmCap,
    flags: u32,
    args: [u64; 4],
    _pad: [u8; 64],
}

#[repr(transparent)]
pub struct KvmCap(pub u32);

impl KvmCap {
    pub const MAX_VCPUS: Self = Self(66);
    pub const X2APIC_API: Self = Self(129);
    pub const X86_USER_SPACE_MSR: Self = Self(188);
    pub const EXIT_HYPERCALL: Self = Self(201);
    pub const XSAVE2: Self = Self(208);
    pub const VM_TYPES: Self = Self(235);
}

#[repr(C)]
pub struct KvmUserspaceMemoryRegion {
    slot: u32,
    flags: KvmUserspaceMemoryRegionFlags,
    guest_phys_addr: u64,
    /// bytes
    memory_size: u64,
    /// start of the userspace allocated memory
    userspace_addr: u64,
}

bitflags! {
    #[derive(Clone, Copy)]
    #[repr(transparent)]
    pub struct KvmUserspaceMemoryRegionFlags: u32 {
        const KVM_MEM_LOG_DIRTY_PAGES = 1 << 0;
        const KVM_MEM_READONLY = 1 << 1;
        const KVM_MEM_PRIVATE = 1 << 2;
    }
}

#[repr(C)]
pub struct KvmUserspaceMemoryRegion2<'a> {
    region: KvmUserspaceMemoryRegion,
    restricted_offset: u64,
    restricted_fd: Option<BorrowedFd<'a>>,
    _pad1: u32,
    _pad2: [u64; 14],
}

#[cfg(feature = "snp")]
pub struct SevHandle {
    fd: OwnedFd,
}

#[cfg(feature = "snp")]
impl SevHandle {
    pub fn new() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .open("/dev/sev")
            .context("failed to open /dev/sev")?;
        let fd = OwnedFd::from(file);
        Ok(Self { fd })
    }
}

#[cfg(feature = "snp")]
#[repr(C)]
struct KvmSevCmd<'a, 'b> {
    pub payload: KvmSevCmdPayload<'a>,
    pub error: u32,
    pub sev_fd: Option<BorrowedFd<'b>>,
}

#[cfg(feature = "snp")]
#[allow(clippy::enum_variant_names)]
#[repr(C, u32)]
// FIXME: Figure out which ones need `&mut T` and which ones need `&T`
pub enum KvmSevCmdPayload<'a> {
    KvmSevInit2 {
        data: &'a mut KvmSevInit,
    } = 22,
    KvmSevSnpLaunchStart {
        data: &'a mut KvmSevSnpLaunchStart,
    } = 100,
    KvmSevSnpLaunchFinish {
        data: &'a mut KvmSevSnpLaunchFinish,
    } = 102,
    KvmSevSnpLaunchUpdateVmpls {
        data: &'a mut KvmSevSnpLaunchUpdateVmpls,
    } = 103,
}

#[cfg(feature = "snp")]
#[repr(C)]
pub struct KvmSevInit {
    pub vmsa_features: SevFeatures,
    pub flags: u32,
    pub ghcb_version: u16,
    pub _pad1: u16,
    pub _pad2: [u32; 8],
}

#[cfg(feature = "snp")]
#[repr(C)]
pub struct KvmSevSnpLaunchStart {
    /// Guest policy to use.
    pub policy: GuestPolicy,
    /// guest OS visible workarounds
    pub gosvw: [u8; 16],
    pub flags: u16,
    pub pad0: [u8; 6],
    pub pad1: [u64; 4],
}

#[cfg(feature = "snp")]
#[repr(C)]
pub struct KvmSevSnpLaunchUpdate {
    /// Guest page number to start from.
    pub gfn_start: u64,
    /// userspace address need to be encrypted
    pub uaddr: u64,
    /// length of memory region
    pub len: u64,
    pub page_type: u8,
    pub pad0: u8,
    pub flags: u16,
    pub vcpu_id: u32,
    pub pad2: [u64; 4],
}

#[cfg(feature = "snp")]
#[repr(C)]
pub struct KvmSevSnpLaunchUpdateVmpls {
    pub base: KvmSevSnpLaunchUpdate,
    pub vmpl3_perms: VmplPermissions,
    pub vmpl2_perms: VmplPermissions,
    pub vmpl1_perms: VmplPermissions,
}

#[cfg(feature = "snp")]
#[repr(C)]
pub struct KvmSevSnpLaunchFinish {
    id_block_uaddr: u64,
    id_auth_uaddr: u64,
    id_block_en: u8,
    auth_key_en: u8,
    vcek_disabled: u8,
    host_data: [u8; 32],
    pad0: [u8; 3],
    flags: u16,
    pad1: [u64; 4],
}

#[repr(u32)]
pub enum MpState {
    Runnable,
}

#[cfg(feature = "tdx")]
#[repr(C)]
pub struct KvmTdxCmd<'a> {
    payload: KvmTdxCmdPayload<'a>,
    error: u64,
}

#[cfg(feature = "tdx")]
#[allow(clippy::enum_variant_names)]
#[repr(C, u32)]
pub enum KvmTdxCmdPayload<'a> {
    KvmTdxCapabilities(KvmTdxCapabilitiesPayload<'a>),
    KvmTdxInitVm(KvmTdxInitVmPayload<'a>),
    KvmTdxInitVcpu(KvmTdxInitVcpuPayload),
    KvmTdxExtendMemory(KvmTdxExtendMemoryPayload<'a>),
    KvmTdxFinalizeVm(KvmTdxFinalizeVmPayload),
}

#[cfg(feature = "tdx")]
#[repr(C, packed(4))]
pub struct KvmTdxCapabilitiesPayload<'a> {
    flags: u32,
    data: &'a mut KvmTdxCapabilities,
}

#[cfg(feature = "tdx")]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct KvmTdxCapabilities {
    pub attrs_fixed0: u64,
    pub attrs_fixed1: u64,
    pub xfam_fixed0: u64,
    pub xfam_fixed1: u64,
    pub supported_gpaw: SupportedGpaw,
    padding: u32,
    reserved: [u64; 251],
    nr_cpuid_configs: u32,
    cpuid_configs: [KvmTdxCpuidConfig; MAX_ENTRIES],
}

#[cfg(feature = "tdx")]
impl KvmTdxCapabilities {
    fn cpuid_configs(&self) -> &[KvmTdxCpuidConfig] {
        &self.cpuid_configs[..self.nr_cpuid_configs as usize]
    }
}

#[cfg(feature = "tdx")]
impl fmt::Debug for KvmTdxCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KvmTdxCapabilities")
            .field("attrs_fixed0", &self.attrs_fixed0)
            .field("attrs_fixed1", &self.attrs_fixed1)
            .field("xfam_fixed0", &self.xfam_fixed0)
            .field("xfam_fixed1", &self.xfam_fixed1)
            .field("supported_gpaw", &self.supported_gpaw)
            .field("cpuid_configs", &self.cpuid_configs())
            .finish()
    }
}

#[cfg(feature = "tdx")]
bitflags! {
    #[derive(Debug, Clone, Copy)]
    #[repr(transparent)]
    pub struct SupportedGpaw: u32 {
        const GPAW_48 = 1 << 0;
        const GPAW_52 = 1 << 1;
    }
}

#[cfg(feature = "tdx")]
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct KvmTdxCpuidConfig {
    leaf: u32,
    sub_leaf: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

#[cfg(feature = "tdx")]
#[repr(C, packed(4))]
pub struct KvmTdxInitVmPayload<'a> {
    flags: u32,
    data: &'a KvmTdxInitVm,
}

#[cfg(feature = "tdx")]
#[repr(C)]
pub struct KvmTdxInitVm {
    attributes: u64,
    mrconfigid: [u8; 48],
    mrowner: [u8; 48],
    mrownerconfig: [u8; 48],
    max_num_l2_vms: u8,
    reserved: [u64; 1003],
    cpuid: KvmCpuid2<MAX_ENTRIES>,
}

#[cfg(feature = "tdx")]
#[repr(C, packed(4))]
pub struct KvmTdxInitVcpuPayload {
    flags: u32,
    initial_rcx: u64,
}

#[cfg(feature = "tdx")]
#[repr(C, packed(4))]
pub struct KvmTdxExtendMemoryPayload<'a> {
    flags: u32,
    data: &'a mut KvmMemoryMapping,
}

#[cfg(feature = "tdx")]
#[repr(C)]
pub struct KvmMemoryMapping {
    base_gfn: u64,
    nr_pages: u64,
    flags: u64,
    source: u64,
}

#[cfg(feature = "tdx")]
#[repr(C, packed(4))]
pub struct KvmTdxFinalizeVmPayload {
    flags: u32,
    data: u64,
}

#[repr(C)]
pub struct KvmSetMemoryAttributes {
    address: u64,
    size: u64,
    attributes: KvmMemoryAttributes,
    flags: u64,
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    #[repr(transparent)]
    pub struct KvmMemoryAttributes: u64 {
        const PRIVATE = 1 << 3;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    #[repr(transparent)]
    pub struct KvmGuestMemFdFlags: u64 { }
}

#[repr(C)]
pub struct KvmMsrs<T>
where
    T: ?Sized,
{
    nmsrs: u32, /* number of msrs in entries */
    pad: u32,
    entries: T,
}

#[repr(C)]
pub struct KvmMsrEntry {
    index: u32,
    reserved: u32,
    data: u64,
}

const KVM_MAX_XCRS: usize = 16;

#[derive(Zeroable)]
#[repr(C)]
struct KvmXcr {
    xcr: u32,
    reserved: u32,
    value: u64,
}

#[derive(Zeroable)]
#[repr(C)]
struct KvmXcrs {
    nr_xcrs: u32,
    flags: u32,
    xcrs: [KvmXcr; KVM_MAX_XCRS],
    padding: [u64; 16],
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::KvmSyncRegs;

    #[test]
    fn test_kvm_sync_regs_size() {
        assert_eq!(size_of::<KvmSyncRegs>(), 2048);
    }
}
