#![allow(dead_code)]

use std::{
    array::from_fn,
    fs::OpenOptions,
    mem::size_of,
    num::{NonZeroU8, NonZeroUsize},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::prelude::OpenOptionsExt,
    },
    ptr::NonNull,
};

use anyhow::{anyhow, ensure, Context, Result};
use bit_field::BitField;
use bitflags::bitflags;
use bytemuck::{pod_read_unaligned, Contiguous, Pod, Zeroable};
use nix::{
    errno::Errno,
    ioctl_none, ioctl_read, ioctl_readwrite, ioctl_write_int_bad, ioctl_write_ptr,
    libc::O_SYNC,
    request_code_none,
    sys::mman::{MapFlags, ProtFlags},
};
use snp_types::{guest_policy::GuestPolicy, PageType, VmplPermissions};
use tracing::debug;
use volatile::VolatilePtr;

use crate::{kvm::hidden::KvmCpuid2, slot::Slot};

const KVMIO: u8 = 0xAE;

pub struct KvmHandle {
    fd: OwnedFd,
}

impl KvmHandle {
    pub fn new() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_SYNC)
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

    pub fn create_vm(&self, protected: bool) -> Result<VmHandle> {
        debug!("creating vm");

        ioctl_write_int_bad!(kvm_create_vm, request_code_none!(KVMIO, 0x01));
        let res = unsafe { kvm_create_vm(self.fd.as_raw_fd(), i32::from(protected)) };
        let raw_fd = res.context("failed to create vm")?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        Ok(VmHandle { fd })
    }

    pub fn get_supported_cpuid(&self) -> Result<Box<[KvmCpuidEntry2]>> {
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

    pub fn set_user_memory_region(
        &self,
        slot: u16,
        guest_phys_addr: u64,
        pages: Box<[Page]>,
    ) -> Result<VolatilePtr<[Page]>> {
        // FIXME: Is returning a racy volatile pointer bad? No one knows!

        debug!("mapping memory");

        let pages = Box::leak(pages);
        let pages = VolatilePtr::from_mut_ref(pages);

        let region = KvmUserspaceMemoryRegion {
            slot: u32::from(slot),
            flags: KvmUserspaceMemoryRegionFlags::empty(),
            guest_phys_addr,
            memory_size: u64::try_from(pages.len() * 0x1000).unwrap(),
            userspace_addr: pages.as_ptr().as_ptr() as *mut Page as u64,
        };

        ioctl_write_ptr!(
            kvm_set_user_memory_region,
            KVMIO,
            0x46,
            KvmUserspaceMemoryRegion
        );
        let res = unsafe { kvm_set_user_memory_region(self.fd.as_raw_fd(), &region) };
        res.context("failed to map memory")?;
        Ok(pages)
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
                Some(restricted_fd),
                0,
            )?;
        }

        Ok(())
    }

    pub unsafe fn map_encrypted_memory_evil(
        &self,
        id: u16,
        slot: &Slot,
        offset: u64,
    ) -> Result<()> {
        debug!(id, guest_phys_addr = %format_args!("{:x?}", slot.gpa()), "mapping private memory");

        let shared_mapping = slot.shared_mapping();
        let restricted_fd = slot.restricted_fd();

        unsafe {
            self.map_private_memory(
                id,
                slot.gpa().start_address().as_u64(),
                u64::try_from(shared_mapping.len().get())?,
                u64::try_from(shared_mapping.as_ptr().as_ptr() as usize)?,
                Some(restricted_fd),
                offset,
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

    pub fn irq_line(&self, gsi: u32, level: bool) -> Result<()> {
        debug!("setting irq line");

        #[repr(C)]
        pub struct KvmIrqLevel {
            gsi: u32,
            level: u32,
        }

        let data = KvmIrqLevel {
            gsi,
            level: u32::from(level),
        };

        ioctl_write_ptr!(kvm_irq_line, KVMIO, 0x61, KvmIrqLevel);
        let res = unsafe { kvm_irq_line(self.fd.as_raw_fd(), &data) };
        res.context("failed to set irq line")?;

        Ok(())
    }

    pub fn irq_line_status(&self, gsi: u32) -> Result<(u32, u32)> {
        debug!("setting irq line");

        #[repr(C)]
        pub struct KvmIrqLevel {
            gsi_or_status: u32,
            level: u32,
        }

        let mut data = KvmIrqLevel {
            gsi_or_status: gsi,
            level: 0,
        };

        ioctl_readwrite!(kvm_irq_line, KVMIO, 0x67, KvmIrqLevel);
        let res = unsafe { kvm_irq_line(self.fd.as_raw_fd(), &mut data) };
        res.context("failed to set irq line")?;

        Ok((data.gsi_or_status, data.level))
    }

    pub fn signal_msi(&self, address: u64, data: u32) -> Result<()> {
        debug!("signalling msi");

        #[repr(C)]
        pub struct KvmMsi {
            address_lo: u32,
            address_hi: u32,
            data: u32,
            flags: u32,
            devid: u32,
            pad: [u8; 12],
        }

        let data = KvmMsi {
            address_lo: address.get_bits(..32) as u32,
            address_hi: address.get_bits(32..) as u32,
            data,
            flags: 0,
            devid: 0,
            pad: [0; 12],
        };

        ioctl_write_ptr!(kvm_signal_msi, KVMIO, 0xa5, KvmMsi);
        let res = unsafe { kvm_signal_msi(self.fd.as_raw_fd(), &data) };
        res.context("failed to signal msi")?;

        Ok(())
    }

    pub fn get_irqchip(&self, chip_id: u32) -> Result<[u8; 512]> {
        debug!("getting irqchip");

        let mut data = KvmIrqchip {
            chip_id,
            _pad: 0,
            chip: [0; 512],
        };

        ioctl_readwrite!(kvm_get_irqchip, KVMIO, 0x62, KvmIrqchip);
        let res = unsafe { kvm_get_irqchip(self.fd.as_raw_fd(), &mut data) };
        res.context("failed to get irqchip")?;

        Ok(data.chip)
    }

    pub fn set_irqchip(&self, chip_id: u32, chip: [u8; 512]) -> Result<()> {
        debug!("setting irqchip");

        let mut data = KvmIrqchip {
            chip_id,
            _pad: 0,
            chip,
        };

        ioctl_read!(kvm_set_irqchip, KVMIO, 0x63, KvmIrqchip);
        let res = unsafe { kvm_set_irqchip(self.fd.as_raw_fd(), &mut data) };
        res.context("failed to set irqchip")?;

        Ok(())
    }

    pub fn set_gsi_routing<const N: usize>(&self, entries: [KvmIrqRoutingEntry; N]) -> Result<()> {
        debug!("setting gsi routing");

        let data = KvmIrqRouting {
            nr: u32::try_from(N)?,
            flags: 0,
            entries,
        };

        ioctl_write_ptr!(
            kvm_set_gsi_routing,
            KVMIO,
            0x6a,
            KvmIrqRouting<[KvmIrqRoutingEntry; 0]>
        );
        let res = unsafe {
            kvm_set_gsi_routing(
                self.fd.as_raw_fd(),
                (&data as *const KvmIrqRouting<_>).cast(),
            )
        };
        res.context("failed to set gsi routing")?;

        Ok(())
    }

    pub fn irqfd(&self, irqfd: &KvmIrqfd) -> Result<()> {
        debug!("registering irqfd");
        ioctl_write_ptr!(kvm_interrupt, KVMIO, 0x76, KvmIrqfd);
        let res = unsafe { kvm_interrupt(self.fd.as_raw_fd(), irqfd) };
        res.context("failed to register irqfd")?;
        Ok(())
    }

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

    pub fn sev_snp_init(&self) -> Result<()> {
        let mut data = KvmSnpInit {
            flags: KvmSnpInitFlags::KVM_SEV_SNP_RESTRICTED_INJET,
        };
        let payload = KvmSevCmdPayload::KvmSevSnpInit { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, None) };
        res.context("failed to initialize sev snp")?;
        Ok(())
    }

    pub fn sev_snp_launch_start(&self, policy: GuestPolicy, sev_handle: &SevHandle) -> Result<()> {
        debug!("starting snp launch");
        let mut data = KvmSevSnpLaunchStart {
            policy,
            ma_uaddr: 0,
            ma_en: 0,
            imi_en: 0,
            gosvw: [0; 16],
            _pad: [0; 6],
        };
        let payload = KvmSevCmdPayload::KvmSevSnpLaunchStart { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, Some(sev_handle)) };
        res.context("failed to start sev snp launch")?;
        Ok(())
    }

    pub fn sev_snp_launch_update(
        &self,
        start_addr: u64,
        uaddr: u64,
        len: u32,
        page_type: PageType,
        vmpl1_perms: VmplPermissions,
        // FIXME: figure out if we need a sev handle for this operation
        sev_handle: &SevHandle,
    ) -> Result<()> {
        debug!("updating snp launch");

        ensure!(
            start_addr & 0xfff == 0,
            "start address is not properly aligned"
        );
        let start_gfn = start_addr >> 12;

        let mut data = KvmSevSnpLaunchUpdate {
            start_gfn,
            uaddr,
            len,
            imi_page: 0,
            page_type: page_type as u8,
            vmpl3_perms: VmplPermissions::empty(),
            vmpl2_perms: VmplPermissions::empty(),
            vmpl1_perms,
        };
        let payload = KvmSevCmdPayload::KvmSevSnpLaunchUpdate { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, Some(sev_handle)) };
        res.context("failed to update sev snp launch")?;
        Ok(())
    }

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
            _pad: [0; 6],
        };
        let payload = KvmSevCmdPayload::KvmSevSnpLaunchFinish { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, Some(sev_handle)) };
        res.context("failed to finish sev snp launch")?;
        Ok(())
    }

    pub fn sev_snp_dbg_decrypt(&self, gfn: u64) -> Result<[u8; 4096]> {
        debug!("debug decrypting");

        let mut page = [0xcc; 4096];

        let mut data = KvmSevSnpDbg {
            src_gfn: gfn,
            dst_uaddr: &mut page as *const [u8; 4096] as u64,
        };
        let payload = KvmSevCmdPayload::KvmSevSnpDbgDecrypt { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, None) };
        res.context("failed to debug decrypt")?;
        Ok(page)
    }

    pub fn sev_snp_dbg_decrypt_vmsa(&self, vcpu_id: u32) -> Result<[u8; 4096]> {
        debug!("debug decrypting vmsa");

        let mut page = [0xcc; 4096];

        let mut data = KvmSevSnpDbgVmsa {
            vcpu_id,
            dst_uaddr: &mut page as *const [u8; 4096] as u64,
        };
        let payload = KvmSevCmdPayload::KvmSevSnpDbgDecryptVmsa { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, None) };
        res.context("failed to debug decrypt vmsa")?;
        Ok(page)
    }

    pub fn register_encrypted_region(&self, addr: u64, size: u64) -> Result<()> {
        debug!("registering encrypted region");

        let mut data = KvmEncRegion { addr, size };
        ioctl_read!(kvm_sev_mem_enc_register_region, KVMIO, 0xbb, KvmEncRegion);
        let res = unsafe { kvm_sev_mem_enc_register_region(self.fd.as_raw_fd(), &mut data) };
        res.context("failed to register encrypted region")?;
        Ok(())
    }

    pub fn get_supported_memory_attributes(&self) -> Result<KvmMemoryAttributes> {
        debug!("getting supported memory regions");

        let mut data = KvmMemoryAttributes::empty();
        ioctl_read!(kvm_set_memory_attributes, KVMIO, 0xd2, KvmMemoryAttributes);
        let res = unsafe { kvm_set_memory_attributes(self.fd.as_raw_fd(), &mut data) };
        res.context("failed toget supported memory attributes")?;
        Ok(data)
    }

    pub fn set_memory_attributes(
        &self,
        address: &mut u64,
        size: &mut u64,
        attributes: KvmMemoryAttributes,
    ) -> Result<()> {
        debug!(?address, ?size, ?attributes, "setting memory attributes");

        let mut data = KvmSetMemoryAttributes {
            address: *address,
            size: *size,
            attributes,
            flags: 0,
        };
        ioctl_readwrite!(
            kvm_set_memory_attributes,
            KVMIO,
            0xd3,
            KvmSetMemoryAttributes
        );
        let res = unsafe { kvm_set_memory_attributes(self.fd.as_raw_fd(), &mut data) };
        res.context("failed to set memory attributes")?;
        *address = data.address;
        *size = data.size;
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

    pub fn get_debug_regs(&self) -> Result<KvmDebugRegs> {
        let mut regs = KvmDebugRegs {
            db: [0; 4],
            dr6: 0,
            dr7: 0,
            flags: 0,
            reserved: [0; 9],
        };
        ioctl_read!(kvm_get_sregs, KVMIO, 0xa1, KvmDebugRegs);
        let res = unsafe { kvm_get_sregs(self.fd.as_raw_fd(), &mut regs) };
        res.context("failed to get debug registers")?;
        Ok(regs)
    }

    pub fn set_debug_regs(&self, regs: KvmDebugRegs) -> Result<()> {
        ioctl_write_ptr!(kvm_set_sregs, KVMIO, 0xa2, KvmDebugRegs);
        let res = unsafe { kvm_set_sregs(self.fd.as_raw_fd(), &regs) };
        res.context("failed to set debug registers")?;
        Ok(())
    }

    pub fn set_guest_debug(&self, guest_debug: KvmGuestDebug) -> Result<()> {
        ioctl_write_ptr!(kvm_set_guest_debug, KVMIO, 0x9b, KvmGuestDebug);
        let res = unsafe { kvm_set_guest_debug(self.fd.as_raw_fd(), &guest_debug) };
        res.context("failed to set special registers")?;
        Ok(())
    }

    pub fn queue_nmi(&self) -> Result<()> {
        ioctl_none!(kvm_nmi, KVMIO, 0x9a);
        let res = unsafe { kvm_nmi(self.fd.as_raw_fd()) };
        res.context("failed to queue interrupts")?;
        Ok(())
    }

    pub fn queue_interrupt(&self, irq: NonZeroU8) -> Result<()> {
        #[repr(C)]
        pub struct KvmInterrupt {
            irq: u32,
        }

        let data = KvmInterrupt {
            irq: u32::from(irq.get()),
        };

        ioctl_write_ptr!(kvm_interrupt, KVMIO, 0x86, KvmInterrupt);
        let res = unsafe { kvm_interrupt(self.fd.as_raw_fd(), &data) };
        res.context("failed to queue interrupts")?;
        Ok(())
    }

    pub fn get_lapic(&self) -> Result<KvmLapicState> {
        let mut state = KvmLapicState { regs: [0; 0x400] };
        ioctl_read!(kvm_get_vcpu_events, KVMIO, 0x8e, KvmLapicState);
        let res = unsafe { kvm_get_vcpu_events(self.fd.as_raw_fd(), &mut state) };
        res.context("failed to get lapic state")?;
        Ok(state)
    }

    pub fn set_lapic(&self, state: &KvmLapicState) -> Result<()> {
        ioctl_write_ptr!(kvm_get_vcpu_events, KVMIO, 0x8f, KvmLapicState);
        let res = unsafe { kvm_get_vcpu_events(self.fd.as_raw_fd(), state) };
        res.context("failed to set lapic state")?;
        Ok(())
    }

    pub fn get_mp_state(&self) -> Result<KvmMpState> {
        let mut value = 0u32;
        ioctl_read!(kvm_get_vcpu_events, KVMIO, 0x98, u32);
        let res = unsafe { kvm_get_vcpu_events(self.fd.as_raw_fd(), &mut value) };
        res.context("failed to get mp state")?;

        KvmMpState::from_integer(value).with_context(|| anyhow!("unexpected mp_state: {value}"))
    }

    pub fn set_mp_state(&self, mp_state: KvmMpState) -> Result<()> {
        ioctl_write_ptr!(kvm_get_vcpu_events, KVMIO, 0x99, u32);
        let res = unsafe { kvm_get_vcpu_events(self.fd.as_raw_fd(), &(mp_state as u32)) };
        res.context("failed to set mp state")?;
        Ok(())
    }

    pub fn get_msr(&self, index: u32) -> Result<u64> {
        let mut msrs = KvmMsrs {
            nmsrs: 1,
            pad: 0,
            entries: [KvmMsrEntry {
                index,
                reserved: 0,
                data: 0,
            }],
        };
        ioctl_readwrite!(kvm_get_msrs, KVMIO, 0x88, KvmMsrs<[KvmMsrEntry; 0]>);
        let res = unsafe {
            kvm_get_msrs(
                self.fd.as_raw_fd(),
                (&mut msrs) as *mut KvmMsrs<[KvmMsrEntry; 1]> as *mut KvmMsrs<[KvmMsrEntry; 0]>,
            )
        };
        res.context("failed to get msr")?;
        Ok(msrs.entries[0].data)
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

    pub fn get_vcpu_events(&self) -> Result<KvmVcpuEvents> {
        let mut events = KvmVcpuEvents::zeroed();
        ioctl_read!(kvm_get_vcpu_events, KVMIO, 0x9f, KvmVcpuEvents);
        let res = unsafe { kvm_get_vcpu_events(self.fd.as_raw_fd(), &mut events) };
        res.context("failed to get vcpu events")?;
        Ok(events)
    }

    pub fn set_vcpu_events(&self, events: &KvmVcpuEvents) -> Result<()> {
        ioctl_write_ptr!(kvm_set_vcpu_events, KVMIO, 0xa0, KvmVcpuEvents);
        let res = unsafe { kvm_set_vcpu_events(self.fd.as_raw_fd(), events) };
        res.context("failed to set vcpu events")?;
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

    pub fn get_kvm_run_block(&self) -> Result<VolatilePtr<KvmRun>> {
        // FIXME: unmap the memory
        let res = unsafe {
            nix::sys::mman::mmap(
                None,
                NonZeroUsize::new(size_of::<KvmRun>()).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                Some(self.fd.as_fd()),
                0,
            )
        };
        let ptr = res.context("failed to map vcpu kvm_run block")?;
        let ptr = unsafe { VolatilePtr::new_read_write(NonNull::new_unchecked(ptr.cast())) };
        Ok(ptr)
    }

    /// Returns `true` if the cpu ran interrupted or returns `false` if the
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
    pub interrupt_bitmap: [u64; (KVM_NR_INTERRUPTS + 63) / 64],
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
        selector: 0,
        ty: 10,
        present: 1,
        dpl: 0,
        db: 1,
        s: 0,
        l: 0,
        g: 0,
        avl: 0,
        unusable: 0,
        _padding: 0,
    };
    pub const DATA64: Self = Self {
        base: 0,
        limit: 0xffff_ffff,
        selector: 0,
        ty: 3,
        present: 1,
        dpl: 0,
        db: 1,
        s: 0,
        l: 0,
        g: 0,
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

#[repr(C)]
pub struct KvmDebugRegs {
    pub db: [u64; 4],
    pub dr6: u64,
    pub dr7: u64,
    pub flags: u64,
    pub reserved: [u64; 9],
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
    padding: [u32; 3],
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
            4 => KvmExit::Debug(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitDebug>()],
            )),
            5 => KvmExit::Hlt,
            6 => KvmExit::Mmio(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitMmio>()],
            )),
            7 => KvmExit::IrqWindowOpen,
            8 => KvmExit::Shutdown,
            10 => KvmExit::Interrupted,
            17 => KvmExit::Internal(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitInternalError>()],
            )),
            24 => KvmExit::SystemEvent(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitSystemEvent>()],
            )),
            38 => KvmExit::MemoryFault(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitMemoryFault>()],
            )),
            50 => KvmExit::Vmgexit(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitVmgexit>()],
            )),
            51 => KvmExit::ReflectVc,
            exit_reason => KvmExit::Other { exit_reason },
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
    Debug(KvmExitDebug),
    Hlt,
    Mmio(KvmExitMmio),
    IrqWindowOpen,
    Shutdown,
    Interrupted,
    Internal(KvmExitInternalError),
    SystemEvent(KvmExitSystemEvent),
    MemoryFault(KvmExitMemoryFault),
    Vmgexit(KvmExitVmgexit),
    ReflectVc,
    Other { exit_reason: u32 },
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
pub struct KvmExitMemoryFault {
    pub flags: KvmExitMemoryFaultFlags,
    pub gpa: u64,
    pub size: u64,
}

bitflags! {
    #[derive(Pod, Zeroable)]
    #[repr(transparent)]
    pub struct KvmExitMemoryFaultFlags: u64 {
        const PRIVATE = 1 << 0;
    }
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitVmgexit {
    pub ghcb_msr: u64,
    pub error: u8,
}

#[repr(C)]
pub struct KvmGuestDebug {
    pub control: u32,
    pub pad: u32,
    pub arch: KvmGuestDebugArch,
}

#[repr(C)]
pub struct KvmGuestDebugArch {
    pub debugreg: [u64; 8],
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
    pub const SPLIT_IRQCHIP: Self = Self(121);
    pub const X2APIC_API: Self = Self(129);
    pub const PRIVATE_MEM: Self = Self(224);
    pub const UNMAPPED_PRIVATE_MEM: Self = Self(240);
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

pub struct SevHandle {
    fd: OwnedFd,
}

impl SevHandle {
    pub fn new() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_SYNC)
            .open("/dev/sev")
            .context("failed to open /dev/sev")?;
        let fd = OwnedFd::from(file);
        Ok(Self { fd })
    }
}

#[repr(C)]
struct KvmSevCmd<'a, 'b> {
    pub payload: KvmSevCmdPayload<'a>,
    pub error: u32,
    pub sev_fd: Option<BorrowedFd<'b>>,
}

#[allow(clippy::enum_variant_names)]
#[repr(C, u32)]
// FIXME: Figure out which ones need `&mut T` and which ones need `&T`
pub enum KvmSevCmdPayload<'a> {
    KvmSevSnpInit { data: &'a mut KvmSnpInit } = 22,
    KvmSevSnpLaunchStart { data: &'a mut KvmSevSnpLaunchStart } = 23,
    KvmSevSnpLaunchUpdate { data: &'a mut KvmSevSnpLaunchUpdate } = 24,
    KvmSevSnpLaunchFinish { data: &'a mut KvmSevSnpLaunchFinish } = 25,
    KvmSevSnpDbgDecrypt { data: &'a mut KvmSevSnpDbg } = 28,
    KvmSevSnpDbgDecryptVmsa { data: &'a mut KvmSevSnpDbgVmsa } = 29,
}

#[repr(C)]
pub struct KvmSevDbg {
    src_uaddr: u64,
    dst_uaddr: u64,
    len: u32,
}

#[repr(C)]
pub struct KvmSnpInit {
    pub flags: KvmSnpInitFlags,
}

bitflags! {
    #[repr(transparent)]
    pub struct KvmSnpInitFlags: u64 {
        const KVM_SEV_SNP_RESTRICTED_INJET = 1 << 0;
        const KVM_SEV_SNP_RESTRICTED_TIMER_INJET = 1 << 1;
    }
}

#[repr(C)]
pub struct KvmSevSnpLaunchStart {
    /// Guest policy to use.
    pub policy: GuestPolicy,
    /// userspace address of migration agent
    pub ma_uaddr: u64,
    /// 1 if the migtation agent is enabled
    pub ma_en: u8,
    /// set IMI to 1.
    pub imi_en: u8,
    /// guest OS visible workarounds
    pub gosvw: [u8; 16],
    pub _pad: [u8; 6],
}

#[repr(C)]
pub struct KvmSevSnpLaunchUpdate {
    /// Guest page number to start from.
    pub start_gfn: u64,
    /// userspace address need to be encrypted
    pub uaddr: u64,
    /// length of memory region
    pub len: u32,
    /// 1 if memory is part of the IMI
    pub imi_page: u8,
    /// page type
    pub page_type: u8,
    /// VMPL3 permission mask
    pub vmpl3_perms: VmplPermissions,
    /// VMPL2 permission mask
    pub vmpl2_perms: VmplPermissions,
    /// VMPL1 permission mask
    pub vmpl1_perms: VmplPermissions,
}

#[repr(C)]
pub struct KvmSevSnpLaunchFinish {
    id_block_uaddr: u64,
    id_auth_uaddr: u64,
    id_block_en: u8,
    auth_key_en: u8,
    host_data: [u8; 32],
    _pad: [u8; 6],
}

#[repr(C)]
pub struct KvmSevSnpDbg {
    src_gfn: u64,
    dst_uaddr: u64,
}

#[repr(C)]
pub struct KvmSevSnpDbgVmsa {
    vcpu_id: u32,
    dst_uaddr: u64,
}

#[repr(C)]
pub struct KvmEncRegion {
    pub addr: u64,
    pub size: u64,
}

#[repr(C)]
pub struct KvmSetMemoryAttributes {
    address: u64,
    size: u64,
    attributes: KvmMemoryAttributes,
    flags: u64,
}

bitflags! {
    #[repr(transparent)]
    pub struct KvmMemoryAttributes: u64 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE = 1 << 2;
        const PRIVATE = 1 << 3;
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct KvmLapicState {
    pub regs: [u8; 0x400],
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

#[repr(C)]
pub struct KvmIrqchip {
    chip_id: u32,
    _pad: u32,
    chip: [u8; 512],
}

#[repr(C)]
pub struct KvmIrqRouting<T> {
    nr: u32,
    flags: u32,
    entries: T,
}

#[repr(C)]
pub struct KvmIrqRoutingEntry {
    gsi: u32,
    ty: u32,
    flags: u32,
    _pad: u32,
    irqchip: KvmIrqRoutingIrqchip,
}

impl KvmIrqRoutingEntry {
    pub fn to_irq_chip(gsi: u32, irqchip: u32, pin: u32) -> Self {
        Self {
            gsi,
            ty: 1,
            flags: 0,
            _pad: 0,
            irqchip: KvmIrqRoutingIrqchip {
                irqchip,
                pin,
                _pad: [0; 6],
            },
        }
    }
}

#[repr(C)]
pub struct KvmIrqRoutingIrqchip {
    irqchip: u32,
    pin: u32,
    _pad: [u32; 6],
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmIoapicState {
    pub base_address: u64,
    pub ioregsel: u32,
    pub id: u32,
    pub irr: u32,
    pub pad: u32,
    pub redirtbl: [KvmIoapicStateRedirTableEntry; 24],
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct KvmIoapicStateRedirTableEntry {
    pub vector: u8,
    pub flags: u16,
    _reserved: [u8; 4],
    pub dest_id: u8,
}

#[derive(Debug)]
#[repr(C)]
pub struct KvmIrqfd<'a> {
    fd: BorrowedFd<'a>,
    gsi: u32,
    flags: KvmIrqfdFlags,
    resamplefd: Option<BorrowedFd<'a>>,
    _pad: [u8; 16],
}

impl<'a> KvmIrqfd<'a> {
    pub fn new(
        fd: BorrowedFd<'a>,
        gsi: u32,
        resamplefd: Option<BorrowedFd<'a>>,
        deassign: bool,
    ) -> Self {
        let mut flags = KvmIrqfdFlags::empty();
        if deassign {
            flags |= KvmIrqfdFlags::DEASSIGN;
        }
        if resamplefd.is_some() {
            flags |= KvmIrqfdFlags::RESAMPLE;
        }

        Self {
            fd,
            gsi,
            flags,
            resamplefd,
            _pad: [0; 16],
        }
    }
}

bitflags! {
    pub struct KvmIrqfdFlags: u32 {
        const DEASSIGN = 1 << 0;
        const RESAMPLE = 1 << 1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Contiguous)]
#[repr(u32)]
pub enum KvmMpState {
    Runnable = 0,
    Uninitialized = 1,
    InitReceived = 2,
    Halted = 3,
    SipiReceived = 4,
    Stopped = 5,
    CheckStop = 6,
    Operating = 7,
    Load = 8,
    ApResetHold = 9,
    Suspended = 10,
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
