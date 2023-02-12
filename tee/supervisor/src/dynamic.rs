//! FIXME: This performs really poorly, fix this.

use core::{
    arch::asm,
    num::NonZeroU32,
    sync::atomic::{AtomicU8, Ordering},
};

use bit_field::BitField;
use constants::{physical_address::DYNAMIC, MEMORY_PORT};
use snp_types::VmplPermissions;
use x86_64::{
    instructions::port::PortWriteOnly,
    structures::paging::{
        page::NotGiantPageSize, FrameAllocator, FrameDeallocator, Page, PhysFrame, Size2MiB,
        Size4KiB,
    },
    PhysAddr,
};

use crate::pagetable::TEMPORARY_MAPPER;

const SLOTS: usize = 1 << 15;
const BITMAP_SIZE: usize = SLOTS / 8;

pub static HOST_ALLOCTOR: HostAllocator = HostAllocator::new();

pub struct HostAllocator {
    bitmap: [AtomicU8; BITMAP_SIZE],
}

impl HostAllocator {
    pub const fn new() -> Self {
        Self {
            bitmap: [const { AtomicU8::new(0) }; BITMAP_SIZE],
        }
    }

    fn allocate_slot_id(&self) -> Option<u16> {
        self.bitmap.iter().enumerate().find_map(|(i, bitmap)| {
            let mut byte = bitmap.load(Ordering::SeqCst);
            loop {
                // Find an unset bit.
                let bit = (0..8).find(|&i| !byte.get_bit(i))?;

                // Set the bit.
                byte = bitmap.fetch_or(1 << bit, Ordering::SeqCst);

                // Check if the bit was just set by another core.
                if byte.get_bit(bit) {
                    continue;
                }

                // Success!
                return Some(u16::try_from(i * 8 + bit).unwrap());
            }
        })
    }

    unsafe fn deallocate_slot_id(&self, slot_id: u16) {
        let byte_idx = usize::from(slot_id / 8);
        let bit_idx = usize::from(slot_id % 8);

        let mut mask = !0;
        mask.set_bit(bit_idx, false);

        let prev = self.bitmap[byte_idx].fetch_and(mask, Ordering::SeqCst);
        assert!(prev.get_bit(bit_idx));
    }
}

unsafe impl FrameAllocator<Size2MiB> for &'_ HostAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        // Allocate a slot id.
        let slot_id = self.allocate_slot_id()?;

        let base = PhysFrame::<Size2MiB>::containing_address(PhysAddr::new(DYNAMIC.start()));
        let frame = base + u64::from(slot_id);

        // Tell the host to enable the slot.
        unsafe {
            update_slot_status(slot_id, true);
        }

        // Create a temporary mapping.
        let mut mapper = TEMPORARY_MAPPER.borrow_mut();
        let mapping = mapper.create_temporary_mapping_2mib(frame);

        // Validate the memory.
        unsafe {
            mapping.pvalidate(true);
        }

        Some(frame)
    }
}

impl FrameDeallocator<Size2MiB> for &'_ HostAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size2MiB>) {
        assert!(DYNAMIC.contains(frame.start_address().as_u64()));
        let base = PhysFrame::<Size2MiB>::containing_address(PhysAddr::new(DYNAMIC.start()));
        let slot_id = u16::try_from(frame - base).unwrap();

        // Create a temporary mapping.
        let mut mapper = TEMPORARY_MAPPER.borrow_mut();
        let mapping = mapper.create_temporary_mapping_2mib(frame);

        // Reset the VMPL permissions.
        unsafe {
            mapping.rmpadjust(1, VmplPermissions::empty(), false);
            mapping.rmpadjust(2, VmplPermissions::empty(), false);
            mapping.rmpadjust(3, VmplPermissions::empty(), false);
        }

        // Validate the memory.
        unsafe {
            mapping.pvalidate(false);
        }

        // Tell the host to disable the slot.
        update_slot_status(slot_id, false);

        // Deallocate a slot id.
        self.deallocate_slot_id(slot_id);
    }
}

pub unsafe fn update_slot_status(slot_id: u16, enabled: bool) {
    let mut request: u32 = 0;
    request.set_bits(0..15, u32::from(slot_id));
    request.set_bit(15, enabled);
    PortWriteOnly::new(MEMORY_PORT).write(request);
}

pub unsafe fn pvalidate_2mib(page: Page<Size2MiB>, valid: bool) {
    let res = unsafe { pvalidate(page, valid) };
    match res {
        Ok(changed) => assert!(changed),
        Err(code) if code.get() == 6 => {
            for i in 0..512 {
                let page = Page::<Size4KiB>::from_start_address(page.start_address()).unwrap() + i;
                let res = unsafe { pvalidate(page, valid) };
                assert_eq!(res, Ok(true));
            }
        }
        Err(code) => panic!("failed to validate memory {code}"),
    }
}

pub unsafe fn pvalidate<S>(page: Page<S>, valid: bool) -> Result<bool, NonZeroU32>
where
    S: NotGiantPageSize,
{
    let is_giant_page = S::SIZE != 0x1000;
    let return_code: u64;
    let unchanged: u32;

    asm!(
        "pvalidate",
        "setc cl",
        inout("rax") page.start_address().as_u64() => return_code,
        inout("ecx") u32::from(is_giant_page) => unchanged,
        in("edx") u32::from(valid),
        options(nostack),
    );

    let return_code = return_code as u32;
    if let Some(return_code) = NonZeroU32::new(return_code) {
        Err(return_code)
    } else {
        Ok(unchanged == 0)
    }
}

pub unsafe fn rmpadjust_2mib(
    page: Page<Size2MiB>,
    target_vmpl: u8,
    target_perm_mask: VmplPermissions,
    vmsa: bool,
) {
    let res = unsafe { rmpadjust(page, target_vmpl, target_perm_mask, vmsa) };
    match res {
        Ok(()) => {}
        Err(code) if code.get() == 6 => {
            for i in 0..512 {
                let page = Page::<Size4KiB>::from_start_address(page.start_address()).unwrap() + i;
                let res = unsafe { rmpadjust(page, target_vmpl, target_perm_mask, vmsa) };
                res.unwrap();
            }
        }
        Err(code) => panic!("failed to validate memory {code}"),
    }
}

pub unsafe fn rmpadjust<S>(
    page: Page<S>,
    target_vmpl: u8,
    target_perm_mask: VmplPermissions,
    vmsa: bool,
) -> Result<(), NonZeroU32>
where
    S: NotGiantPageSize,
{
    let is_giant_page = S::SIZE != 0x1000;

    let mut rdx = 0;
    rdx.set_bits(0..=7, u64::from(target_vmpl));
    rdx.set_bits(8..=15, u64::from(target_perm_mask.bits()));
    rdx.set_bit(16, vmsa);

    let return_code: u64;

    asm!(
        "rmpadjust",
        "setc cl",
        inout("rax") page.start_address().as_u64() => return_code,
        in("ecx") u32::from(is_giant_page),
        in("rdx") rdx,
        options(nostack),
    );

    let return_code = return_code as u32;
    if let Some(return_code) = NonZeroU32::new(return_code) {
        Err(return_code)
    } else {
        Ok(())
    }
}
