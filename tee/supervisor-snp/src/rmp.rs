use core::{arch::asm, num::NonZeroU32};

use bit_field::BitField;
use snp_types::VmplPermissions;
use x86_64::structures::paging::{page::NotGiantPageSize, Page, Size2MiB, Size4KiB};

/// Update the validation status of a frame.
///
/// # Safety
///
/// This is inherently dangerous.
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

/// Update the validation status of a frame.
///
/// # Safety
///
/// This is inherently dangerous.
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

/// Adjust the permissions of a frame at a given VMPL.
///
/// # Safety
///
/// This is inherently dangerous.
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

/// Adjust the permissions of a frame at a given VMPL.
///
/// # Safety
///
/// This is inherently dangerous.
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
