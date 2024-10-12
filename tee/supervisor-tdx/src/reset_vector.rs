use core::{arch::global_asm, mem::MaybeUninit};

use constants::MAX_APS_COUNT;
use x86_64::{registers::model_specific::FsBase, VirtAddr};

use crate::{main, per_cpu::PerCpu};

pub const STACK_SIZE: usize = 16;

global_asm!(
    include_str!("reset_vector.s"),
    MAX_APS_COUNT = const MAX_APS_COUNT,
    STACK_SIZE = const STACK_SIZE * 0x1000,
);

#[export_name = "_start"]
extern "sysv64" fn premain(vcpu_index: usize) {
    // Setup a `PerCpu` instance for the current cpu.
    let mut per_cpu = MaybeUninit::uninit();
    let ptr = per_cpu.as_mut_ptr();
    per_cpu.write(PerCpu::new(ptr, vcpu_index));
    FsBase::write(VirtAddr::from_ptr(ptr));

    main();
}
