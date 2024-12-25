use core::ops::Range;

use x86_64::{
    structures::paging::{PageSize, PhysFrame, Size1GiB, Size2MiB},
    PhysAddr,
};

const fn addr<S>(addr: u64) -> PhysFrame<S>
where
    S: PageSize,
{
    let addr = PhysAddr::new(addr);
    let Ok(frame) = PhysFrame::from_start_address(addr) else {
        unreachable!()
    };
    frame
}

const fn addr_range<S>(start: u64, end: u64) -> Range<PhysFrame<S>>
where
    S: PageSize,
{
    assert!(start < end);
    addr(start)..addr(end + 1)
}

pub mod kernel {
    use super::*;

    // The segments of the kernel binary:
    pub const RESET_VECTOR: PhysFrame<Size2MiB> = addr(0x10040000000);
    pub const TEXT: Range<PhysFrame<Size2MiB>> = addr_range(0x10040200000, 0x10040ffffff);
    pub const RODATA: Range<PhysFrame<Size2MiB>> = addr_range(0x10080000000, 0x10080ffffff);
    pub const DATA: Range<PhysFrame<Size2MiB>> = addr_range(0x100c0000000, 0x100c0ffffff);
    pub const STACK: Range<PhysFrame<Size2MiB>> = addr_range(0x10140000000, 0x10140ffffff);

    const fn shadow_addr(addr: u64) -> PhysFrame<Size2MiB> {
        const KASAN_SHADOW_SCALE_SHIFT: u64 = 3;
        /// Note that this is the physical address.
        const KASAN_SHADOW_OFFSET: u64 = 0x180_0000_0000;

        let offset = addr - 0xffff_8000_0000_0000;
        let scaled = offset >> KASAN_SHADOW_SCALE_SHIFT;
        let addr = scaled + KASAN_SHADOW_OFFSET;
        let Ok(frame) = PhysFrame::from_start_address(PhysAddr::new(addr)) else {
            panic!()
        };
        frame
    }

    // The shadow memory segments of the kernel binary (for KASAN):
    pub const TEXT_SHADOW: PhysFrame<Size2MiB> = shadow_addr(0xffff800000000000);
    pub const RODATA_SHADOW: PhysFrame<Size2MiB> = shadow_addr(0xffff800001000000);
    pub const DATA_SHADOW: PhysFrame<Size2MiB> = shadow_addr(0xffff800002000000);
    pub const STACK_SHADOW: PhysFrame<Size2MiB> = shadow_addr(0xffff800004000000);
    pub const LOG_BUFFER_SHADOW: PhysFrame<Size2MiB> = shadow_addr(0xffff800007000000);
    pub const INIT_FILE_SHADOW: PhysFrame<Size2MiB> = shadow_addr(0xffff809000000000);
    pub const INPUT_FILE_SHADOW: PhysFrame<Size2MiB> = shadow_addr(0xffff80a000000000);

    pub const LOG_BUFFER: PhysFrame<Size2MiB> = addr(0x90000000000);
}

pub mod supervisor {
    use super::*;

    // The segments of the supervisor-snp binary.
    pub mod snp {
        use super::*;

        pub const CPUID_PAGE: PhysFrame<Size2MiB> = addr(0xffa00000);
        pub const PAGETABLES: PhysFrame<Size2MiB> = addr(0xffc00000);
        pub const RESET_VECTOR: PhysFrame<Size2MiB> = addr(0xffe00000);
        pub const TEXT: Range<PhysFrame<Size2MiB>> = addr_range(0x100000000, 0x100ffffff);
        pub const RODATA: Range<PhysFrame<Size2MiB>> = addr_range(0x140000000, 0x140ffffff);
        pub const DATA: Range<PhysFrame<Size2MiB>> = addr_range(0x180000000, 0x180ffffff);
        pub const STACK: PhysFrame<Size2MiB> = addr(0x1c0000000);
        pub const SECRETS: PhysFrame<Size2MiB> = addr(0x200000000);
        pub const SHADOW_STACK: PhysFrame<Size2MiB> = addr(0x240000000);
        pub const SHARED: PhysFrame<Size2MiB> = addr(0x280000000);
        pub const VMSAS: PhysFrame<Size2MiB> = addr(0x2c0000000);
    }

    // The segments of the supervisor-tdx binary.
    pub mod tdx {
        use super::*;

        pub const PAGETABLES: PhysFrame<Size2MiB> = addr(0xffc00000);
        pub const RESET_VECTOR: PhysFrame<Size2MiB> = addr(0xffe00000);
        pub const TEXT: Range<PhysFrame<Size2MiB>> = addr_range(0x40000000, 0x40ffffff);
        pub const RODATA: Range<PhysFrame<Size2MiB>> = addr_range(0x41000000, 0x41ffffff);
        pub const DATA: Range<PhysFrame<Size2MiB>> = addr_range(0x42000000, 0x42ffffff);
        pub const STACK: PhysFrame<Size2MiB> = addr(0x43200000);
        pub const SHARED: PhysFrame<Size2MiB> = addr(0x44000000);
        pub const KERNEL_ELF_HEADER: PhysFrame<Size2MiB> = addr(0x08000000000);
    }

    pub const LOG_BUFFER: PhysFrame<Size2MiB> = addr(0x90000200000);
}

// 64 gibibytes of dynamic physical memory that can be hot-plugged and hot-unplugged.
pub const DYNAMIC: Range<PhysFrame<Size1GiB>> = addr_range(0x020000000000, 0x20fffffffff);
pub const DYNAMIC_2MIB: Range<PhysFrame<Size2MiB>> = addr_range(
    DYNAMIC.start.start_address().as_u64(),
    DYNAMIC.end.start_address().as_u64() - 1,
);
pub const INIT_FILE: Range<PhysFrame<Size1GiB>> =
    addr_range(0x0000_0300_0000_0000, 0x0000_030f_ffff_ffff);
pub const INPUT_FILE: Range<PhysFrame<Size1GiB>> =
    addr_range(0x0000_0400_0000_0000, 0x0000_040f_ffff_ffff);

// Regions for kernel-guest communication during profiling.
pub const PROFILER_CONTROL: Range<PhysFrame<Size2MiB>> = addr_range(0x80000000000, 0x80000ffffff);
pub const PROFILER_BUFFER: PhysFrame<Size1GiB> = addr(0x80040000000);
