use core::{
    arch::asm,
    cell::{Cell, OnceCell, RefCell},
    ptr::null_mut,
    sync::atomic::{AtomicUsize, Ordering},
};

use alloc::sync::Arc;
use constants::MAX_APS_COUNT;
use x86_64::{
    registers::segmentation::{Segment64, GS},
    structures::{gdt::GlobalDescriptorTable, paging::Page, tss::TaskStateSegment},
    VirtAddr,
};

use crate::{
    memory::pagetable::ReservedFrameStorage,
    user::process::{
        memory::VirtualMemory,
        syscall::cpu_state::{KernelRegisters, RawExit, Registers},
    },
};

static COUNT: AtomicUsize = AtomicUsize::new(0);
static mut STORAGE: [PerCpu; MAX_APS_COUNT as usize] =
    [const { PerCpu::new() }; MAX_APS_COUNT as usize];

#[repr(C)]
pub struct PerCpu {
    this: *mut PerCpu,
    pub idx: usize,
    pub kernel_registers: Cell<KernelRegisters>,
    pub new_userspace_registers: Cell<Registers>,
    pub reserved_frame_storage: RefCell<ReservedFrameStorage>,
    pub temporary_mapping: OnceCell<RefCell<Page>>,
    pub tss: OnceCell<TaskStateSegment>,
    pub gdt: OnceCell<GlobalDescriptorTable>,
    pub current_virtual_memory: Cell<Option<Arc<VirtualMemory>>>,
    pub int0x80_handler: Cell<u64>,
    pub exit_with_sysret: Cell<bool>,
    pub userspace_exception_exit_point: Cell<u64>,
    pub exit: Cell<RawExit>,
}

impl PerCpu {
    pub const fn new() -> Self {
        Self {
            this: null_mut(),
            idx: 0,
            kernel_registers: Cell::new(KernelRegisters::ZERO),
            new_userspace_registers: Cell::new(Registers::ZERO),
            reserved_frame_storage: RefCell::new(ReservedFrameStorage::new()),
            temporary_mapping: OnceCell::new(),
            tss: OnceCell::new(),
            gdt: OnceCell::new(),
            current_virtual_memory: Cell::new(None),
            int0x80_handler: Cell::new(0),
            exit_with_sysret: Cell::new(false),
            userspace_exception_exit_point: Cell::new(0),
            exit: Cell::new(RawExit::Syscall),
        }
    }

    pub fn get() -> &'static Self {
        let addr: u64;
        unsafe {
            // SAFETY: If the GS segment wasn't programmed yet, this will cause
            // a page fault, which is a safe thing to do.
            asm!("mov {}, gs:[0]", out(reg) addr, options(pure, nomem, preserves_flags, nostack));
        }
        let ptr = addr as *const Self;
        unsafe { &*ptr }
    }

    pub fn init() {
        let addr = GS::read_base();
        assert_eq!(addr, VirtAddr::new(0), "GS segment was already initialized");

        let idx = COUNT.fetch_add(1, Ordering::SeqCst);
        let ptr = unsafe { &mut STORAGE[idx] };
        ptr.this = ptr;
        ptr.idx = idx;

        let addr = VirtAddr::from_ptr(ptr);
        unsafe {
            GS::write_base(addr);
        }
    }
}
