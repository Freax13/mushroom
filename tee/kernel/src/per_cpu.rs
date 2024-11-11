use core::{
    arch::asm,
    cell::{Cell, OnceCell, RefCell},
    mem::offset_of,
    ptr::null_mut,
    sync::atomic::{AtomicUsize, Ordering},
};

use alloc::sync::Arc;
use constants::{ApIndex, MAX_APS_COUNT};
use x86_64::{
    registers::segmentation::{Segment64, GS},
    structures::{gdt::GlobalDescriptorTable, paging::Page, tss::TaskStateSegment},
    VirtAddr,
};

use crate::{
    memory::{frame, pagetable::PagetablesAllocations},
    user::process::syscall::cpu_state::{KernelRegisters, RawExit, Registers},
};

static COUNT: AtomicUsize = AtomicUsize::new(0);
static mut STORAGE: [PerCpu; MAX_APS_COUNT as usize] =
    [const { PerCpu::new() }; MAX_APS_COUNT as usize];

pub struct PerCpu {
    this: *mut PerCpu,
    pub idx: ApIndex,
    pub kernel_registers: Cell<KernelRegisters>,
    pub new_userspace_registers: Cell<Registers>,
    pub temporary_mapping: OnceCell<RefCell<Page>>,
    pub tss: OnceCell<TaskStateSegment>,
    pub gdt: OnceCell<GlobalDescriptorTable>,
    pub int0x80_handler: Cell<u64>,
    pub exit_with_sysret: Cell<bool>,
    pub exit: Cell<RawExit>,
    pub vector: Cell<u8>,
    pub error_code: Cell<u64>,
    pub last_pagetables: RefCell<Option<Arc<PagetablesAllocations>>>,
    pub private_allocator_state: RefCell<Option<frame::PrivateState>>,
}

impl PerCpu {
    pub const fn new() -> Self {
        Self {
            this: null_mut(),
            idx: ApIndex::new(0),
            kernel_registers: Cell::new(KernelRegisters::ZERO),
            new_userspace_registers: Cell::new(Registers::ZERO),
            temporary_mapping: OnceCell::new(),
            tss: OnceCell::new(),
            gdt: OnceCell::new(),
            int0x80_handler: Cell::new(0),
            exit_with_sysret: Cell::new(false),
            exit: Cell::new(RawExit::Syscall),
            vector: Cell::new(0),
            error_code: Cell::new(0),
            last_pagetables: RefCell::new(None),
            private_allocator_state: RefCell::new(None),
        }
    }

    pub fn get() -> &'static Self {
        let addr: u64;
        unsafe {
            // SAFETY: If the GS segment wasn't programmed yet, this will cause
            // a page fault, which is a safe thing to do.
            asm!(
                "mov {}, gs:[{THIS_OFFSET}]",
                out(reg) addr,
                THIS_OFFSET = const offset_of!(Self, this),
                options(pure, nomem, preserves_flags, nostack),
            );
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
        ptr.idx = ApIndex::new(u8::try_from(idx).unwrap());

        let addr = VirtAddr::from_ptr(ptr);
        unsafe {
            GS::write_base(addr);
        }
    }
}
