use alloc::sync::Arc;
use core::{
    arch::asm,
    cell::{Cell, OnceCell, RefCell},
    mem::offset_of,
    ops::Deref,
    ptr::{addr_of, null_mut},
    sync::atomic::{AtomicUsize, Ordering},
};

use constants::{ApIndex, MAX_APS_COUNT};
use x86_64::{
    VirtAddr,
    registers::segmentation::{GS, Segment64},
    structures::{gdt::GlobalDescriptorTable, tss::TaskStateSegment},
};

use crate::{
    exception::InterruptData,
    memory::{frame, pagetable::PagetablesAllocations},
    rt::SchedulerData,
    user::syscall::cpu_state::{KernelRegisters, RawExit, Registers},
};

static COUNT: AtomicUsize = AtomicUsize::new(0);
static mut STORAGE: [PerCpu; MAX_APS_COUNT as usize] =
    [const { PerCpu::new() }; MAX_APS_COUNT as usize];

#[repr(align(64))]
pub struct PerCpu {
    this: *mut PerCpu,
    sync: PerCpuSync,
    pub kernel_registers: Cell<KernelRegisters>,
    pub new_userspace_registers: Cell<Registers>,
    pub tss: OnceCell<TaskStateSegment>,
    pub gdt: OnceCell<GlobalDescriptorTable>,
    pub exit_with_sysret: Cell<bool>,
    pub exit: Cell<RawExit>,
    pub vector: Cell<u8>,
    pub error_code: Cell<u64>,
    pub last_pagetables: RefCell<Option<Arc<PagetablesAllocations>>>,
    pub private_allocator_state: RefCell<Option<frame::PrivateState>>,
    pub scheduler_data: SchedulerData,
}

impl PerCpu {
    pub const fn new() -> Self {
        Self {
            this: null_mut(),
            sync: PerCpuSync::new(),
            kernel_registers: Cell::new(KernelRegisters::ZERO),
            new_userspace_registers: Cell::new(Registers::ZERO),
            tss: OnceCell::new(),
            gdt: OnceCell::new(),
            exit_with_sysret: Cell::new(false),
            exit: Cell::new(RawExit::Syscall),
            vector: Cell::new(0),
            error_code: Cell::new(0),
            last_pagetables: RefCell::new(None),
            private_allocator_state: RefCell::new(None),
            scheduler_data: SchedulerData::new(),
        }
    }

    #[inline]
    pub fn get_raw() -> *const Self {
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
        addr as *const Self
    }

    #[track_caller]
    pub fn get() -> &'static Self {
        // Make sure that `PerCpu` can't get be used in an interrupt handler.
        // Interrupt handler are considered additional threads and PerCpu is
        // not thread-safe.
        PerCpuSync::get().interrupt_data.check_max_interrupt(None);

        let ptr = Self::get_raw();
        unsafe { &*ptr }
    }

    pub fn init() {
        let addr = GS::read_base();
        assert_eq!(addr, VirtAddr::new(0), "GS segment was already initialized");

        let idx = COUNT.fetch_add(1, Ordering::SeqCst);
        let ptr = unsafe { &mut STORAGE[idx] };
        ptr.this = ptr;
        ptr.sync.idx = ApIndex::new(u8::try_from(idx).unwrap());

        let addr = VirtAddr::from_ptr(ptr);
        unsafe {
            GS::write_base(addr);
        }
    }
}

// Make it easy to access the `Sync` data as well.
impl Deref for PerCpu {
    type Target = PerCpuSync;

    fn deref(&self) -> &Self::Target {
        &self.sync
    }
}

/// Data associated with a CPU that's safe to access from another thread e.g.
/// an interrupt handler.
pub struct PerCpuSync {
    pub idx: ApIndex,
    pub interrupt_data: InterruptData,
}

impl PerCpuSync {
    pub const fn new() -> Self {
        // Assert that `Self` is indeed Sync.
        const fn assert_sync<T: Sync>() {}
        assert_sync::<Self>();

        Self {
            idx: ApIndex::new(0),
            interrupt_data: InterruptData::new(),
        }
    }

    #[inline]
    pub fn get() -> &'static Self {
        let raw = PerCpu::get_raw();
        let raw = unsafe { addr_of!((*raw).sync) };
        unsafe { &*raw }
    }
}
