use core::{cell::SyncUnsafeCell, ptr::NonNull};

use constants::{
    MAX_APS_COUNT,
    physical_address::{
        INIT_FILE, INPUT_FILE,
        supervisor::{LOG_BUFFER, tdx::*},
    },
};
use static_page_tables::{StaticPageTable, StaticPd, StaticPdp, StaticPml4, StaticPt, flags};
use volatile::{VolatilePtr, access::WriteOnly};
use x86_64::{
    PhysAddr,
    structures::paging::{PageSize, PhysFrame, Size4KiB},
};

use crate::reset_vector::STACK_SIZE;

#[unsafe(link_section = ".pagetables")]
#[unsafe(export_name = "pml4")]
static PML4: StaticPml4 = {
    let mut page_table = StaticPageTable::new();
    page_table.set_table(0, &PDP_0, flags!(WRITE));
    page_table
};

#[unsafe(link_section = ".pagetables")]
static PDP_0: StaticPdp = {
    let mut page_table = StaticPageTable::new();
    page_table.set_table(1, &PD_0_1, flags!(WRITE));
    page_table.set_table(3, &PD_0_3, flags!(WRITE));
    page_table.set_page_range(64, INPUT_FILE, flags!(S | EXECUTE_DISABLE));
    page_table.set_page_range(128, INPUT_FILE, flags!(WRITE | EXECUTE_DISABLE));
    page_table.set_page_range(192, INIT_FILE, flags!(EXECUTE_DISABLE));
    page_table
};

#[unsafe(link_section = ".pagetables")]
static PD_0_1: StaticPd = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page_range(0, TEXT, flags!());
    page_table.set_page_range(8, RODATA, flags!(EXECUTE_DISABLE));
    page_table.set_page_range(16, DATA, flags!(WRITE | EXECUTE_DISABLE));
    page_table.set_table_range(25, &PT_0_1_25, flags!(WRITE | EXECUTE_DISABLE));
    page_table.set_page(32, SHARED, flags!(S | WRITE | EXECUTE_DISABLE));
    page_table.set_page(36, LOG_BUFFER, flags!(S | WRITE | EXECUTE_DISABLE));
    page_table.set_page(40, KERNEL_ELF_HEADER, flags!(EXECUTE_DISABLE));
    page_table
};

const NUM_STACK_PAGE_TABLES: usize = (STACK_SIZE * MAX_APS_COUNT as usize).div_ceil(512);

#[unsafe(link_section = ".pagetables")]
static PT_0_1_25: [StaticPt; NUM_STACK_PAGE_TABLES] = {
    let mut page_tables = [const { StaticPageTable::new() }; NUM_STACK_PAGE_TABLES];

    let mut i = 0;
    while i < NUM_STACK_PAGE_TABLES {
        let mut page_table = StaticPageTable::new();

        let mut j = 0;
        while j < 512 {
            let combined_index = i * 512 + j;
            let addr = PhysFrame::containing_address(PhysAddr::new(
                STACK.start_address().as_u64() + Size4KiB::SIZE * combined_index as u64,
            ));
            let flags = if combined_index % STACK_SIZE == 0 {
                flags!(DIRTY | EXECUTE_DISABLE)
            } else {
                flags!(WRITE | EXECUTE_DISABLE)
            };
            page_table.set_page(j, addr, flags);
            j += 1;
        }

        page_tables[i] = page_table;
        i += 1;
    }

    page_tables
};

#[unsafe(link_section = ".pagetables")]
static PD_0_3: StaticPd = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page(511, RESET_VECTOR, flags!());
    page_table
};

/// Create static variables that are shared with the host.
#[macro_export]
macro_rules! shared {
    ($(static $name:ident : $ty:ty = $init:expr;)*) => {
        $(
            #[unsafe(link_section = ".shared")]
            static $name: $crate::pagetable::Shared<$ty> = {
                let init: $ty = $init;
                unsafe { $crate::pagetable::Shared::new(init) }
            };
        )*
    };
}

/// A chunk of memory that's shared with the host.
#[repr(C, align(4096))]
pub struct Shared<T>(SyncUnsafeCell<T>);

impl<T> Shared<T> {
    /// This is an internal implementation detail of [`shared!`].
    ///
    /// # Safety
    ///
    /// The caller has to ensure that the `Shared<T>` instance is stored in the `.shared` section.
    pub const unsafe fn new(value: T) -> Self {
        Self(SyncUnsafeCell::new(value))
    }

    pub fn frame(&self) -> PhysFrame {
        let addr = PhysAddr::new(core::ptr::from_ref(self) as u64);
        PhysFrame::from_start_address(addr).unwrap()
    }

    pub fn as_write_only_ptr(&self) -> VolatilePtr<'_, T, WriteOnly> {
        let ptr = NonNull::from(&self.0).cast();
        unsafe { VolatilePtr::new_restricted(WriteOnly, ptr) }
    }
}
