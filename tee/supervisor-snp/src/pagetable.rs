use core::{cell::SyncUnsafeCell, ptr::NonNull};

use bytemuck::AnyBitPattern;
use constants::physical_address::{
    self,
    supervisor::{snp::*, LOG_BUFFER},
    DYNAMIC, INPUT_FILE,
};
use static_page_tables::{flags, StaticPageTable, StaticPd, StaticPdp, StaticPml4, StaticPt};
use volatile::{
    access::{ReadOnly, WriteOnly},
    VolatilePtr,
};
use x86_64::structures::paging::PhysFrame;

#[link_section = ".pagetables"]
#[export_name = "pml4"]
static PML4: StaticPml4 = {
    let mut page_table = StaticPageTable::new();
    page_table.set_table(0, &PDP_0, flags!(C | WRITE));
    page_table.set_table(64, &PDP_64, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table.set_table(128, &PDP_128, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table
};

#[link_section = ".pagetables"]
static PDP_0: StaticPdp = {
    let mut page_table = StaticPageTable::new();
    page_table.set_table(1, &PD_0_1, flags!(C | WRITE));
    page_table.set_table(3, &PD_0_3, flags!(C | WRITE));
    page_table.set_page_range(64, INPUT_FILE, flags!(EXECUTE_DISABLE));
    page_table.set_page_range(128, INPUT_FILE, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table
};

#[link_section = ".pagetables"]
static PD_0_1: StaticPd = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page_range(0, TEXT, flags!(C));
    page_table.set_page_range(8, RODATA, flags!(C | EXECUTE_DISABLE));
    page_table.set_page_range(16, DATA, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table.set_page(25, STACK, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table.set_page(27, SECRETS, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table.set_page(29, SHADOW_STACK, flags!(C | EXECUTE_DISABLE | DIRTY));
    page_table.set_page(32, SHARED, flags!(WRITE | EXECUTE_DISABLE));
    page_table.set_table(34, &PT_0_1_34, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table.set_page(36, LOG_BUFFER, flags!(WRITE | EXECUTE_DISABLE));
    page_table.set_page(38, VMSAS, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table
};

#[link_section = ".pagetables"]
static PT_0_1_34: StaticPt = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page_range(
        0,
        physical_address::SUPERVISOR_SERVICES,
        flags!(C | WRITE | EXECUTE_DISABLE),
    );
    page_table
};

#[link_section = ".pagetables"]
static PD_0_3: StaticPd = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page(509, CPUID_PAGE, flags!(C | EXECUTE_DISABLE));
    page_table.set_page(510, PAGETABLES, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table.set_page(511, RESET_VECTOR, flags!(C));
    page_table
};

#[link_section = ".pagetables"]
static PDP_64: StaticPdp = {
    let mut page_table = StaticPageTable::new();
    page_table.set_page_range(0, DYNAMIC, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table
};

#[link_section = ".pagetables"]
static PDP_128: StaticPdp = {
    let mut page_table = StaticPageTable::new();
    page_table.set_table(0, &PD_128_0, flags!(C | WRITE));
    page_table
};

#[link_section = ".pagetables"]
static PD_128_0: StaticPd = {
    let mut page_table = StaticPageTable::new();
    page_table.set_table(0, &PT_128_0_0, flags!(C | WRITE | EXECUTE_DISABLE));
    page_table
};

#[link_section = ".pagetables"]
static PT_128_0_0: StaticPt = StaticPageTable::new();

/// Create static variables that are shared with the host.
#[macro_export]
macro_rules! shared {
    ($(static $name:ident : $ty:ty = $init:expr;)*) => {
        $(
            #[link_section = ".shared"]
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
        let ptr: *const Self = self;
        let offset_in_shared = ptr as u64 - 0x44000000;
        let pa = SHARED.start_address() + offset_in_shared;
        PhysFrame::from_start_address(pa).unwrap()
    }

    pub fn as_read_only_ptr(&self) -> VolatilePtr<'_, T, ReadOnly>
    where
        T: AnyBitPattern,
    {
        let ptr = NonNull::from(&self.0).cast();
        unsafe { VolatilePtr::new_read_only(ptr) }
    }

    pub fn as_write_only_ptr(&self) -> VolatilePtr<'_, T, WriteOnly> {
        let ptr = NonNull::from(&self.0).cast();
        unsafe { VolatilePtr::new_restricted(WriteOnly, ptr) }
    }
}
