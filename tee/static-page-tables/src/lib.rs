#![no_std]
#![feature(const_mut_refs, const_unsafecell_get_mut, const_ptr_is_null)]

use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    ops::Range,
    ptr::{null, null_mut},
};

use x86_64::{
    structures::paging::{PageSize, PhysFrame, Size1GiB, Size2MiB, Size4KiB},
    PhysAddr,
};

pub type StaticPml4 = StaticPageTable<Level4>;
pub type StaticPdp = StaticPageTable<Level3>;
pub type StaticPd = StaticPageTable<Level2>;
pub type StaticPt = StaticPageTable<Level1>;

#[repr(C, align(4096))]
pub struct StaticPageTable<L> {
    entries: [UnsafeCell<*const ()>; 512],
    _marker: PhantomData<L>,
}

impl<L> StaticPageTable<L>
where
    L: Level,
{
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            entries: [const { UnsafeCell::new(null()) }; 512],
            _marker: PhantomData,
        }
    }

    const fn set_entry(&mut self, index: usize, entry: *const ()) {
        assert!(
            self.entries[index].get_mut().is_null(),
            "entry is already in use"
        );
        self.entries[index] = UnsafeCell::new(entry);
    }

    /// Add a new entry pointing to a table on the next lower level.
    pub const fn set_table(
        &mut self,
        index: usize,
        next: &'static StaticPageTable<L::Next>,
        mut flags: Flags,
    ) where
        L: ParentLevel,
    {
        flags.0 |= Flags::PRESENT.0;
        self.set_entry(
            index,
            (next as *const StaticPageTable<L::Next> as *const ()).wrapping_byte_add(flags.0),
        );
    }

    /// Add one or more entries pointing to tables on the next lower level.
    pub const fn set_table_range(
        &mut self,
        mut index: usize,
        mut next: &'static [StaticPageTable<L::Next>],
        mut flags: Flags,
    ) where
        L: ParentLevel,
    {
        flags.0 |= Flags::PRESENT.0;

        while let Some((first, rest)) = next.split_first() {
            self.set_entry(
                index,
                (first as *const StaticPageTable<L::Next> as *const ()).wrapping_byte_add(flags.0),
            );
            index += 1;
            next = rest;
        }
    }

    /// Add a new entry pointing to a page.
    pub const fn set_page(&mut self, index: usize, addr: PhysFrame<L::Size>, mut flags: Flags)
    where
        L: PageLevel,
    {
        flags.0 |= Flags::PRESENT.0;
        if L::HUGE {
            flags.0 |= Flags::HUGE.0;
        }

        self.set_entry(
            index,
            (addr.start_address().as_u64() as *const ()).wrapping_byte_add(flags.0),
        );
    }

    /// Add one or more entries pointing to a contigous pages.
    pub const fn set_page_range(
        &mut self,
        mut index: usize,
        mut addr: Range<PhysFrame<L::Size>>,
        flags: Flags,
    ) where
        L: PageLevel,
    {
        while addr.start.start_address().as_u64() != addr.end.start_address().as_u64() {
            self.set_page(index, addr.start, flags);

            index += 1;
            addr.start = PhysFrame::containing_address(PhysAddr::new(
                addr.start.start_address().as_u64() + <L::Size>::SIZE,
            ));
        }
    }

    /// Clear an entry.
    pub const fn clear_entry(&mut self, index: usize) {
        self.entries[index] = UnsafeCell::new(null_mut());
    }

    /// Clone a page table.
    ///
    /// # Safety
    ///
    /// This method must only be called at compile-time.
    pub const unsafe fn clone(&self) -> Self {
        let mut this = Self::new();

        let mut i = 0;
        while i < 512 {
            this.entries[i] = UnsafeCell::new(unsafe {
                // SAFETY: We never create mutable references to the entries at
                // compile time, so reading can't race.
                self.entries[i].get().read()
            });
            i += 1;
        }

        this
    }
}

impl StaticPageTable<Level4> {
    /// Add a recursive page table entry.
    pub const fn set_recursive_table(
        &mut self,
        index: usize,
        table: &'static Self,
        mut flags: Flags,
    ) {
        flags.0 |= Flags::PRESENT.0 | Flags::EXECUTE_DISABLE.0;
        self.set_entry(
            index,
            (table as *const Self as *const ()).wrapping_byte_add(flags.0),
        );
    }
}

/// SAFETY: We never access any of the entries without a mutable reference.
unsafe impl<L> Sync for StaticPageTable<L> {}

pub trait Level {}

/// A page table level which can be a parent to another level.
pub trait ParentLevel {
    type Next: Level;
}

/// A page table level at which pages can be mapped.
pub trait PageLevel {
    /// The size of the pages which can be mapped.
    type Size: PageSize;
    /// Whether pages at this level are considered huge.
    const HUGE: bool;
}

pub enum Level4 {}

impl Level for Level4 {}

impl ParentLevel for Level4 {
    type Next = Level3;
}

pub enum Level3 {}

impl Level for Level3 {}

impl ParentLevel for Level3 {
    type Next = Level2;
}

impl PageLevel for Level3 {
    type Size = Size1GiB;
    const HUGE: bool = true;
}

pub enum Level2 {}

impl Level for Level2 {}

impl ParentLevel for Level2 {
    type Next = Level1;
}

impl PageLevel for Level2 {
    type Size = Size2MiB;
    const HUGE: bool = true;
}

pub enum Level1 {}

impl Level for Level1 {}

impl PageLevel for Level1 {
    type Size = Size4KiB;
    const HUGE: bool = false;
}

#[derive(Clone, Copy)]
pub struct Flags(pub usize);

impl Flags {
    pub const PRESENT: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const DIRTY: Self = Self(1 << 6);
    pub const HUGE: Self = Self(1 << 7);
    pub const C: Self = Self(1 << 51);
    pub const S: Self = Self(1 << 51);
    pub const EXECUTE_DISABLE: Self = Self(1 << 63);
}

#[macro_export]
macro_rules! flags {
    () => {
        $crate::Flags(0)
    };
    ($ident:ident $(| $more:ident)*) => {
        $crate::Flags($crate::Flags::$ident.0 $(| $crate::Flags::$more.0)*)
    };
}
