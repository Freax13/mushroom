use alloc::collections::btree_map::BTreeMap;
use core::{cmp, ops::Bound};

use crate::{
    error::{Result, ensure, err},
    fs::fd::{ReadBuf, WriteBuf},
    memory::page::KernelPage,
};

pub struct SparseBuffer {
    /// The length of the buffer in bytes.
    len: usize,
    pages: BTreeMap<usize, KernelPage>,
}

impl SparseBuffer {
    pub fn new(len: usize, pages: impl Iterator<Item = (usize, KernelPage)>) -> Self {
        Self {
            len,
            pages: pages
                .inspect(|(i, _)| {
                    debug_assert!(i * 0x1000 < len);
                })
                .collect(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn read(&self, offset: usize, buf: &mut (impl ReadBuf + ?Sized)) -> Result<usize> {
        let len = cmp::min(self.len.saturating_sub(offset), buf.buffer_len());
        if len == 0 {
            return Ok(0);
        }

        let start = offset;
        let end = offset + len - 1;

        let start_page = start / 0x1000;
        let end_page = (end + 1).div_ceil(0x1000);

        let mut iter = self.pages.range(start_page..end_page).peekable();
        for i in start_page..end_page {
            // Calcuate the start and end indices of `page` in `self`.
            let page_start = i * 0x1000;
            let page_end = (i + 1) * 0x1000 - 1;

            // Calculate the start and end indices in `self` for the copy operation.
            let copy_start = cmp::max(page_start, start);
            let copy_end = cmp::min(page_end, end);

            let buf_copy_start = copy_start - offset;

            // If there's an i'th page, copy its content, otherwise just zero the memory.
            if let Some((_, page)) = iter.next_if(|&(idx, _)| *idx == i) {
                // Calculate the start and end indices in `page` for the copy operation.
                let page_copy_start = copy_start - page_start;
                let page_copy_end = copy_end - page_start;
                let src = page.index(page_copy_start..=page_copy_end);

                unsafe {
                    buf.write_volatile(buf_copy_start, src)?;
                }
            } else {
                // Calculate how many bytes to clear.
                let len = copy_end - copy_start + 1;

                buf.fill(buf_copy_start, len, 0)?;
            }
        }

        Ok(len)
    }

    pub fn write(&mut self, offset: usize, buf: &dyn WriteBuf, max_size: usize) -> Result<usize> {
        let remaining_len = max_size
            .checked_sub(offset)
            .filter(|&remaining| remaining > 0)
            .ok_or(err!(FBig))?;
        let len = cmp::min(buf.buffer_len(), remaining_len);
        if len > 0 {
            let start = offset;
            let end = offset + len - 1;

            let start_page = start / 0x1000;
            let end_page = (end + 1).div_ceil(0x1000);

            let mut cursor = self.pages.lower_bound_mut(Bound::Included(&start_page));
            for i in start_page..end_page {
                // If no page exists for the given index, create one.
                if cursor.peek_next().is_none_or(|(idx, _)| *idx != i) {
                    cursor.insert_after(i, KernelPage::zeroed()).unwrap();
                }
                // Get a reference to the page.
                let (_, page) = cursor.next().unwrap();

                // Calcuate the start and end indices of `page` in `self`.
                let page_start = i * 0x1000;
                let page_end = (i + 1) * 0x1000 - 1;

                // Calculate the start and end indices in `self` for the copy
                // operation.
                let copy_start = cmp::max(page_start, start);
                let copy_end = cmp::min(page_end, end);

                // Calculate the start and end indices in `page` for the copy
                // operation.
                let page_copy_start = copy_start - page_start;
                let page_copy_end = copy_end - page_start;
                page.make_mut(true)?;
                let dst = page.index(page_copy_start..=page_copy_end);

                let buf_copy_start = copy_start - offset;
                unsafe {
                    buf.read_volatile(buf_copy_start, dst)?;
                }
            }
        }

        // Update the length.
        self.len = cmp::max(self.len, offset + len);

        Ok(len)
    }

    pub fn truncate(&mut self, len: usize) -> Result<()> {
        let page_offset = len % 0x1000;
        let page_index = len / 0x1000;
        let mut cursor = self.pages.lower_bound_mut(Bound::Included(&page_index));

        // If `len` isn't on a page boundary, clear the content towards the end.
        if page_offset > 0
            && let Some((_, page)) = cursor.peek_next().filter(|&(idx, _)| *idx == page_index)
        {
            page.zero_range(page_offset.., true)?;
            cursor.next();
        }

        // Remove all pages after `len`.
        while cursor.remove_next().is_some() {}

        self.len = len;

        Ok(())
    }

    pub fn get_page(&mut self, page_idx: usize, shared: bool) -> Result<KernelPage> {
        ensure!(page_idx * 0x1000 < self.len, Acces);

        if shared {
            let page = self
                .pages
                .entry(page_idx)
                .or_insert_with(KernelPage::zeroed);

            // Always make shared pages mutable immediately. We need to do this
            // because we need to ensure that calling `make_mut(...)` on the
            // returned pages doesn't allocate a new page every time.
            page.make_mut(true)?;

            page.clone()
        } else if let Some(page) = self.pages.get_mut(&page_idx) {
            page.clone()
        } else {
            Ok(KernelPage::zeroed())
        }
    }
}
