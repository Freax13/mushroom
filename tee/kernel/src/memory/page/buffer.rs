use core::{cmp, iter::repeat_with};

use alloc::vec::Vec;

use crate::{
    error::{Result, ensure},
    fs::fd::{ReadBuf, WriteBuf},
};

use super::KernelPage;

pub struct Buffer {
    /// The length of the vector in bytes.
    len: usize,
    pages: Vec<KernelPage>,
}

impl Buffer {
    #[inline]
    pub fn new() -> Self {
        Self {
            len: 0,
            pages: Vec::new(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn reserve(&mut self, additional: usize) -> Result<()> {
        if additional == 0 {
            return Ok(());
        }

        let total_len = self.len() + additional;
        let num_pages = total_len.div_ceil(0x1000);
        let new_pages = num_pages.saturating_sub(self.pages.len());

        self.pages.try_reserve(new_pages)?;
        self.pages
            .extend(repeat_with(KernelPage::zeroed).take(new_pages));

        Ok(())
    }

    /// Reserve `additional` bytes and make sure that they're all zero.
    fn reserve_zeroed(&mut self, additional: usize) -> Result<()> {
        if additional == 0 {
            return Ok(());
        }

        if self.len() % 0x1000 != 0 {
            let start = self.len() % 0x1000;
            let idx = self.len() / 0x1000;
            let page = &mut self.pages[idx];
            page.zero_range(start.., true)?;
        }

        let following_pages = self.len().div_ceil(4096);
        self.pages.drain(following_pages..);

        self.reserve(additional)?;

        Ok(())
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

        for (i, page) in self
            .pages
            .iter()
            .enumerate()
            .take(end_page)
            .skip(start_page)
        {
            // Calcuate the start and end indices of `page` in `self`.
            let page_start = i * 0x1000;
            let page_end = (i + 1) * 0x1000 - 1;

            // Calculate the start and end indices in `self` for the copy operation.
            let copy_start = cmp::max(page_start, start);
            let copy_end = cmp::min(page_end, end);

            // Calculate the start and end indices in `page` for the copy operation.
            let page_copy_start = copy_start - page_start;
            let page_copy_end = copy_end - page_start;
            let src = page.index(page_copy_start..=page_copy_end);

            let buf_copy_start = copy_start - offset;
            unsafe {
                buf.write_volatile(buf_copy_start, src)?;
            }
        }

        Ok(len)
    }

    pub fn write(&mut self, offset: usize, buf: &dyn WriteBuf) -> Result<usize> {
        // Zero reserve the memory between `len` and `offset`.
        let needed_capacity = offset.saturating_sub(self.len());
        self.reserve_zeroed(needed_capacity)?;

        let len = buf.buffer_len();
        if len == 0 {
            return Ok(0);
        }

        // Reserve enough memory for the write.
        let needed_capacity = (offset + len).saturating_sub(self.len());
        self.reserve(needed_capacity)?;

        let start = offset;
        let end = offset + len - 1;

        let start_page = start / 0x1000;
        let end_page = (end + 1).div_ceil(0x1000);

        for (i, page) in self
            .pages
            .iter_mut()
            .enumerate()
            .take(end_page)
            .skip(start_page)
        {
            // Calcuate the start and end indices of `page` in `self`.
            let page_start = i * 0x1000;
            let page_end = (i + 1) * 0x1000 - 1;

            // Calculate the start and end indices in `self` for the copy operation.
            let copy_start = cmp::max(page_start, start);
            let copy_end = cmp::min(page_end, end);

            // Calculate the start and end indices in `page` for the copy operation.
            let page_copy_start = copy_start - page_start;
            let page_copy_end = copy_end - page_start;
            page.make_mut(true)?;
            let dst = page.index(page_copy_start..=page_copy_end);

            let buf_copy_start = copy_start - offset;
            unsafe {
                buf.read_volatile(buf_copy_start, dst)?;
            }
        }

        // Update the length.
        self.len = cmp::max(self.len, offset + len);

        Ok(len)
    }

    pub fn truncate(&mut self, len: usize) -> Result<()> {
        let additional = len.saturating_sub(self.len());
        self.reserve_zeroed(additional)?;

        self.len = len;

        Ok(())
    }

    pub fn get_page(&mut self, page_idx: usize, shared: bool) -> Result<KernelPage> {
        ensure!(page_idx < self.pages.len(), Acces);

        // Zero reserve until the end of the page to make sure that we don't
        // leak unitialized bytes.
        let end = (page_idx + 1) * 0x1000;
        let additional = end.saturating_sub(self.len());
        self.reserve_zeroed(additional)?;

        // Always make shared pages mutable immediately. We need to do this
        // because we need to ensure that calling `make_mut(...)` on the
        // returned pages doesn't allocate a new page every time.
        if shared {
            self.pages[page_idx].make_mut(true)?;
        }

        self.pages[page_idx].clone()
    }
}
