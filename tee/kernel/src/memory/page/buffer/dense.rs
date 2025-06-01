use core::{cmp, iter::repeat};

use alloc::vec::Vec;

use crate::{
    error::{Result, ensure},
    fs::fd::{ReadBuf, WriteBuf},
};

use super::{KernelPage, sparse::SparseBuffer};

pub struct DenseBuffer {
    /// The length of the buffer in bytes.
    len: usize,
    pages: Vec<KernelPage>,
}

impl DenseBuffer {
    #[inline]
    pub const fn new() -> Self {
        Self {
            len: 0,
            pages: Vec::new(),
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

        for (i, page) in self
            .pages
            .iter()
            .chain(repeat(&KernelPage::zeroed())) // TODO: Zero the buffer directly instead of copying from the zero page.
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

    pub fn write(
        &mut self,
        offset: usize,
        buf: &dyn WriteBuf,
    ) -> Result<Result<usize, NotDenseError>> {
        // Make sure that we don't need to add too many empty extra pages. If
        // that's the case, the buffer likely isn't dense.
        let start = offset;
        let start_page = start / 0x1000;
        let additional_pages = start_page.saturating_sub(self.pages.len());
        if additional_pages > 128 {
            return Ok(Err(NotDenseError));
        }

        let len = buf.buffer_len();
        if len > 0 {
            // Add as many pages as required for the write.
            let end = offset + len - 1;
            let end_page = (end + 1).div_ceil(0x1000);
            if self.pages.len() < end_page {
                self.pages.resize_with(end_page, KernelPage::zeroed);
            }

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
        }

        // Update the length.
        self.len = cmp::max(self.len, offset + len);

        Ok(Ok(len))
    }

    pub fn truncate(&mut self, len: usize) -> Result<()> {
        if len < self.len {
            // Remove all completly truncated pages.
            let remove_page_index = len.div_ceil(0x1000);
            self.pages.truncate(remove_page_index);

            // If the last page isn't fully truncated, just zero everything
            // after `len`.
            let page_offset = len % 0x1000;
            let page_index = len / 0x1000;
            if page_offset != 0 {
                if let Some(page) = self.pages.get_mut(page_index) {
                    page.zero_range(page_offset.., true)?;
                }
            }
        }

        self.len = len;

        Ok(())
    }

    pub fn get_page(
        &mut self,
        page_idx: usize,
        shared: bool,
    ) -> Result<Result<KernelPage, NotDenseError>> {
        ensure!(page_idx * 0x1000 < self.len, Acces);

        // Get the page. If it hasn't been allocated yet, it hasn't been
        // written to yet and accesses are likely not dense.
        let Some(page) = self.pages.get_mut(page_idx) else {
            // If the page doesn't need to be shared, we can just return the
            // zero page.
            if !shared {
                return Ok(Ok(KernelPage::zeroed()));
            }

            // Adding the page to the buffer would require making it sparse.
            return Ok(Err(NotDenseError));
        };

        // Always make shared pages mutable immediately. We need to do this
        // because we need to ensure that calling `make_mut(...)` on the
        // returned pages doesn't allocate a new page every time.
        if shared {
            page.make_mut(true)?;
        }

        page.clone().map(Ok)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NotDenseError;

impl From<DenseBuffer> for SparseBuffer {
    fn from(value: DenseBuffer) -> Self {
        Self::new(value.len, value.pages.into_iter().enumerate())
    }
}
