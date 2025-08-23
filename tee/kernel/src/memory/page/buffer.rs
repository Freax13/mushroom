use self::{
    dense::{DenseBuffer, NotDenseError},
    sparse::SparseBuffer,
};
use crate::{
    error::Result,
    fs::fd::{ReadBuf, WriteBuf},
    memory::page::KernelPage,
};

mod dense;
mod sparse;

pub struct Buffer {
    buffer_impl: BufferImpl,
}

/// Sparse buffers may have holes, dense buffers may not. Dense buffers are
/// generally faster.
enum BufferImpl {
    Dense(DenseBuffer),
    Sparse(SparseBuffer),
}

impl Buffer {
    #[inline]
    pub fn new() -> Self {
        Self {
            buffer_impl: BufferImpl::Dense(DenseBuffer::new()),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match &self.buffer_impl {
            BufferImpl::Dense(buffer) => buffer.len(),
            BufferImpl::Sparse(buffer) => buffer.len(),
        }
    }

    pub fn read(&self, offset: usize, buf: &mut (impl ReadBuf + ?Sized)) -> Result<usize> {
        match &self.buffer_impl {
            BufferImpl::Dense(buffer) => buffer.read(offset, buf),
            BufferImpl::Sparse(buffer) => buffer.read(offset, buf),
        }
    }

    fn do_buffer_op<R>(
        &mut self,
        mut dense: impl FnMut(&mut DenseBuffer) -> Result<Result<R, NotDenseError>>,
        mut sparse: impl FnMut(&mut SparseBuffer) -> Result<R>,
    ) -> Result<R> {
        if let BufferImpl::Dense(buffer) = &mut self.buffer_impl {
            // Attempt the operation on a dense buffer.
            let res = dense(buffer)?;

            // If it succeeds, then return its result.
            if let Ok(result) = res {
                return Ok(result);
            }

            // Otherwise convert the buffer into a sparse buffer and try again.
            let buffer = core::mem::replace(buffer, DenseBuffer::new());
            self.buffer_impl = BufferImpl::Sparse(SparseBuffer::from(buffer));
        }

        let BufferImpl::Sparse(buffer) = &mut self.buffer_impl else {
            unreachable!()
        };
        sparse(buffer)
    }

    pub fn write(&mut self, offset: usize, buf: &dyn WriteBuf) -> Result<usize> {
        self.do_buffer_op(
            |buffer| buffer.write(offset, buf),
            |buffer| buffer.write(offset, buf),
        )
    }

    pub fn truncate(&mut self, len: usize) -> Result<()> {
        match &mut self.buffer_impl {
            BufferImpl::Dense(buffer) => buffer.truncate(len),
            BufferImpl::Sparse(buffer) => buffer.truncate(len),
        }
    }

    pub fn get_page(&mut self, page_idx: usize, shared: bool) -> Result<KernelPage> {
        self.do_buffer_op(
            |buffer| buffer.get_page(page_idx, shared),
            |buffer| buffer.get_page(page_idx, shared),
        )
    }
}
