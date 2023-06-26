use core::iter::from_fn;

use alloc::{borrow::Cow, sync::Arc, vec::Vec};

use crate::error::{Error, Result};

#[derive(Clone)]
pub struct Path {
    bytes: Arc<[u8]>,
}

impl Path {
    pub fn new(path: Vec<u8>) -> Result<Self> {
        if path.is_empty() {
            return Err(Error::inval(()));
        }
        Ok(Self { bytes: path.into() })
    }

    pub fn segments(&self) -> impl Iterator<Item = PathSegment> {
        let mut bytes_opt = Some(&*self.bytes);

        let mut first = true;

        from_fn(move || {
            let was_first = core::mem::replace(&mut first, false);
            let bytes = bytes_opt.as_mut()?;
            if let Some(bs) = bytes.strip_prefix(b"/") {
                *bytes = bs;
                if was_first {
                    return Some(PathSegment::Root);
                } else {
                    return Some(PathSegment::Empty);
                }
            }

            let next = bytes.iter().position(|&b| b == b'/');
            let segment_bytes = if let Some(next) = next {
                let segment_bytes = &bytes[..next];
                bytes_opt = Some(&bytes[next + 1..]);
                segment_bytes
            } else {
                let bytes = *bytes;
                bytes_opt = None;
                bytes
            };
            match segment_bytes {
                b"" => Some(PathSegment::Empty),
                b"." => Some(PathSegment::Dot),
                b".." => Some(PathSegment::DotDot),
                bytes => Some(PathSegment::FileName(FileName::new(bytes).unwrap())),
            }
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn canonicalize(&mut self) -> Result<()> {
        // Short-circuit for paths that are already canonical.
        if self
            .segments()
            .all(|segment| matches!(segment, PathSegment::Root | PathSegment::FileName(_)))
        {
            return Ok(());
        }

        let capacity = self
            .segments()
            .scan(0usize, |count, b| {
                match b {
                    PathSegment::Empty | PathSegment::Dot => {}
                    PathSegment::DotDot => *count = count.saturating_sub(1),
                    PathSegment::Root | PathSegment::FileName(_) => *count += 1,
                }
                Some(*count)
            })
            .max()
            .unwrap_or_default();

        let mut stack = Vec::with_capacity(capacity);
        for segment in self.segments() {
            match segment {
                PathSegment::Empty => {}
                PathSegment::Dot => {}
                PathSegment::DotDot => {
                    stack.pop();
                }
                segment @ (PathSegment::Root | PathSegment::FileName(_)) => {
                    stack.push(segment);
                }
            }
        }

        // FIXME: We can use a smaller capacity.
        let mut path = Vec::with_capacity(self.bytes.len());

        let mut iter = stack.into_iter().peekable();
        if iter.next_if_eq(&PathSegment::Root).is_some() {
            path.push(b'/');
        }
        let mut iter = iter.map(|segment| match segment {
            PathSegment::Root | PathSegment::Empty | PathSegment::Dot | PathSegment::DotDot => {
                unreachable!()
            }
            PathSegment::FileName(filename) => filename,
        });
        if let Some(first) = iter.next() {
            path.extend_from_slice(first.as_bytes());
            for rest in iter {
                path.push(b'/');
                path.extend_from_slice(rest.as_bytes());
            }
        }
        *self = Path::new(path)?;
        Ok(())
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum PathSegment<'a> {
    /// The path starts at the root of the file system. Can only be the first
    /// segment in a path.
    Root,
    Empty,
    Dot,
    DotDot,
    FileName(FileName<'a>),
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileName<'a>(Cow<'a, [u8]>);

impl<'a> FileName<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        match bytes {
            b"" | b"." | b".." => Err(Error::inval(())),
            _ => Ok(Self(Cow::Borrowed(bytes))),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_owned(self) -> FileName<'static> {
        FileName(Cow::Owned(self.0.into_owned()))
    }
}
