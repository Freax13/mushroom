use core::{
    fmt::{Debug, Display},
    iter::from_fn,
};

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

    pub fn join_segment(&mut self, name: &FileName) -> Self {
        let mut bytes = self.bytes.to_vec();
        if !bytes.ends_with(b"/") {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(&name.0);
        Self {
            bytes: Arc::from(bytes),
        }
    }
}

impl Debug for Path {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.as_bytes().escape_ascii(), f)
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
