use alloc::{borrow::Cow, sync::Arc, vec::Vec};
use core::{
    fmt::{Debug, Display},
    iter::from_fn,
};

use crate::{
    error::{Result, bail, ensure},
    spin::lazy::Lazy,
};

pub const PATH_MAX: usize = 0x1000;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Path {
    bytes: Arc<[u8]>,
}

impl Path {
    pub fn root() -> Self {
        static ROOT: Lazy<Path> = Lazy::new(|| Path::new(b"/".to_vec()).unwrap());
        ROOT.clone()
    }

    pub fn new(path: Vec<u8>) -> Result<Self> {
        ensure!(!path.is_empty(), NoEnt);
        ensure!(path.len() < PATH_MAX, NameTooLong);
        Ok(Self { bytes: path.into() })
    }

    pub fn segments(&self) -> impl Iterator<Item = PathSegment<'_>> {
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

    pub fn is_absolute(&self) -> bool {
        self.as_bytes().starts_with(b"/")
    }

    pub fn has_trailing_slash(&self) -> bool {
        self.as_bytes().ends_with(b"/")
    }

    pub fn join_segment(&self, name: &FileName) -> Result<Self> {
        let mut bytes = self.bytes.to_vec();
        if !bytes.ends_with(b"/") {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(&name.0);
        ensure!(bytes.len() < PATH_MAX, NameTooLong);
        Ok(Self {
            bytes: Arc::from(bytes),
        })
    }
}

impl Debug for Path {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.as_bytes().escape_ascii(), f)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
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
            b"" | b"." | b".." => bail!(Inval),
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

impl Debug for FileName<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.as_bytes().escape_ascii(), f)
    }
}

impl PartialEq<str> for FileName<'_> {
    fn eq(&self, other: &str) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}
