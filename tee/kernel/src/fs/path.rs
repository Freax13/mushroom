use core::fmt::{self, Debug, Display};

use alloc::{borrow::ToOwned, vec::Vec};

use crate::error::{Error, Result};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileName(Vec<u8>);

impl FileName {
    pub fn new(name: &[u8]) -> Result<Self, ParseFileNameError> {
        match name {
            b"" => Err(ParseFileNameError::Empty),
            b"." => Err(ParseFileNameError::Dot),
            b".." => Err(ParseFileNameError::DotDot),
            name if name.contains(&b'/') => Err(ParseFileNameError::Slash),
            name => Ok(Self(name.to_owned())),
        }
    }
}

impl Debug for FileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(str) = core::str::from_utf8(&self.0) {
            Debug::fmt(str, f)
        } else {
            self.0.fmt(f)
        }
    }
}

#[derive(Debug)]
pub enum ParseFileNameError {
    Empty,
    Dot,
    DotDot,
    Slash,
}

impl Display for ParseFileNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseFileNameError::Empty => write!(f, "file name must not be empty"),
            ParseFileNameError::Dot => write!(f, "dot is a valid file name"),
            ParseFileNameError::DotDot => write!(f, "dot dot is not a valid file name"),
            ParseFileNameError::Slash => write!(f, "file name must not contains a slash"),
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum PathSegment {
    Empty,
    Dot,
    DotDot,
    FileName(FileName),
}

#[derive(Clone)]
pub struct Path {
    is_absolute: bool,
    segments: Vec<PathSegment>,
}

impl Path {
    pub fn new(mut path: &[u8]) -> Result<Self> {
        if path.is_empty() {
            return Err(Error::inval(()));
        }

        let mut is_absolute = false;
        if let Some((head, tail)) = path.split_first() {
            if *head == b'/' {
                is_absolute = true;
                path = tail;
            }
        }

        let mut this = Path {
            is_absolute,
            segments: Vec::new(),
        };
        if !path.is_empty() {
            for segment in path.split(|&c| c == b'/') {
                this.join_in_place(segment);
            }
        }
        Ok(this)
    }

    pub fn is_absolute(&self) -> bool {
        self.is_absolute
    }

    pub fn segments(&self) -> &[PathSegment] {
        &self.segments
    }

    pub fn is_root(&self) -> bool {
        self.is_absolute && self.segments().is_empty()
    }

    fn join_in_place(&mut self, segment: &[u8]) {
        let res = FileName::new(segment);
        let segment = match res {
            Ok(file_name) => PathSegment::FileName(file_name),
            Err(ParseFileNameError::Empty) => PathSegment::Empty,
            Err(ParseFileNameError::Dot) => PathSegment::Dot,
            Err(ParseFileNameError::DotDot) => PathSegment::DotDot,
            Err(ParseFileNameError::Slash) => unreachable!(),
        };
        self.segments.push(segment);
    }

    pub fn join(&self, segment: &[u8]) -> Self {
        let mut this = self.clone();
        this.join_in_place(segment);
        this
    }

    pub fn canonicalize(&mut self) -> Result<()> {
        let mut idx = 0;
        while let Some(segment) = self.segments.get(idx) {
            match segment {
                PathSegment::Empty | PathSegment::Dot => {
                    self.segments.remove(idx);
                }
                PathSegment::DotDot => {
                    if let Some(new_idx) = idx.checked_sub(1) {
                        idx = new_idx;
                        self.segments.remove(idx);
                        self.segments.remove(idx);
                    }
                }
                PathSegment::FileName(_) => idx += 1,
            }
        }
        Ok(())
    }

    pub fn filename(&self) -> Option<&FileName> {
        match self.segments.last()? {
            PathSegment::FileName(filename) => Some(filename),
            _ => None,
        }
    }

    pub fn parent(&self) -> Result<Path> {
        let mut parent = self.join(b"..");
        parent.canonicalize()?;
        Ok(parent)
    }
}
