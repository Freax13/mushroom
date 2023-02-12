use core::fmt::{self, Display};

use alloc::{borrow::ToOwned, vec::Vec};

#[derive(PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub enum PathSegment {
    Empty,
    Dot,
    DotDot,
    FileName(FileName),
}

pub struct Path {
    is_absolute: bool,
    segments: Vec<PathSegment>,
}

impl Path {
    pub fn new(mut path: &[u8]) -> Self {
        let mut is_absolute = false;
        if let Some((head, tail)) = path.split_first() {
            if *head == b'/' {
                is_absolute = true;
                path = tail;
            }
        }

        let segments = path
            .split(|&c| c == b'/')
            .map(|segment| {
                let res = FileName::new(segment);
                match res {
                    Ok(file_name) => PathSegment::FileName(file_name),
                    Err(ParseFileNameError::Empty) => PathSegment::Empty,
                    Err(ParseFileNameError::Dot) => PathSegment::Dot,
                    Err(ParseFileNameError::DotDot) => PathSegment::DotDot,
                    Err(ParseFileNameError::Slash) => unreachable!(),
                }
            })
            .collect();

        Path {
            is_absolute,
            segments,
        }
    }

    pub fn is_absolute(&self) -> bool {
        self.is_absolute
    }

    pub fn segments(&self) -> &[PathSegment] {
        &self.segments
    }
}
