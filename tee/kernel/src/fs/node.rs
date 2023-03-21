use core::{any::Any, cmp, iter::repeat, ops::Deref};

use alloc::{
    borrow::Cow,
    collections::{btree_map::Entry, BTreeMap},
    sync::Arc,
};
use spin::{Lazy, Mutex};

use crate::error::{Error, Result};

use super::{path::FileName, Path, PathSegment};

pub mod special;

pub static ROOT_NODE: Lazy<Arc<TmpFsDirectory>> = Lazy::new(|| Arc::new(TmpFsDirectory::new()));

#[derive(Clone)]
pub enum Node {
    File(Arc<dyn File>),
    Directory(Arc<dyn Directory>),
}

pub trait File: Send + Sync + 'static {
    fn is_executable(&self) -> bool;
    fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize>;
    fn write(&self, offset: usize, buf: &[u8]) -> Result<usize>;
    fn read_snapshot(&self) -> Result<FileSnapshot>;
}

#[derive(Clone)]
pub struct FileSnapshot(Arc<Cow<'static, [u8]>>);

impl FileSnapshot {
    pub fn empty() -> Self {
        static EMPTY: Lazy<FileSnapshot> = Lazy::new(|| FileSnapshot(Arc::new(Cow::Borrowed(&[]))));
        EMPTY.clone()
    }
}

impl From<Arc<Cow<'static, [u8]>>> for FileSnapshot {
    fn from(value: Arc<Cow<'static, [u8]>>) -> Self {
        if value.is_empty() {
            return Self::empty();
        }

        Self(value)
    }
}

impl Deref for FileSnapshot {
    type Target = Cow<'static, [u8]>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub trait Directory: Any + Send + Sync {
    fn get_node(&self, file_name: &FileName) -> Result<Node>;
    fn mkdir(&self, file_name: FileName, create_new: bool) -> Result<Arc<dyn Directory>>;
    fn create(&self, file_name: FileName, create_new: bool) -> Result<Arc<dyn File>>;
}

pub fn lookup_node(mut start_node: Node, path: &Path) -> Result<Node> {
    if path.is_absolute() {
        start_node = Node::Directory(ROOT_NODE.clone());
    }
    path.segments()
        .iter()
        .try_fold(start_node, |node, segment| {
            let dir = match node {
                Node::File(_) => return Err(Error::NotDir),
                Node::Directory(dir) => dir,
            };

            match segment {
                PathSegment::Empty | PathSegment::Dot => Ok(Node::Directory(dir)),
                PathSegment::DotDot => todo!(),
                PathSegment::FileName(file_name) => dir.get_node(file_name),
            }
        })
}

pub fn create_file(start_node: Node, path: &Path) -> Result<Arc<dyn File>> {
    let mut start_node = match start_node {
        Node::File(_) => return Err(Error::NotDir),
        Node::Directory(dir) => dir,
    };
    if path.is_absolute() {
        start_node = ROOT_NODE.clone();
    }

    let (last, segments) = path.segments().split_last().unwrap();
    let dir = segments
        .iter()
        .try_fold(start_node, |dir, segment| match segment {
            PathSegment::Empty | PathSegment::Dot => Ok(dir),
            PathSegment::DotDot => todo!(),
            PathSegment::FileName(file_name) => {
                let dir = dir.get_node(file_name)?;
                match dir {
                    Node::File(_) => Err(Error::NotDir),
                    Node::Directory(dir) => Ok(dir),
                }
            }
        })?;

    let file_name = match last {
        PathSegment::Empty => todo!(),
        PathSegment::Dot => todo!(),
        PathSegment::DotDot => todo!(),
        PathSegment::FileName(file_name) => file_name,
    };
    let file = dir.create(file_name.clone(), false)?;
    Ok(file)
}

pub struct TmpFsDirectory {
    items: Mutex<BTreeMap<FileName, Node>>,
}

impl TmpFsDirectory {
    pub const fn new() -> Self {
        Self {
            items: Mutex::new(BTreeMap::new()),
        }
    }

    /// Mount a special file into the tmpfs directory.
    pub fn mount(&self, path_segment: FileName, file: impl File) {
        let mut guard = self.items.lock();
        guard.insert(path_segment, Node::File(Arc::new(file)));
    }
}

impl Directory for TmpFsDirectory {
    fn get_node(&self, path_segment: &FileName) -> Result<Node> {
        self.items
            .lock()
            .get(path_segment)
            .cloned()
            .ok_or(Error::NoEnt)
    }

    fn mkdir(&self, path_segment: FileName, create_new: bool) -> Result<Arc<dyn Directory>> {
        let mut guard = self.items.lock();
        let entry = guard.entry(path_segment);
        match entry {
            Entry::Vacant(entry) => {
                let dir = Arc::new(TmpFsDirectory::new());
                entry.insert(Node::Directory(dir.clone()));
                Ok(dir)
            }
            Entry::Occupied(entry) => {
                if create_new {
                    return Err(Error::Exist);
                }
                match entry.get() {
                    Node::File(_) => Err(Error::Exist),
                    Node::Directory(dir) => Ok(dir.clone()),
                }
            }
        }
    }

    fn create(&self, path_segment: FileName, create_new: bool) -> Result<Arc<dyn File>> {
        let mut guard = self.items.lock();
        let entry = guard.entry(path_segment);
        match entry {
            Entry::Vacant(entry) => {
                let file = Arc::new(TmpFsFile::new(false, &[]));
                entry.insert(Node::File(file.clone()));
                Ok(file)
            }
            Entry::Occupied(mut entry) => {
                if create_new {
                    return Err(Error::Exist);
                }
                match entry.get_mut() {
                    Node::File(f) => Ok(f.clone()),
                    Node::Directory(_) => Err(Error::Exist),
                }
            }
        }
    }
}

pub struct TmpFsFile {
    content: Mutex<Arc<Cow<'static, [u8]>>>,
    executable: bool,
}

impl TmpFsFile {
    pub fn new(executable: bool, content: &'static [u8]) -> Self {
        Self {
            content: Mutex::new(Arc::new(Cow::Borrowed(content))),
            executable,
        }
    }
}

impl File for TmpFsFile {
    fn is_executable(&self) -> bool {
        self.executable
    }

    fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let guard = self.content.lock();
        let slice = guard.get(offset..).ok_or(Error::Inval)?;
        let len = cmp::min(slice.len(), buf.len());
        buf[..len].copy_from_slice(&slice[..len]);
        Ok(len)
    }

    fn write(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        let mut guard = self.content.lock();
        let bytes = Arc::make_mut(&mut guard);
        let bytes = bytes.to_mut();

        // Grow the file to be able to hold at least `offset+buf.len()` bytes.
        let new_min_len = offset + buf.len();
        if let Some(diff) = new_min_len.checked_sub(bytes.len()) {
            bytes.extend(repeat(0).take(diff));
        }

        // Copy the buffer into the file.
        bytes[offset..][..buf.len()].copy_from_slice(buf);

        Ok(buf.len())
    }

    fn read_snapshot(&self) -> Result<FileSnapshot> {
        let content = self.content.lock().clone();
        Ok(FileSnapshot(content))
    }
}
