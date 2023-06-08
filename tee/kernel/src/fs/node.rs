use core::{any::Any, cmp, iter::repeat, ops::Deref};

use alloc::{
    borrow::Cow,
    collections::{btree_map::Entry, BTreeMap},
    sync::Arc,
};
use spin::{Lazy, Mutex};

use crate::{
    error::{Error, Result},
    user::process::syscall::args::FileMode,
};

use super::{path::FileName, Path, PathSegment};

pub mod special;

pub static ROOT_NODE: Lazy<Arc<TmpFsDirectory>> = Lazy::new(|| Arc::new(TmpFsDirectory::new()));

#[derive(Clone)]
pub enum Node {
    File(Arc<dyn File>),
    Directory(Arc<dyn Directory>),
    Link(Link),
}

impl Node {
    fn resolve_link(self, start_dir: Arc<dyn Directory>) -> Result<NonLinkNode> {
        self.resolve_link_recursive(start_dir, &mut 16)
    }

    fn resolve_link_recursive(
        self,
        start_dir: Arc<dyn Directory>,
        recursion: &mut u8,
    ) -> Result<NonLinkNode> {
        match self {
            Node::File(file) => Ok(NonLinkNode::File(file)),
            Node::Directory(dir) => Ok(NonLinkNode::Directory(dir)),
            Node::Link(link) => {
                *recursion = recursion.checked_sub(1).ok_or_else(|| Error::r#loop(()))?;
                lookup_node_recursive(start_dir, &link.target, recursion)
            }
        }
    }
}

pub enum NonLinkNode {
    File(Arc<dyn File>),
    Directory(Arc<dyn Directory>),
}

impl TryFrom<NonLinkNode> for Arc<dyn Directory> {
    type Error = Error;

    #[track_caller]
    fn try_from(value: NonLinkNode) -> Result<Self> {
        match value {
            NonLinkNode::File(_) => Err(Error::not_dir(())),
            NonLinkNode::Directory(dir) => Ok(dir),
        }
    }
}

pub trait File: Send + Sync + 'static {
    fn mode(&self) -> FileMode;
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
    fn create_file(
        &self,
        file_name: FileName,
        mode: FileMode,
        create_new: bool,
    ) -> Result<Arc<dyn File>>;
    fn create_dir(&self, file_name: FileName, create_new: bool) -> Result<Arc<dyn Directory>>;
    fn create_link(&self, file_name: FileName, target: Path, create_new: bool) -> Result<()>;
}

#[derive(Clone)]
pub struct Link {
    target: Path,
}

pub fn lookup_node(start_node: Arc<dyn Directory>, path: &Path) -> Result<NonLinkNode> {
    lookup_node_recursive(start_node, path, &mut 16)
}

fn lookup_node_recursive(
    mut start_node: Arc<dyn Directory>,
    path: &Path,
    recursion: &mut u8,
) -> Result<NonLinkNode> {
    if path.is_absolute() {
        start_node = ROOT_NODE.clone();
    }
    path.segments()
        .iter()
        .try_fold(NonLinkNode::Directory(start_node), |node, segment| {
            let dir = <Arc<dyn Directory>>::try_from(node)?;

            match segment {
                PathSegment::Empty | PathSegment::Dot => Ok(NonLinkNode::Directory(dir)),
                PathSegment::DotDot => todo!(),
                PathSegment::FileName(file_name) => {
                    *recursion = recursion.checked_sub(1).ok_or_else(|| Error::r#loop(()))?;
                    let node = dir.get_node(file_name)?;
                    node.resolve_link_recursive(dir, recursion)
                }
            }
        })
}

fn find_parent(start_node: Node, path: &Path) -> Result<(Arc<dyn Directory>, &PathSegment)> {
    let start_node = if path.is_absolute() {
        ROOT_NODE.clone()
    } else {
        let start_node = start_node.resolve_link_recursive(ROOT_NODE.clone(), &mut 16)?;
        <Arc<dyn Directory>>::try_from(start_node)?
    };

    let (last, segments) = path
        .segments()
        .split_last()
        .ok_or_else(|| Error::inval(()))?;
    let dir = segments
        .iter()
        .try_fold(start_node, |dir, segment| match segment {
            PathSegment::Empty | PathSegment::Dot => Ok(dir),
            PathSegment::DotDot => todo!(),
            PathSegment::FileName(file_name) => {
                let node = dir.get_node(file_name)?;
                let node = node.resolve_link(dir.clone())?;
                <Arc<dyn Directory>>::try_from(node)
            }
        })?;
    Ok((dir, last))
}

pub fn create_file(start_node: Node, path: &Path, mode: FileMode) -> Result<Arc<dyn File>> {
    let (dir, last) = find_parent(start_node, path)?;
    let file_name = match last {
        PathSegment::Empty => todo!(),
        PathSegment::Dot => todo!(),
        PathSegment::DotDot => todo!(),
        PathSegment::FileName(file_name) => file_name,
    };
    let file = dir.create_file(file_name.clone(), mode, false)?;
    Ok(file)
}

pub fn create_directory(start_node: Node, path: &Path) -> Result<Arc<dyn Directory>> {
    let (dir, last) = find_parent(start_node, path)?;
    let file_name = match last {
        PathSegment::Empty => todo!(),
        PathSegment::Dot => todo!(),
        PathSegment::DotDot => todo!(),
        PathSegment::FileName(file_name) => file_name,
    };
    let file = dir.create_dir(file_name.clone(), false)?;
    Ok(file)
}

pub fn create_link(start_node: Node, path: &Path, target: Path) -> Result<()> {
    let (dir, last) = find_parent(start_node, path)?;
    let file_name = match last {
        PathSegment::Empty => todo!(),
        PathSegment::Dot => todo!(),
        PathSegment::DotDot => todo!(),
        PathSegment::FileName(file_name) => file_name,
    };
    dir.create_link(file_name.clone(), target, true)?;
    Ok(())
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
            .ok_or(Error::no_ent(()))
    }

    fn create_dir(&self, file_name: FileName, create_new: bool) -> Result<Arc<dyn Directory>> {
        let mut guard = self.items.lock();
        let entry = guard.entry(file_name);
        match entry {
            Entry::Vacant(entry) => {
                let dir = Arc::new(TmpFsDirectory::new());
                entry.insert(Node::Directory(dir.clone()));
                Ok(dir)
            }
            Entry::Occupied(entry) => {
                if create_new {
                    return Err(Error::exist(()));
                }
                match entry.get() {
                    Node::Directory(dir) => Ok(dir.clone()),
                    Node::File(_) | Node::Link(_) => Err(Error::exist(())),
                }
            }
        }
    }

    fn create_file(
        &self,
        path_segment: FileName,
        mode: FileMode,
        create_new: bool,
    ) -> Result<Arc<dyn File>> {
        let mut guard = self.items.lock();
        let entry = guard.entry(path_segment);
        match entry {
            Entry::Vacant(entry) => {
                let file = Arc::new(TmpFsFile::new(mode, &[]));
                entry.insert(Node::File(file.clone()));
                Ok(file)
            }
            Entry::Occupied(mut entry) => {
                if create_new {
                    return Err(Error::exist(()));
                }
                match entry.get_mut() {
                    Node::File(f) => Ok(f.clone()),
                    Node::Link(_) => Err(Error::exist(())),
                    Node::Directory(_) => Err(Error::exist(())),
                }
            }
        }
    }

    fn create_link(&self, file_name: FileName, target: Path, create_new: bool) -> Result<()> {
        let mut guard = self.items.lock();
        let entry = guard.entry(file_name);
        match entry {
            Entry::Vacant(entry) => {
                entry.insert(Node::Link(Link { target }));
                Ok(())
            }
            Entry::Occupied(mut entry) => {
                if create_new {
                    return Err(Error::exist(()));
                }
                entry.insert(Node::Link(Link { target }));
                Ok(())
            }
        }
    }
}

pub struct TmpFsFile {
    content: Mutex<Arc<Cow<'static, [u8]>>>,
    mode: FileMode,
}

impl TmpFsFile {
    pub fn new(mode: FileMode, content: &'static [u8]) -> Self {
        Self {
            content: Mutex::new(Arc::new(Cow::Borrowed(content))),
            mode,
        }
    }
}

impl File for TmpFsFile {
    fn mode(&self) -> FileMode {
        self.mode
    }

    fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let guard = self.content.lock();
        let slice = guard.get(offset..).ok_or(Error::inval(()))?;
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
