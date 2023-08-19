use core::{
    any::Any,
    ops::Deref,
    sync::atomic::{AtomicU64, Ordering},
};

use alloc::{
    borrow::Cow,
    sync::{Arc, Weak},
    vec::Vec,
};
use spin::Lazy;

use crate::{
    error::{Error, Result},
    user::process::syscall::args::{FileMode, FileType, Stat},
};

use self::tmpfs::TmpFsDir;

use super::path::{FileName, Path, PathSegment};

pub mod devtmpfs;
pub mod tmpfs;

pub static ROOT_NODE: Lazy<Arc<TmpFsDir>> =
    Lazy::new(|| TmpFsDir::root(FileMode::from_bits_truncate(0o755)));

fn new_ino() -> u64 {
    static INO_COUNTER: AtomicU64 = AtomicU64::new(1);
    INO_COUNTER.fetch_add(1, Ordering::SeqCst)
}

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
                lookup_and_resolve_node_recursive(start_dir, &link.target, recursion)
            }
        }
    }

    pub fn stat(&self) -> Stat {
        match self {
            Node::File(file) => file.stat(),
            Node::Directory(dir) => dir.stat(),
            Node::Link(link) => link.stat(),
        }
    }
}

pub enum NonLinkNode {
    File(Arc<dyn File>),
    Directory(Arc<dyn Directory>),
}

impl NonLinkNode {
    pub fn stat(&self) -> Stat {
        match self {
            NonLinkNode::File(file) => file.stat(),
            NonLinkNode::Directory(dir) => dir.stat(),
        }
    }

    pub fn set_mode(&self, mode: FileMode) {
        match self {
            NonLinkNode::File(file) => file.set_mode(mode),
            NonLinkNode::Directory(dir) => dir.set_mode(mode),
        }
    }
}

impl TryFrom<NonLinkNode> for Arc<dyn File> {
    type Error = Error;

    #[track_caller]
    fn try_from(value: NonLinkNode) -> Result<Self> {
        match value {
            NonLinkNode::File(file) => Ok(file),
            NonLinkNode::Directory(_) => Err(Error::is_dir(())),
        }
    }
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

impl From<NonLinkNode> for Node {
    fn from(value: NonLinkNode) -> Self {
        match value {
            NonLinkNode::File(file) => Self::File(file),
            NonLinkNode::Directory(dir) => Self::Directory(dir),
        }
    }
}

pub trait File: Send + Sync + 'static {
    fn stat(&self) -> Stat;
    fn set_mode(&self, mode: FileMode);
    fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize>;
    fn write(&self, offset: usize, buf: &[u8]) -> Result<usize>;
    fn read_snapshot(&self) -> Result<FileSnapshot>;

    fn mode(&self) -> FileMode {
        self.stat().mode.mode()
    }
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
    fn parent(&self) -> Result<Arc<dyn Directory>>;
    fn stat(&self) -> Stat;
    fn set_mode(&self, mode: FileMode);
    fn get_node(&self, file_name: &FileName) -> Result<Node>;
    fn create_file(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
        create_new: bool,
    ) -> Result<Arc<dyn File>>;
    fn create_dir(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
    ) -> Result<Arc<dyn Directory>>;
    fn create_link(
        &self,
        file_name: FileName<'static>,
        target: Path,
        create_new: bool,
    ) -> Result<()>;
    fn hard_link(&self, file_name: FileName<'static>, node: Node) -> Result<()>;
    fn mount(&self, file_name: FileName<'static>, node: Node) -> Result<()>;
    fn list_entries(&self) -> Vec<DirEntry>;
    fn delete_non_dir(&self, file_name: FileName<'static>) -> Result<()>;
    fn delete_dir(&self, file_name: FileName<'static>) -> Result<()>;

    fn mode(&self) -> FileMode {
        self.stat().mode.mode()
    }
}

pub struct DirEntry {
    pub ino: u64,
    pub ty: FileType,
    pub name: DirEntryName,
}

impl DirEntry {
    pub fn len(&self) -> usize {
        let len = 19 + self.name.as_ref().len() + 1;
        len.next_multiple_of(8)
    }
}

pub enum DirEntryName {
    FileName(FileName<'static>),
    Dot,
    DotDot,
}

impl AsRef<[u8]> for DirEntryName {
    fn as_ref(&self) -> &[u8] {
        match self {
            DirEntryName::FileName(filename) => filename.as_bytes(),
            DirEntryName::Dot => b".",
            DirEntryName::DotDot => b"..",
        }
    }
}

impl From<FileName<'static>> for DirEntryName {
    fn from(value: FileName<'static>) -> Self {
        Self::FileName(value)
    }
}

#[derive(Clone)]
pub struct Link {
    target: Path,
}

impl Link {
    fn stat(&self) -> Stat {
        todo!()
    }
}

/// Find a node.
pub fn lookup_node(start_dir: Arc<dyn Directory>, path: &Path) -> Result<Node> {
    let (_, node) = lookup_node_recursive(start_dir, path, &mut 16)?;
    Ok(node)
}

// Find a node while taking recursion limits into account.
fn lookup_node_recursive(
    start_dir: Arc<dyn Directory>,
    path: &Path,
    recursion: &mut u8,
) -> Result<(Arc<dyn Directory>, Node)> {
    let res = path.segments().try_fold(
        (start_dir.clone(), Node::Directory(start_dir)),
        |(start_dir, node), segment| -> Result<_> {
            let node = node.resolve_link_recursive(start_dir.clone(), recursion)?;
            let dir = <Arc<dyn Directory>>::try_from(node)?;

            match segment {
                PathSegment::Root => Ok((ROOT_NODE.clone(), Node::Directory(ROOT_NODE.clone()))),
                PathSegment::Empty | PathSegment::Dot => Ok((start_dir, Node::Directory(dir))),
                PathSegment::DotDot => {
                    let parent = dir.parent()?;
                    Ok((parent.clone(), Node::Directory(parent)))
                }
                PathSegment::FileName(file_name) => {
                    *recursion = recursion.checked_sub(1).ok_or_else(|| Error::r#loop(()))?;
                    let node = dir.get_node(&file_name)?;
                    Ok((dir, node))
                }
            }
        },
    );
    res
}

// Find a node and resolve links.
pub fn lookup_and_resolve_node(start_dir: Arc<dyn Directory>, path: &Path) -> Result<NonLinkNode> {
    lookup_and_resolve_node_recursive(start_dir, path, &mut 16)
}

// Find a node and resolve links while taking recursion limits into account.
fn lookup_and_resolve_node_recursive(
    start_dir: Arc<dyn Directory>,
    path: &Path,
    recursion: &mut u8,
) -> Result<NonLinkNode> {
    let (dir, node) = lookup_node_recursive(start_dir.clone(), path, recursion)?;
    node.resolve_link_recursive(dir, recursion)
}

fn find_parent(
    start_dir: Arc<dyn Directory>,
    path: &Path,
) -> Result<(Arc<dyn Directory>, PathSegment)> {
    let mut segments = path.segments();
    let first = segments.next().ok_or_else(|| Error::inval(()))?;
    segments.try_fold((start_dir, first), |(dir, segment), next_segment| {
        let dir = match segment {
            PathSegment::Root => ROOT_NODE.clone() as Arc<dyn Directory>,
            PathSegment::Empty | PathSegment::Dot => dir,
            PathSegment::DotDot => unreachable!(),
            PathSegment::FileName(file_name) => {
                let node = dir.get_node(&file_name)?;
                let node = node.resolve_link(dir.clone())?;
                <Arc<dyn Directory>>::try_from(node)?
            }
        };
        Ok((dir, next_segment))
    })
}

pub fn create_file(
    start_dir: Arc<dyn Directory>,
    path: &Path,
    mode: FileMode,
) -> Result<Arc<dyn File>> {
    let (dir, last) = find_parent(start_dir, path)?;
    let file_name = match last {
        PathSegment::Root => todo!(),
        PathSegment::Empty => todo!(),
        PathSegment::Dot => todo!(),
        PathSegment::DotDot => todo!(),
        PathSegment::FileName(file_name) => file_name,
    };
    let file = dir.create_file(file_name.into_owned(), mode, false)?;
    Ok(file)
}

pub fn create_directory(
    start_dir: Arc<dyn Directory>,
    path: &Path,
    mode: FileMode,
) -> Result<Arc<dyn Directory>> {
    let (dir, last) = find_parent(start_dir, path)?;
    let file_name = match last {
        PathSegment::Root => todo!(),
        PathSegment::Empty => todo!(),
        PathSegment::Dot => todo!(),
        PathSegment::DotDot => todo!(),
        PathSegment::FileName(file_name) => file_name,
    };
    let file = dir.create_dir(file_name.into_owned(), mode)?;
    Ok(file)
}

pub fn create_link(start_dir: Arc<dyn Directory>, path: &Path, target: Path) -> Result<()> {
    let (dir, last) = find_parent(start_dir, path)?;
    let file_name = match last {
        PathSegment::Root => todo!(),
        PathSegment::Empty => todo!(),
        PathSegment::Dot => todo!(),
        PathSegment::DotDot => todo!(),
        PathSegment::FileName(file_name) => file_name,
    };
    dir.create_link(file_name.into_owned(), target, true)?;
    Ok(())
}

pub fn read_link(start_dir: Arc<dyn Directory>, path: &Path) -> Result<Path> {
    let node = lookup_node(start_dir, path)?;
    match node {
        Node::Link(link) => Ok(link.target),
        Node::File(_) | Node::Directory(_) => Err(Error::inval(())),
    }
}

pub fn mount(
    path: &Path,
    create_node: impl FnOnce(Weak<dyn Directory>) -> Result<Node>,
) -> Result<()> {
    let (dir, last) = find_parent(ROOT_NODE.clone(), path)?;
    let file_name = match last {
        PathSegment::Root => todo!(),
        PathSegment::Empty => todo!(),
        PathSegment::Dot => todo!(),
        PathSegment::DotDot => todo!(),
        PathSegment::FileName(file_name) => file_name,
    };
    let node = create_node(Arc::downgrade(&dir))?;
    dir.mount(file_name.into_owned(), node)?;
    Ok(())
}

pub fn set_mode(start_dir: Arc<dyn Directory>, path: &Path, mode: FileMode) -> Result<()> {
    let node = lookup_and_resolve_node(start_dir, path)?;
    node.set_mode(mode);
    Ok(())
}

pub fn unlink_file(start_dir: Arc<dyn Directory>, path: &Path) -> Result<()> {
    let (parent, segment) = find_parent(start_dir, path)?;
    match segment {
        PathSegment::Root => todo!(),
        PathSegment::Empty => todo!(),
        PathSegment::Dot => todo!(),
        PathSegment::DotDot => todo!(),
        PathSegment::FileName(filename) => parent.delete_non_dir(filename.into_owned()),
    }
}

pub fn unlink_dir(start_dir: Arc<dyn Directory>, path: &Path) -> Result<()> {
    let (parent, segment) = find_parent(start_dir, path)?;
    match segment {
        PathSegment::Root => todo!(),
        PathSegment::Empty => todo!(),
        PathSegment::Dot => todo!(),
        PathSegment::DotDot => todo!(),
        PathSegment::FileName(filename) => parent.delete_dir(filename.into_owned()),
    }
}

pub fn hard_link(
    start_dir: Arc<dyn Directory>,
    start_path: &Path,
    target_dir: Arc<dyn Directory>,
    target_path: &Path,
    symlink_follow: bool,
) -> Result<()> {
    let target_node = if symlink_follow {
        Node::from(lookup_and_resolve_node(target_dir, target_path)?)
    } else {
        lookup_node(target_dir, target_path)?
    };
    let (parent, filename) = find_parent(start_dir, start_path)?;
    match filename {
        PathSegment::Root => todo!(),
        PathSegment::Empty => todo!(),
        PathSegment::Dot => todo!(),
        PathSegment::DotDot => todo!(),
        PathSegment::FileName(filename) => parent.hard_link(filename.into_owned(), target_node),
    }
}
