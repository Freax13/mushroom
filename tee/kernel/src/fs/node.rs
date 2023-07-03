use core::{
    any::Any,
    cmp,
    iter::repeat,
    ops::Deref,
    sync::atomic::{AtomicU64, Ordering},
};

use alloc::{
    borrow::Cow,
    collections::{btree_map::Entry, BTreeMap},
    sync::Arc,
    vec::Vec,
};
use spin::{Lazy, Mutex};

use crate::{
    error::{Error, Result},
    user::process::syscall::args::{FileMode, FileType, FileTypeAndMode, Stat},
};

use super::path::{FileName, Path, PathSegment};

pub mod special;

pub static ROOT_NODE: Lazy<Arc<TmpFsDirectory>> =
    Lazy::new(|| Arc::new(TmpFsDirectory::new(FileMode::from_bits_truncate(0o755))));

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
    let mut path = path.clone();
    path.canonicalize()?;
    let res = path.segments().try_fold(
        (start_dir.clone(), Node::Directory(start_dir)),
        |(start_dir, node), segment| -> Result<_> {
            let node = node.resolve_link_recursive(start_dir.clone(), recursion)?;
            let dir = <Arc<dyn Directory>>::try_from(node)?;

            match segment {
                PathSegment::Root => Ok((ROOT_NODE.clone(), Node::Directory(ROOT_NODE.clone()))),
                PathSegment::Empty | PathSegment::Dot => Ok((start_dir, Node::Directory(dir))),
                PathSegment::DotDot => todo!(),
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

pub struct TmpFsDirectory {
    ino: u64,
    internal: Mutex<TmpFsDirectoryInternal>,
}

struct TmpFsDirectoryInternal {
    mode: FileMode,
    items: BTreeMap<FileName<'static>, Node>,
}

impl TmpFsDirectory {
    pub fn new(mode: FileMode) -> Self {
        Self {
            ino: new_ino(),
            internal: Mutex::new(TmpFsDirectoryInternal {
                mode,
                items: BTreeMap::new(),
            }),
        }
    }

    /// Mount a special file into the tmpfs directory.
    pub fn mount(&self, path_segment: FileName<'static>, file: impl File) {
        let mut guard = self.internal.lock();
        guard.items.insert(path_segment, Node::File(Arc::new(file)));
    }
}

impl Directory for TmpFsDirectory {
    fn stat(&self) -> Stat {
        let guard = self.internal.lock();
        let mode = FileTypeAndMode::new(FileType::Dir, guard.mode);
        // FIXME: Fill in more values.
        Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode,
            uid: 0,
            gid: 0,
            _pad0: 0,
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: 0,
            atime_nsec: 0,
            mtime: 0,
            mtime_nsec: 0,
            ctime: 0,
            ctime_nsec: 0,
            _unused: [0; 3],
        }
    }

    fn set_mode(&self, mode: FileMode) {
        self.internal.lock().mode = mode;
    }

    fn get_node(&self, path_segment: &FileName) -> Result<Node> {
        self.internal
            .lock()
            .items
            .get(path_segment)
            .cloned()
            .ok_or(Error::no_ent(()))
    }

    fn create_dir(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
    ) -> Result<Arc<dyn Directory>> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name);
        match entry {
            Entry::Vacant(entry) => {
                let dir = Arc::new(TmpFsDirectory::new(mode));
                entry.insert(Node::Directory(dir.clone()));
                Ok(dir)
            }
            Entry::Occupied(_) => Err(Error::exist(())),
        }
    }

    fn create_file(
        &self,
        path_segment: FileName<'static>,
        mode: FileMode,
        create_new: bool,
    ) -> Result<Arc<dyn File>> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(path_segment);
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

    fn create_link(
        &self,
        file_name: FileName<'static>,
        target: Path,
        create_new: bool,
    ) -> Result<()> {
        let mut guard = self.internal.lock();
        let entry = guard.items.entry(file_name);
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

    fn hard_link(&self, file_name: FileName<'static>, node: Node) -> Result<()> {
        self.internal.lock().items.insert(file_name.clone(), node);
        Ok(())
    }

    fn list_entries(&self) -> Vec<DirEntry> {
        let guard = self.internal.lock();

        let mut entries = Vec::with_capacity(2 + guard.items.len());
        entries.push(DirEntry {
            ino: 0,
            ty: FileType::Dir,
            name: DirEntryName::Dot,
        });
        entries.push(DirEntry {
            ino: 0,
            ty: FileType::Dir,
            name: DirEntryName::DotDot,
        });
        for (name, node) in guard.items.iter() {
            let stat = node.stat();
            entries.push(DirEntry {
                ino: stat.ino,
                ty: stat.mode.ty(),
                name: DirEntryName::from(name.clone()),
            })
        }

        entries
    }

    fn delete_non_dir(&self, file_name: FileName<'static>) -> Result<()> {
        let mut guard = self.internal.lock();
        let node = guard.items.entry(file_name);
        let Entry::Occupied(entry) = node else {
            return Err(Error::no_ent(()));
        };
        if matches!(entry.get(), Node::Directory(_)) {
            return Err(Error::is_dir(()));
        }
        entry.remove();
        Ok(())
    }

    fn delete_dir(&self, file_name: FileName<'static>) -> Result<()> {
        let mut guard = self.internal.lock();
        let node = guard.items.entry(file_name);
        let Entry::Occupied(entry) = node else {
            return Err(Error::no_ent(()));
        };
        if !matches!(entry.get(), Node::Directory(_)) {
            return Err(Error::is_dir(()));
        }
        entry.remove();
        Ok(())
    }
}

pub struct TmpFsFile {
    ino: u64,
    internal: Mutex<TmpFsFileInternal>,
}

struct TmpFsFileInternal {
    content: Arc<Cow<'static, [u8]>>,
    mode: FileMode,
}

impl TmpFsFile {
    pub fn new(mode: FileMode, content: &'static [u8]) -> Self {
        Self {
            ino: new_ino(),
            internal: Mutex::new(TmpFsFileInternal {
                content: Arc::new(Cow::Borrowed(content)),
                mode,
            }),
        }
    }
}

impl File for TmpFsFile {
    fn stat(&self) -> Stat {
        let guard = self.internal.lock();
        let mode = FileTypeAndMode::new(FileType::File, guard.mode);
        let size = guard.content.len() as i64;

        // FIXME: Fill in more values.
        Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode,
            uid: 0,
            gid: 0,
            _pad0: 0,
            rdev: 0,
            size,
            blksize: 0,
            blocks: 0,
            atime: 0,
            atime_nsec: 0,
            mtime: 0,
            mtime_nsec: 0,
            ctime: 0,
            ctime_nsec: 0,
            _unused: [0; 3],
        }
    }

    fn set_mode(&self, mode: FileMode) {
        self.internal.lock().mode = mode;
    }

    fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let guard = self.internal.lock();
        let slice = guard.content.get(offset..).ok_or(Error::inval(()))?;
        let len = cmp::min(slice.len(), buf.len());
        buf[..len].copy_from_slice(&slice[..len]);
        Ok(len)
    }

    fn write(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        let mut guard = self.internal.lock();
        let bytes = Arc::make_mut(&mut guard.content);
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
        let content = self.internal.lock().content.clone();
        Ok(FileSnapshot(content))
    }
}
