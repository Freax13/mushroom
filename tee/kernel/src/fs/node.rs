use core::ops::Deref;

use alloc::{
    borrow::Cow,
    collections::{btree_map::Entry, BTreeMap},
    sync::Arc,
};
use spin::{Lazy, Mutex};

use crate::{
    error::{Error, Result},
    user::process::fd::OpenFileDescription,
};

use super::{path::FileName, Path, PathSegment};

pub static ROOT_NODE: Lazy<Arc<TmpFsDirectory>> = Lazy::new(|| Arc::new(TmpFsDirectory::new()));

#[derive(Clone)]
pub enum Node {
    File(Arc<dyn File>),
    Directory(Arc<dyn Directory>),
}

pub trait File: Send + Sync {
    fn is_executable(&self) -> bool;
    fn read_snapshot(&self) -> Result<FileSnapshot>;
}

#[derive(Clone)]
pub struct FileSnapshot(Arc<Cow<'static, [u8]>>);

impl Deref for FileSnapshot {
    type Target = Cow<'static, [u8]>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub trait Directory: Send + Sync {
    fn get_node(&self, file_name: &FileName) -> Result<Node>;
    fn mkdir(&self, file_name: FileName, create_new: bool) -> Result<Arc<dyn Directory>>;
    fn create(&self, file_name: FileName, file: Arc<dyn File>, create_new: bool) -> Result<()>;
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

pub fn create_file(start_node: Node, path: &Path, executable: bool) -> Result<Arc<TmpFsFile>> {
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
    let dynamic_file = Arc::new(TmpFsFile::new(executable, &[]));
    dir.create(file_name.clone(), dynamic_file.clone(), false);
    Ok(dynamic_file)
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

    fn create(&self, path_segment: FileName, file: Arc<dyn File>, create_new: bool) -> Result<()> {
        let mut guard = self.items.lock();
        let entry = guard.entry(path_segment);
        match entry {
            Entry::Vacant(entry) => {
                entry.insert(Node::File(file));
                Ok(())
            }
            Entry::Occupied(mut entry) => {
                if create_new {
                    return Err(Error::Exist);
                }
                match entry.get_mut() {
                    Node::File(f) => {
                        *f = file;
                        Ok(())
                    }
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

    fn read_snapshot(&self) -> Result<FileSnapshot> {
        let content = self.content.lock().clone();
        Ok(FileSnapshot(content))
    }
}

pub struct WriteonlyFile {
    file: Arc<TmpFsFile>,
}

impl WriteonlyFile {
    pub fn new(file: Arc<TmpFsFile>) -> Self {
        Self { file }
    }
}

impl OpenFileDescription for WriteonlyFile {
    fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut guard = self.file.content.lock();
        let content = Arc::make_mut(&mut guard);
        content.to_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
}

pub struct NullFile;

impl File for NullFile {
    fn is_executable(&self) -> bool {
        false
    }

    fn read_snapshot(&self) -> Result<FileSnapshot> {
        Ok(FileSnapshot(Arc::new(Cow::Borrowed(&[]))))
    }
}
