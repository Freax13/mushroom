use core::{
    ops::Deref,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    spin::lazy::Lazy,
    user::process::{
        syscall::args::{ExtractableThreadState, OpenFlags},
        thread::ThreadGuard,
    },
};
use alloc::{
    borrow::Cow,
    sync::{Arc, Weak},
    vec::Vec,
};

use crate::{
    error::{Error, Result},
    user::process::syscall::args::{FileMode, FileType, Stat},
};

use self::tmpfs::TmpFsDir;

use super::{
    fd::{FileDescriptor, FileDescriptorTable},
    path::{FileName, Path, PathSegment},
};

pub mod devtmpfs;
pub mod fdfs;
pub mod tmpfs;

pub static ROOT_NODE: Lazy<Arc<TmpFsDir>> =
    Lazy::new(|| TmpFsDir::root(FileMode::from_bits_truncate(0o755)));

pub fn new_ino() -> u64 {
    static INO_COUNTER: AtomicU64 = AtomicU64::new(1);
    INO_COUNTER.fetch_add(1, Ordering::SeqCst)
}

pub type DynINode = Arc<dyn INode>;

pub trait INode: Send + Sync + 'static {
    fn ty(&self) -> FileType {
        self.stat().mode.ty()
    }
    fn stat(&self) -> Stat;

    fn open(&self, flags: OpenFlags) -> Result<FileDescriptor>;

    fn mode(&self) -> FileMode {
        self.stat().mode.mode()
    }

    fn set_mode(&self, mode: FileMode);

    // Directory related functions.

    fn parent(&self) -> Result<DynINode> {
        Err(Error::not_dir(()))
    }

    fn get_node(&self, file_name: &FileName, ctx: &FileAccessContext) -> Result<DynINode> {
        let _ = file_name;
        let _ = ctx;
        Err(Error::not_dir(()))
    }

    fn create_file(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
        create_new: bool,
    ) -> Result<DynINode> {
        let _ = file_name;
        let _ = mode;
        let _ = create_new;
        Err(Error::not_dir(()))
    }

    fn create_dir(&self, file_name: FileName<'static>, mode: FileMode) -> Result<DynINode> {
        let _ = file_name;
        let _ = mode;
        Err(Error::not_dir(()))
    }

    fn create_link(
        &self,
        file_name: FileName<'static>,
        target: Path,
        create_new: bool,
    ) -> Result<DynINode> {
        let _ = file_name;
        let _ = target;
        let _ = create_new;
        Err(Error::not_dir(()))
    }

    fn hard_link(&self, file_name: FileName<'static>, node: DynINode) -> Result<()> {
        let _ = file_name;
        let _ = node;
        Err(Error::not_dir(()))
    }

    fn mount(&self, file_name: FileName<'static>, node: DynINode) -> Result<()> {
        let _ = file_name;
        let _ = node;
        Err(Error::not_dir(()))
    }

    fn list_entries(&self, ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
        let _ = ctx;
        Err(Error::not_dir(()))
    }

    fn delete_non_dir(&self, file_name: FileName<'static>) -> Result<()> {
        let _ = file_name;
        Err(Error::not_dir(()))
    }

    fn delete_dir(&self, file_name: FileName<'static>) -> Result<()> {
        let _ = file_name;
        Err(Error::not_dir(()))
    }

    // File related functions

    fn read_snapshot(&self) -> Result<FileSnapshot> {
        Err(Error::acces(()))
    }

    // Symlink related functions

    /// Try to follow a symlink. Returns a tuple of where the parent directory
    /// of the resolved node and the node.
    /// Returns `None` if the node doesn't contain a symlink.
    fn try_resolve_link(
        &self,
        start_dir: DynINode,
        ctx: &mut FileAccessContext,
    ) -> Result<Option<(DynINode, DynINode)>> {
        let _ = start_dir;
        let _ = ctx;
        Ok(None)
    }

    fn read_link(&self) -> Result<Path> {
        Err(Error::inval(()))
    }
}

/// Repeatedly follow symlinks until the end.
fn resolve_links(
    mut node: DynINode,
    mut start_dir: DynINode,
    ctx: &mut FileAccessContext,
) -> Result<DynINode> {
    while let Some(next) = node.try_resolve_link(start_dir.clone(), ctx)? {
        (start_dir, node) = next;
    }
    Ok(node)
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

pub struct FileAccessContext {
    pub fdtable: Arc<FileDescriptorTable>,
    symlink_recursion_limit: u16,
}

impl FileAccessContext {
    /// Record that a symlink was followed and return an error if the recursion
    /// limit was exceeded.
    pub fn follow_symlink(&mut self) -> Result<()> {
        self.symlink_recursion_limit = self
            .symlink_recursion_limit
            .checked_sub(1)
            .ok_or_else(|| Error::r#loop(()))?;
        Ok(())
    }
}

impl ExtractableThreadState for FileAccessContext {
    fn extract_from_thread(guard: &ThreadGuard) -> Self {
        Self {
            fdtable: ExtractableThreadState::extract_from_thread(guard),
            symlink_recursion_limit: 16,
        }
    }
}

/// Find a node.
pub fn lookup_node(
    start_dir: DynINode,
    path: &Path,
    ctx: &mut FileAccessContext,
) -> Result<DynINode> {
    let (_, node) = lookup_node_with_parent(start_dir, path, ctx)?;
    Ok(node)
}

// Find a node while taking recursion limits into account.
fn lookup_node_with_parent(
    start_dir: DynINode,
    path: &Path,
    ctx: &mut FileAccessContext,
) -> Result<(DynINode, DynINode)> {
    let res = path.segments().try_fold(
        (start_dir.clone(), start_dir),
        |(start_dir, node), segment| -> Result<_> {
            let node = resolve_links(node, start_dir.clone(), ctx)?;

            match segment {
                PathSegment::Root => Ok((ROOT_NODE.clone(), ROOT_NODE.clone())),
                PathSegment::Empty | PathSegment::Dot => Ok((start_dir, node)),
                PathSegment::DotDot => {
                    let parent = node.parent()?;
                    Ok((parent.clone(), parent))
                }
                PathSegment::FileName(file_name) => {
                    let next_node = node.get_node(&file_name, ctx)?;
                    Ok((node, next_node))
                }
            }
        },
    );
    res
}

// Find a node and resolve links.
pub fn lookup_and_resolve_node(
    start_dir: DynINode,
    path: &Path,
    ctx: &mut FileAccessContext,
) -> Result<DynINode> {
    let (dir, node) = lookup_node_with_parent(start_dir.clone(), path, ctx)?;
    resolve_links(node, dir, ctx)
}

fn find_parent<'a>(
    start_dir: DynINode,
    path: &'a Path,
    ctx: &mut FileAccessContext,
) -> Result<(DynINode, PathSegment<'a>)> {
    let mut segments = path.segments();
    let first = segments.next().ok_or_else(|| Error::inval(()))?;
    segments.try_fold((start_dir, first), |(dir, segment), next_segment| {
        let dir = match segment {
            PathSegment::Root => ROOT_NODE.clone(),
            PathSegment::Empty | PathSegment::Dot => dir,
            PathSegment::DotDot => unreachable!(),
            PathSegment::FileName(file_name) => {
                let node = dir.get_node(&file_name, ctx)?;
                resolve_links(node, dir, ctx)?
            }
        };
        Ok((dir, next_segment))
    })
}

pub fn create_file(
    start_dir: DynINode,
    path: &Path,
    mode: FileMode,
    ctx: &mut FileAccessContext,
) -> Result<DynINode> {
    let (dir, last) = find_parent(start_dir, path, ctx)?;
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
    start_dir: DynINode,
    path: &Path,
    mode: FileMode,
    ctx: &mut FileAccessContext,
) -> Result<DynINode> {
    let (dir, last) = find_parent(start_dir, path, ctx)?;
    match last {
        PathSegment::Root | PathSegment::Empty | PathSegment::Dot | PathSegment::DotDot => {
            Err(Error::exist(()))
        }
        PathSegment::FileName(file_name) => dir.create_dir(file_name.into_owned(), mode),
    }
}

pub fn create_link(
    start_dir: DynINode,
    path: &Path,
    target: Path,
    ctx: &mut FileAccessContext,
) -> Result<()> {
    let (dir, last) = find_parent(start_dir, path, ctx)?;
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

pub fn read_link(start_dir: DynINode, path: &Path, ctx: &mut FileAccessContext) -> Result<Path> {
    let node = lookup_node(start_dir, path, ctx)?;
    node.read_link()
}

pub fn mount(
    path: &Path,
    create_node: impl FnOnce(Weak<dyn INode>) -> Result<DynINode>,
    ctx: &mut FileAccessContext,
) -> Result<()> {
    let (dir, last) = find_parent(ROOT_NODE.clone(), path, ctx)?;
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

pub fn set_mode(
    start_dir: DynINode,
    path: &Path,
    mode: FileMode,
    ctx: &mut FileAccessContext,
) -> Result<()> {
    let node = lookup_and_resolve_node(start_dir, path, ctx)?;
    node.set_mode(mode);
    Ok(())
}

pub fn unlink_file(start_dir: DynINode, path: &Path, ctx: &mut FileAccessContext) -> Result<()> {
    let (parent, segment) = find_parent(start_dir, path, ctx)?;
    match segment {
        PathSegment::Root | PathSegment::Empty | PathSegment::Dot | PathSegment::DotDot => {
            Err(Error::is_dir(()))
        }
        PathSegment::FileName(filename) => parent.delete_non_dir(filename.into_owned()),
    }
}

pub fn unlink_dir(start_dir: DynINode, path: &Path, ctx: &mut FileAccessContext) -> Result<()> {
    let (parent, segment) = find_parent(start_dir, path, ctx)?;
    match segment {
        PathSegment::Root => todo!(),
        PathSegment::Empty => todo!(),
        PathSegment::Dot => todo!(),
        PathSegment::DotDot => todo!(),
        PathSegment::FileName(filename) => parent.delete_dir(filename.into_owned()),
    }
}

pub fn hard_link(
    start_dir: DynINode,
    start_path: &Path,
    target_dir: DynINode,
    target_path: &Path,
    symlink_follow: bool,
    ctx: &mut FileAccessContext,
) -> Result<()> {
    let target_node = if symlink_follow {
        lookup_and_resolve_node(target_dir, target_path, ctx)?
    } else {
        lookup_node(target_dir, target_path, ctx)?
    };
    let (parent, filename) = find_parent(start_dir, start_path, ctx)?;
    match filename {
        PathSegment::Root => todo!(),
        PathSegment::Empty => todo!(),
        PathSegment::Dot => todo!(),
        PathSegment::DotDot => todo!(),
        PathSegment::FileName(filename) => parent.hard_link(filename.into_owned(), target_node),
    }
}

pub fn rename(
    oldd: DynINode,
    oldname: &Path,
    newd: DynINode,
    newname: &Path,
    ctx: &mut FileAccessContext,
) -> Result<()> {
    let (old_parent, segment) = find_parent(oldd, oldname, ctx)?;
    let oldname = match segment {
        PathSegment::Root | PathSegment::Empty | PathSegment::Dot | PathSegment::DotDot => {
            return Err(Error::is_dir(()))
        }
        PathSegment::FileName(filename) => filename,
    };

    let (new_parent, segment) = find_parent(newd, newname, ctx)?;
    let newname = match segment {
        PathSegment::Root | PathSegment::Empty | PathSegment::Dot | PathSegment::DotDot => {
            return Err(Error::is_dir(()))
        }
        PathSegment::FileName(filename) => filename,
    };

    let node = old_parent.get_node(&oldname, ctx)?;
    new_parent.mount(newname.into_owned(), node)?;
    old_parent.delete_non_dir(oldname.into_owned())?;

    Ok(())
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

pub struct OldDirEntry(pub DirEntry);

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
