use crate::{
    error::{ensure, err},
    fs::{
        node::{DynINode, FileAccessContext, INode},
        path::{FileName, Path},
    },
    spin::mutex::Mutex,
    user::process::syscall::args::{FileMode, OpenFlags, Timespec},
};
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};

use crate::{error::Result, fs::node::DirEntry, user::process::syscall::args::Stat};

use super::{Events, FileDescriptor, OpenFileDescription};

#[macro_export]
macro_rules! dir_impls {
    () => {
        fn parent(self: Arc<Self>) -> Result<DynINode> {
            Ok(if let Some((parent, _)) = Directory::location(&*self)? {
                parent
            } else {
                self
            })
        }

        fn path(&self, ctx: &mut FileAccessContext) -> Result<Path> {
            Directory::path(self, ctx)
        }

        fn get_node(&self, file_name: &FileName, ctx: &FileAccessContext) -> Result<DynINode> {
            Directory::get_node(self, file_name, ctx)
        }

        fn create_file(
            &self,
            file_name: FileName<'static>,
            mode: FileMode,
        ) -> Result<Result<DynINode, DynINode>> {
            Directory::create_file(self, file_name, mode)
        }

        fn create_dir(&self, file_name: FileName<'static>, mode: FileMode) -> Result<DynINode> {
            Directory::create_dir(self, file_name, mode)
        }

        fn create_link(
            &self,
            file_name: FileName<'static>,
            target: Path,
            create_new: bool,
        ) -> Result<DynINode> {
            Directory::create_link(self, file_name, target, create_new)
        }

        fn create_char_dev(
            &self,
            file_name: FileName<'static>,
            major: u16,
            minor: u8,
        ) -> Result<DynINode> {
            Directory::create_char_dev(self, file_name, major, minor)
        }

        fn hard_link(&self, file_name: FileName<'static>, node: DynINode) -> Result<()> {
            Directory::hard_link(self, file_name, node)
        }

        fn list_entries(&self, ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
            Ok(Directory::list_entries(self, ctx))
        }

        fn delete(&self, file_name: FileName<'static>) -> Result<()> {
            Directory::delete(self, file_name)
        }

        fn delete_non_dir(&self, file_name: FileName<'static>) -> Result<()> {
            Directory::delete_non_dir(self, file_name)
        }

        fn delete_dir(&self, file_name: FileName<'static>) -> Result<()> {
            Directory::delete_dir(self, file_name)
        }
    };
}

pub trait Directory: INode {
    fn location(&self) -> Result<Option<(DynINode, FileName<'static>)>>;
    fn path(&self, ctx: &mut FileAccessContext) -> Result<Path> {
        let Some((parent, name)) = Directory::location(self)? else {
            return Path::new(b"/".to_vec());
        };
        let mut path = parent.path(ctx)?;
        path = path.join_segment(&name);
        Ok(path)
    }
    fn get_node(&self, file_name: &FileName, ctx: &FileAccessContext) -> Result<DynINode>;
    /// Atomically create a new file or return the existing node.
    fn create_file(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
    ) -> Result<Result<DynINode, DynINode>>;
    fn create_dir(&self, file_name: FileName<'static>, mode: FileMode) -> Result<DynINode>;
    fn create_link(
        &self,
        file_name: FileName<'static>,
        target: Path,
        create_new: bool,
    ) -> Result<DynINode>;
    fn create_char_dev(
        &self,
        file_name: FileName<'static>,
        major: u16,
        minor: u8,
    ) -> Result<DynINode>;
    fn hard_link(&self, file_name: FileName<'static>, node: DynINode) -> Result<()>;
    fn list_entries(&self, ctx: &mut FileAccessContext) -> Vec<DirEntry>;
    fn delete(&self, file_name: FileName<'static>) -> Result<()>;
    fn delete_non_dir(&self, file_name: FileName<'static>) -> Result<()>;
    fn delete_dir(&self, file_name: FileName<'static>) -> Result<()>;
}

pub fn open_dir(dir: Arc<dyn Directory>, flags: OpenFlags) -> Result<FileDescriptor> {
    Ok(FileDescriptor::from(DirectoryFileDescription {
        flags,
        dir,
        entries: Mutex::new(None),
    }))
}

struct DirectoryFileDescription {
    flags: OpenFlags,
    dir: Arc<dyn Directory>,
    entries: Mutex<Option<Vec<DirEntry>>>,
}

impl OpenFileDescription for DirectoryFileDescription {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn update_times(&self, ctime: Timespec, atime: Option<Timespec>, mtime: Option<Timespec>) {
        self.dir.update_times(ctime, atime, mtime);
    }

    fn stat(&self) -> Stat {
        self.dir.stat()
    }

    fn as_dir(&self, _ctx: &mut FileAccessContext) -> Result<DynINode> {
        Ok(self.dir.clone())
    }

    fn getdents64(
        &self,
        mut capacity: usize,
        ctx: &mut FileAccessContext,
    ) -> Result<Vec<DirEntry>> {
        let mut guard = self.entries.lock();
        let entries = guard.get_or_insert_with(|| Directory::list_entries(&*self.dir, ctx));

        let mut ret = Vec::new();
        while let Some(last) = entries.last() {
            if let Some(new_capacity) = capacity.checked_sub(last.len()) {
                ret.push(entries.pop().unwrap());
                capacity = new_capacity;
            } else {
                ensure!(!ret.is_empty(), Inval);
                break;
            }
        }

        Ok(ret)
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & Events::READ
    }
}

/// The location of a directory in a file system.
pub struct Location<T>(LocationImpl<T>);

impl<T> Location<T>
where
    T: Directory,
{
    pub const fn root() -> Self {
        Self(LocationImpl::Root)
    }

    /// Returns the parent of the directory and the filename of this directory
    /// in that directory. Returns `None` if the parent is the root.
    pub fn get(&self) -> Result<Option<(DynINode, FileName<'static>)>> {
        match &self.0 {
            LocationImpl::Root => Ok(None),
            LocationImpl::Directory(parent) => parent.get(),
            LocationImpl::Mount(parent) => parent.get(),
        }
    }
}

enum LocationImpl<T> {
    Root,
    Directory(DirectoryLocation<T>),
    Mount(MountLocation),
}

pub struct DirectoryLocation<T>(Mutex<DirectoryLocationImpl<T>>);

struct DirectoryLocationImpl<T> {
    parent: Weak<T>,
    /// The name of the directory in `parent`.
    file_name: FileName<'static>,
}

impl<T> DirectoryLocation<T>
where
    T: Directory,
{
    pub fn new(parent: Weak<T>, file_name: FileName<'static>) -> Self {
        Self(Mutex::new(DirectoryLocationImpl { parent, file_name }))
    }

    /// Returns the parent of the directory and the filename of this directory
    /// in that directory.
    pub fn get(&self) -> Result<Option<(DynINode, FileName<'static>)>> {
        let guard = self.0.lock();
        let node = guard.parent.upgrade().ok_or(err!(NoEnt))?;
        let file_name = guard.file_name.clone();
        Ok(Some((node, file_name)))
    }
}

impl<T> From<DirectoryLocation<T>> for Location<T> {
    fn from(value: DirectoryLocation<T>) -> Self {
        Self(LocationImpl::Directory(value))
    }
}

pub struct MountLocation {
    parent: Weak<dyn INode>,
    /// The name of the directory in `parent`.
    file_name: FileName<'static>,
}

impl MountLocation {
    pub fn new(parent: Weak<dyn INode>, file_name: FileName<'static>) -> Self {
        Self { parent, file_name }
    }

    /// Returns the parent of the directory and the filename of this directory
    /// in that directory.
    pub fn get(&self) -> Result<Option<(DynINode, FileName<'static>)>> {
        let node = self.parent.upgrade().ok_or(err!(NoEnt))?;
        let file_name = self.file_name.clone();
        Ok(Some((node, file_name)))
    }
}

impl<T> From<MountLocation> for Location<T> {
    fn from(value: MountLocation) -> Self {
        Self(LocationImpl::Mount(value))
    }
}
