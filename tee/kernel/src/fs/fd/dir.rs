use crate::{
    fs::{
        node::{DirEntryName, DynINode, FileAccessContext, INode},
        path::{FileName, Path},
    },
    spin::mutex::Mutex,
    user::process::syscall::args::{FileMode, OpenFlags},
};
use alloc::{sync::Arc, vec::Vec};

use crate::{
    error::{Error, Result},
    fs::node::DirEntry,
    user::process::syscall::args::Stat,
};

use super::{FileDescriptor, OpenFileDescription};

#[macro_export]
macro_rules! dir_impls {
    () => {
        fn parent(&self) -> Result<DynINode> {
            Directory::parent(self)
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
            create_new: bool,
        ) -> Result<DynINode> {
            Directory::create_file(self, file_name, mode, create_new)
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

        fn hard_link(&self, file_name: FileName<'static>, node: DynINode) -> Result<()> {
            Directory::hard_link(self, file_name, node)
        }

        fn list_entries(&self, ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
            Ok(Directory::list_entries(self, ctx))
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
    fn parent(&self) -> Result<DynINode>;
    fn path(&self, ctx: &mut FileAccessContext) -> Result<Path> {
        let parent = Directory::parent(self)?;

        let stat = self.stat();
        let parent_stat = parent.stat();

        // If the directory is its own parent, then it's the root.
        if parent_stat.ino == stat.ino {
            return Path::new(b"/".to_vec());
        }

        let mut path = parent.path(ctx)?;

        // Find the directory in its parent.
        let entries = parent.list_entries(ctx)?;
        let entry = entries
            .into_iter()
            .find(|e| e.ino == stat.ino)
            .ok_or_else(|| Error::no_ent(()))?;

        let DirEntryName::FileName(name) = entry.name else {
            unreachable!()
        };

        path.join_segment(&name);

        Ok(path)
    }
    fn get_node(&self, file_name: &FileName, ctx: &FileAccessContext) -> Result<DynINode>;
    fn create_file(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
        create_new: bool,
    ) -> Result<DynINode>;
    fn create_dir(&self, file_name: FileName<'static>, mode: FileMode) -> Result<DynINode>;
    fn create_link(
        &self,
        file_name: FileName<'static>,
        target: Path,
        create_new: bool,
    ) -> Result<DynINode>;
    fn hard_link(&self, file_name: FileName<'static>, node: DynINode) -> Result<()>;
    fn list_entries(&self, ctx: &mut FileAccessContext) -> Vec<DirEntry>;
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

    fn stat(&self) -> Stat {
        self.dir.stat()
    }

    fn as_dir(&self) -> Result<DynINode> {
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
                if ret.is_empty() {
                    return Err(Error::inval(()));
                }
                break;
            }
        }

        Ok(ret)
    }
}
