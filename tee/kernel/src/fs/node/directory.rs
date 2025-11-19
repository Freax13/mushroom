use alloc::vec::Vec;

use crate::{
    error::Result,
    fs::{
        fd::unix_socket::StreamUnixSocket,
        node::{DirEntry, DynINode, FileAccessContext, INode, Link, LinkLocation},
        path::{FileName, Path},
    },
    user::{
        syscall::args::FileMode,
        thread::{Gid, Uid},
    },
};

macro_rules! dir_impls {
    () => {
        fn get_node(&self, file_name: &FileName, ctx: &FileAccessContext) -> Result<Link> {
            Directory::get_node(self, file_name, ctx)
        }

        fn create_file(
            &self,
            file_name: FileName<'static>,
            mode: FileMode,
            ctx: &FileAccessContext,
        ) -> Result<Result<Link, Link>> {
            Directory::create_file(self, file_name, mode, ctx)
        }

        fn create_tmp_file(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<Link> {
            Directory::create_tmp_file(self, mode, ctx)
        }

        fn create_dir(
            &self,
            file_name: FileName<'static>,
            mode: FileMode,
            ctx: &FileAccessContext,
        ) -> Result<DynINode> {
            Directory::create_dir(self, file_name, mode, ctx)
        }

        fn create_link(
            &self,
            file_name: FileName<'static>,
            target: Path,
            uid: Uid,
            gid: Gid,
            create_new: bool,
        ) -> Result<()> {
            Directory::create_link(self, file_name, target, uid, gid, create_new)
        }

        fn create_char_dev(
            &self,
            file_name: FileName<'static>,
            major: u16,
            minor: u8,
            mode: FileMode,
            uid: Uid,
            gid: Gid,
        ) -> Result<()> {
            Directory::create_char_dev(self, file_name, major, minor, mode, uid, gid)
        }

        fn create_fifo(
            &self,
            file_name: FileName<'static>,
            mode: FileMode,
            uid: Uid,
            gid: Gid,
        ) -> Result<()> {
            Directory::create_fifo(self, file_name, mode, uid, gid)
        }

        fn bind_socket(
            &self,
            file_name: FileName<'static>,
            mode: FileMode,
            uid: Uid,
            gid: Gid,
            socket: &crate::fs::fd::unix_socket::StreamUnixSocket,
            socketname: &Path,
        ) -> Result<()> {
            Directory::bind_socket(self, file_name, mode, uid, gid, socket, socketname)
        }

        fn is_empty_dir(&self) -> bool {
            Directory::is_empty(self)
        }

        fn delete_non_dir(
            &self,
            file_name: FileName<'static>,
            ctx: &FileAccessContext,
        ) -> Result<()> {
            Directory::delete_non_dir(self, file_name, ctx)
        }

        fn delete_dir(&self, file_name: FileName<'static>, ctx: &FileAccessContext) -> Result<()> {
            Directory::delete_dir(self, file_name, ctx)
        }

        fn rename(
            &self,
            oldname: FileName<'static>,
            check_is_dir: bool,
            new_dir: DynINode,
            newname: FileName<'static>,
            no_replace: bool,
            ctx: &FileAccessContext,
        ) -> Result<()> {
            Directory::rename(
                self,
                oldname,
                check_is_dir,
                new_dir,
                newname,
                no_replace,
                ctx,
            )
        }

        fn exchange(
            &self,
            oldname: FileName<'static>,
            new_dir: DynINode,
            newname: FileName<'static>,
            ctx: &FileAccessContext,
        ) -> Result<()> {
            Directory::exchange(self, oldname, new_dir, newname, ctx)
        }

        fn hard_link(
            &self,
            oldname: FileName<'static>,
            follow_symlink: bool,
            new_dir: DynINode,
            newname: FileName<'static>,
            ctx: &FileAccessContext,
        ) -> Result<Option<Path>> {
            Directory::hard_link(self, oldname, follow_symlink, new_dir, newname, ctx)
        }

        fn truncate(&self, _len: usize, _: &FileAccessContext) -> Result<()> {
            bail!(IsDir)
        }
    };
}

pub(crate) use dir_impls;

pub trait Directory: INode {
    fn location(&self) -> &LinkLocation;
    fn get_node(&self, file_name: &FileName, ctx: &FileAccessContext) -> Result<Link>;
    /// Atomically create a new file or return the existing node.
    fn create_file(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
        ctx: &FileAccessContext,
    ) -> Result<Result<Link, Link>>;
    fn create_tmp_file(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<Link>;
    fn create_dir(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
        ctx: &FileAccessContext,
    ) -> Result<DynINode>;
    fn create_link(
        &self,
        file_name: FileName<'static>,
        target: Path,
        uid: Uid,
        gid: Gid,
        create_new: bool,
    ) -> Result<()>;
    fn create_char_dev(
        &self,
        file_name: FileName<'static>,
        major: u16,
        minor: u8,
        mode: FileMode,
        uid: Uid,
        gid: Gid,
    ) -> Result<()>;
    fn create_fifo(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
        uid: Uid,
        gid: Gid,
    ) -> Result<()>;
    fn bind_socket(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
        uid: Uid,
        gid: Gid,
        socket: &StreamUnixSocket,
        socketname: &Path,
    ) -> Result<()>;
    fn is_empty(&self) -> bool;
    fn list_entries(&self, ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>>;
    fn delete_non_dir(&self, file_name: FileName<'static>, ctx: &FileAccessContext) -> Result<()>;
    fn delete_dir(&self, file_name: FileName<'static>, ctx: &FileAccessContext) -> Result<()>;
    fn rename(
        &self,
        oldname: FileName<'static>,
        check_is_dir: bool,
        new_dir: DynINode,
        newname: FileName<'static>,
        no_replace: bool,
        ctx: &FileAccessContext,
    ) -> Result<()>;
    fn exchange(
        &self,
        oldname: FileName<'static>,
        new_dir: DynINode,
        newname: FileName<'static>,
        ctx: &FileAccessContext,
    ) -> Result<()>;
    fn hard_link(
        &self,
        oldname: FileName<'static>,
        follow_symlink: bool,
        new_dir: DynINode,
        newname: FileName<'static>,
        ctx: &FileAccessContext,
    ) -> Result<Option<Path>>;
}
