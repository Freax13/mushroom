use alloc::sync::Weak;

use crate::{
    error::{Error, Result},
    fs::{
        node::{lookup_and_resolve_node, DynINode, FileAccessContext, INode},
        path::Path,
    },
    user::process::syscall::args::{OpenFlags, Stat},
};

use super::OpenFileDescription;

pub struct PathFd {
    start_node: Weak<dyn INode>,
    path: Path,
}

impl PathFd {
    pub fn new(start_node: Weak<dyn INode>, path: Path) -> Self {
        Self { start_node, path }
    }
}

impl OpenFileDescription for PathFd {
    fn flags(&self) -> OpenFlags {
        OpenFlags::empty()
    }

    fn stat(&self) -> Stat {
        todo!()
    }

    fn as_dir(&self, ctx: &mut FileAccessContext) -> Result<DynINode> {
        lookup_and_resolve_node(
            self.start_node.upgrade().ok_or(Error::no_ent(()))?,
            &self.path,
            ctx,
        )
    }
}
