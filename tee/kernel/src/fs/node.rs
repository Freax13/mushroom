use core::{
    any::Any,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    error::{bail, ensure, err},
    spin::lazy::Lazy,
    user::process::{
        syscall::args::{ExtractableThreadState, OpenFlags, Timespec},
        thread::{Gid, ThreadGuard, Uid},
        Process,
    },
};
use alloc::boxed::Box;
use alloc::sync::Arc;
use async_trait::async_trait;
use tmpfs::TmpFs;

use crate::{
    error::Result,
    user::process::syscall::args::{FileMode, FileType, Stat},
};

use self::{
    directory::{Location, MountLocation},
    tmpfs::TmpFsDir,
};

use super::{
    fd::{FileDescriptor, FileLockRecord},
    path::{FileName, Path, PathSegment},
    FileSystem,
};

pub mod directory;

pub mod devtmpfs;
pub mod procfs;
pub mod tmpfs;

pub static ROOT_NODE: Lazy<Arc<TmpFsDir>> = Lazy::new(|| {
    TmpFsDir::new(
        TmpFs::new(),
        Location::root(),
        FileMode::from_bits_truncate(0o755),
        Uid::SUPER_USER,
        Gid::SUPER_USER,
    )
});

pub fn new_ino() -> u64 {
    static INO_COUNTER: AtomicU64 = AtomicU64::new(1);
    INO_COUNTER.fetch_add(1, Ordering::SeqCst)
}

pub fn new_dev() -> u64 {
    static DEV_COUNTER: AtomicU64 = AtomicU64::new(1);
    DEV_COUNTER.fetch_add(1, Ordering::SeqCst)
}

pub type DynINode = Arc<dyn INode>;

#[async_trait]
pub trait INode: Any + Send + Sync + 'static {
    fn ty(&self) -> Result<FileType> {
        self.stat().map(|stat| stat.mode.ty())
    }
    fn stat(&self) -> Result<Stat>;
    fn fs(&self) -> Result<Arc<dyn FileSystem>>;

    fn open(&self, path: Path, flags: OpenFlags) -> Result<FileDescriptor>;

    async fn async_open(self: Arc<Self>, path: Path, flags: OpenFlags) -> Result<FileDescriptor> {
        self.open(path, flags)
    }

    fn mode(&self) -> Result<FileMode> {
        self.stat().map(|stat| stat.mode.mode())
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()>;

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()>;

    fn update_times(&self, ctime: Timespec, atime: Option<Timespec>, mtime: Option<Timespec>);

    // Directory related functions.

    fn path(&self, _ctx: &mut FileAccessContext) -> Result<Path> {
        bail!(NotDir)
    }

    fn parent(self: Arc<Self>) -> Result<DynINode> {
        bail!(NotDir)
    }

    fn get_node(&self, file_name: &FileName, ctx: &FileAccessContext) -> Result<DynINode> {
        let _ = file_name;
        let _ = ctx;
        bail!(NotDir)
    }

    /// Atomically create a new file or return the existing node.
    fn create_file(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
        user: Uid,
        group: Gid,
    ) -> Result<Result<DynINode, DynINode>> {
        let _ = file_name;
        let _ = mode;
        let _ = user;
        let _ = group;
        bail!(NotDir)
    }

    fn create_dir(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
        uid: Uid,
        gid: Gid,
    ) -> Result<DynINode> {
        let _ = file_name;
        let _ = mode;
        let _ = uid;
        let _ = gid;
        bail!(NotDir)
    }

    fn create_link(
        &self,
        file_name: FileName<'static>,
        target: Path,
        uid: Uid,
        gid: Gid,
        create_new: bool,
    ) -> Result<DynINode> {
        let _ = file_name;
        let _ = target;
        let _ = uid;
        let _ = gid;
        let _ = create_new;
        bail!(NotDir)
    }

    fn create_char_dev(
        &self,
        file_name: FileName<'static>,
        major: u16,
        minor: u8,
        mode: FileMode,
        uid: Uid,
        gid: Gid,
    ) -> Result<DynINode> {
        let _ = file_name;
        let _ = major;
        let _ = minor;
        let _ = mode;
        let _ = uid;
        let _ = gid;
        bail!(NotDir)
    }

    fn create_fifo(
        &self,
        file_name: FileName<'static>,
        mode: FileMode,
        uid: Uid,
        gid: Gid,
    ) -> Result<()> {
        let _ = file_name;
        let _ = mode;
        let _ = uid;
        let _ = gid;
        bail!(NotDir)
    }

    fn mount(&self, file_name: FileName<'static>, node: DynINode) -> Result<()> {
        let _ = file_name;
        let _ = node;
        bail!(NotDir)
    }

    fn is_empty_dir(&self) -> bool {
        false
    }

    fn delete_non_dir(&self, file_name: FileName<'static>) -> Result<()> {
        let _ = file_name;
        bail!(NotDir)
    }

    fn delete_dir(&self, file_name: FileName<'static>) -> Result<()> {
        let _ = file_name;
        bail!(NotDir)
    }

    fn rename(
        &self,
        oldname: FileName<'static>,
        check_is_dir: bool,
        new_dir: DynINode,
        newname: FileName<'static>,
        no_replace: bool,
    ) -> Result<()> {
        let _ = oldname;
        let _ = check_is_dir;
        let _ = new_dir;
        let _ = newname;
        let _ = no_replace;
        bail!(NotDir)
    }

    fn exchange(
        &self,
        oldname: FileName<'static>,
        new_dir: DynINode,
        newname: FileName<'static>,
    ) -> Result<()> {
        let _ = oldname;
        let _ = new_dir;
        let _ = newname;
        bail!(NotDir)
    }

    fn hard_link(
        &self,
        oldname: FileName<'static>,
        follow_symlink: bool,
        new_dir: DynINode,
        newname: FileName<'static>,
    ) -> Result<Option<Path>> {
        let _ = oldname;
        let _ = follow_symlink;
        let _ = new_dir;
        let _ = newname;
        bail!(NotDir)
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

    fn read_link(&self, ctx: &FileAccessContext) -> Result<Path> {
        let _ = ctx;
        bail!(Inval)
    }

    fn file_lock_record(&self) -> &Arc<FileLockRecord>;
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
pub struct FileAccessContext {
    pub process: Option<Arc<Process>>,
    symlink_recursion_limit: u16,
    pub filesystem_user_id: Uid,
    pub filesystem_group_id: Gid,
    pub supplementary_group_ids: Arc<[Gid]>,
}

impl FileAccessContext {
    pub fn root() -> Self {
        Self {
            process: None,
            symlink_recursion_limit: 16,
            filesystem_user_id: Uid::SUPER_USER,
            filesystem_group_id: Gid::SUPER_USER,
            supplementary_group_ids: Arc::new([]),
        }
    }

    /// Record that a symlink was followed and return an error if the recursion
    /// limit was exceeded.
    pub fn follow_symlink(&mut self) -> Result<()> {
        self.symlink_recursion_limit = self
            .symlink_recursion_limit
            .checked_sub(1)
            .ok_or(err!(Loop))?;
        Ok(())
    }

    #[track_caller]
    pub fn check_permissions(&self, stat: &Stat, permission: Permission) -> Result<()> {
        if self.filesystem_user_id == Uid::SUPER_USER {
            // Access checks are special for the super user: Read and write
            // checks are omitted completly, but for execute at least one
            // execute flag has to be set.
            if matches!(permission, Permission::Execute) {
                ensure!(
                    stat.mode.mode().intersects(
                        FileMode::OWNER_EXECUTE | FileMode::GROUP_EXECUTE | FileMode::OTHER_EXECUTE,
                    ),
                    Acces
                );
            }
            return Ok(());
        }

        let mode_bit = if self.is_user(stat.uid) {
            match permission {
                Permission::Read => FileMode::OWNER_READ,
                Permission::Write => FileMode::OWNER_WRITE,
                Permission::Execute => FileMode::OWNER_EXECUTE,
            }
        } else if self.is_in_group(stat.gid) {
            match permission {
                Permission::Read => FileMode::GROUP_READ,
                Permission::Write => FileMode::GROUP_WRITE,
                Permission::Execute => FileMode::GROUP_EXECUTE,
            }
        } else {
            match permission {
                Permission::Read => FileMode::OTHER_READ,
                Permission::Write => FileMode::OTHER_WRITE,
                Permission::Execute => FileMode::OTHER_EXECUTE,
            }
        };
        ensure!(stat.mode.mode().contains(mode_bit), Acces);

        Ok(())
    }

    pub fn is_user(&self, uid: Uid) -> bool {
        self.filesystem_user_id == Uid::SUPER_USER || self.filesystem_user_id == uid
    }

    pub fn is_in_group(&self, gid: Gid) -> bool {
        self.filesystem_user_id == Uid::SUPER_USER
            || self.filesystem_group_id == gid
            || self.supplementary_group_ids.contains(&gid)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Permission {
    Read,
    Write,
    Execute,
}

impl ExtractableThreadState for FileAccessContext {
    fn extract_from_thread(guard: &ThreadGuard) -> Self {
        let credentials_guard = guard.process().credentials.lock();
        Self {
            process: Some(guard.process().clone()),
            symlink_recursion_limit: 16,
            filesystem_user_id: credentials_guard.filesystem_user_id,
            filesystem_group_id: credentials_guard.filesystem_group_id,
            supplementary_group_ids: credentials_guard.supplementary_group_ids.clone(),
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

            if !matches!(segment, PathSegment::Root) {
                // Make sure that the node is a directory.
                let stat = node.stat()?;
                ensure!(stat.mode.ty() == FileType::Dir, NotDir);
                if !matches!(segment, PathSegment::Dot) {
                    ctx.check_permissions(&stat, Permission::Execute)?;
                }
            }

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
) -> Result<(DynINode, PathSegment<'a>, bool)> {
    let mut segments = path.segments();
    let first = segments.next().ok_or(err!(Inval))?;
    let (parent, segment, trailing_slash) = segments.try_fold(
        (start_dir, first, false),
        |(dir, segment, _trailing_slash), next_segment| -> Result<_> {
            // Don't do anything if the next segment is emtpty or a dot.
            if let PathSegment::Empty = next_segment {
                return Ok((dir, segment, true));
            }

            let dir = match segment {
                PathSegment::Root => ROOT_NODE.clone(),
                PathSegment::Empty | PathSegment::Dot => dir,
                PathSegment::DotDot => dir.parent()?,
                PathSegment::FileName(ref file_name) => {
                    let node = dir.get_node(file_name, ctx)?;
                    resolve_links(node, dir, ctx)?
                }
            };
            let stat = dir.stat()?;
            ensure!(stat.mode.ty() == FileType::Dir, NotDir);
            ctx.check_permissions(&stat, Permission::Execute)?;
            Ok((dir, next_segment, false))
        },
    )?;

    // Make sure that the parent is a directory.
    let stat = parent.stat()?;
    ensure!(stat.mode.ty() == FileType::Dir, NotDir);
    ctx.check_permissions(&stat, Permission::Execute)?;

    Ok((parent, segment, trailing_slash))
}

pub fn create_file(
    mut start_dir: DynINode,
    mut path: Path,
    mode: FileMode,
    flags: OpenFlags,
    ctx: &mut FileAccessContext,
) -> Result<DynINode> {
    loop {
        let (dir, last, trailing_slash) = find_parent(start_dir, &path, ctx)?;
        let PathSegment::FileName(file_name) = last else {
            bail!(IsDir);
        };
        ensure!(!trailing_slash, IsDir);

        match dir.create_file(
            file_name.into_owned(),
            mode,
            ctx.filesystem_user_id,
            ctx.filesystem_group_id,
        )? {
            Ok(file) => return Ok(file),
            Err(existing) => {
                let stat = existing.stat()?;

                // If the node is a symlink start over with the destination
                // path.
                if stat.mode.ty() == FileType::Link {
                    ensure!(!flags.contains(OpenFlags::EXCL), Exist);
                    ensure!(!flags.contains(OpenFlags::NOFOLLOW), Loop);

                    path = existing.read_link(ctx)?;
                    ctx.follow_symlink()?;
                    start_dir = dir;
                    continue;
                }

                ensure!(stat.mode.ty() != FileType::Dir, Exist);
                ensure!(!flags.contains(OpenFlags::EXCL), Exist);

                // Check that the existing file can be opened.
                if flags.contains(OpenFlags::WRONLY) {
                    ctx.check_permissions(&stat, Permission::Write)?;
                } else if flags.contains(OpenFlags::RDWR) {
                    ctx.check_permissions(&stat, Permission::Read)?;
                    ctx.check_permissions(&stat, Permission::Write)?;
                } else {
                    ctx.check_permissions(&stat, Permission::Read)?;
                }

                return Ok(existing);
            }
        }
    }
}

pub fn create_directory(
    start_dir: DynINode,
    path: &Path,
    mode: FileMode,
    ctx: &mut FileAccessContext,
) -> Result<DynINode> {
    let (dir, last, _trailing_slash) = find_parent(start_dir, path, ctx)?;
    match last {
        PathSegment::Root | PathSegment::Empty | PathSegment::Dot | PathSegment::DotDot => {
            bail!(Exist)
        }
        PathSegment::FileName(file_name) => dir.create_dir(
            file_name.into_owned(),
            mode,
            ctx.filesystem_user_id,
            ctx.filesystem_group_id,
        ),
    }
}

pub fn create_link(
    start_dir: DynINode,
    path: &Path,
    target: Path,
    ctx: &mut FileAccessContext,
) -> Result<()> {
    let (dir, last, trailing_slash) = find_parent(start_dir, path, ctx)?;
    let PathSegment::FileName(file_name) = last else {
        bail!(Exist);
    };
    if trailing_slash {
        dir.get_node(&file_name, ctx)?;
        bail!(Exist);
    }
    dir.create_link(
        file_name.into_owned(),
        target,
        ctx.filesystem_user_id,
        ctx.filesystem_group_id,
        true,
    )?;
    Ok(())
}

pub fn read_link(start_dir: DynINode, path: &Path, ctx: &mut FileAccessContext) -> Result<Path> {
    let node = lookup_node(start_dir, path, ctx)?;
    node.read_link(ctx)
}

pub fn create_fifo(
    start_dir: DynINode,
    path: &Path,
    mode: FileMode,
    ctx: &mut FileAccessContext,
) -> Result<()> {
    let (dir, last, _trailing_slash) = find_parent(start_dir, path, ctx)?;
    match last {
        PathSegment::Root | PathSegment::Empty | PathSegment::Dot | PathSegment::DotDot => {
            bail!(Exist)
        }
        PathSegment::FileName(file_name) => dir.create_fifo(
            file_name.into_owned(),
            mode,
            ctx.filesystem_user_id,
            ctx.filesystem_group_id,
        ),
    }
}

pub fn create_char_dev(
    start_dir: DynINode,
    path: &Path,
    major: u16,
    minor: u8,
    mode: FileMode,
    ctx: &mut FileAccessContext,
) -> Result<()> {
    let (dir, last, _trailing_slash) = find_parent(start_dir, path, ctx)?;
    match last {
        PathSegment::Root | PathSegment::Empty | PathSegment::Dot | PathSegment::DotDot => {
            bail!(Exist)
        }
        PathSegment::FileName(file_name) => {
            dir.create_char_dev(
                file_name.into_owned(),
                major,
                minor,
                mode,
                ctx.filesystem_user_id,
                ctx.filesystem_group_id,
            )?;
            Ok(())
        }
    }
}

pub fn mount(
    path: &Path,
    create_node: impl FnOnce(MountLocation) -> Result<DynINode>,
    ctx: &mut FileAccessContext,
) -> Result<()> {
    let (dir, last, _trailing_slash) = find_parent(ROOT_NODE.clone(), path, ctx)?;
    let file_name = match last {
        PathSegment::Root => todo!(),
        PathSegment::Empty => todo!(),
        PathSegment::Dot => todo!(),
        PathSegment::DotDot => todo!(),
        PathSegment::FileName(file_name) => file_name,
    };
    let location = MountLocation::new(Arc::downgrade(&dir), file_name.clone().into_owned());
    let node = create_node(location)?;
    dir.mount(file_name.into_owned(), node)?;
    Ok(())
}

pub fn unlink_file(start_dir: DynINode, path: &Path, ctx: &mut FileAccessContext) -> Result<()> {
    let (parent, segment, trailing_slash) = find_parent(start_dir, path, ctx)?;
    let PathSegment::FileName(filename) = segment else {
        bail!(IsDir)
    };
    ensure!(!trailing_slash, IsDir);
    let stat = parent.stat()?;
    ctx.check_permissions(&stat, Permission::Write)?;
    parent.delete_non_dir(filename.into_owned())
}

pub fn unlink_dir(start_dir: DynINode, path: &Path, ctx: &mut FileAccessContext) -> Result<()> {
    let (parent, segment, _trailing_slash) = find_parent(start_dir, path, ctx)?;
    match segment {
        PathSegment::Root => bail!(NotEmpty),
        PathSegment::Empty => todo!(),
        PathSegment::Dot => bail!(Inval),
        PathSegment::DotDot => bail!(NotEmpty),
        PathSegment::FileName(filename) => {
            let stat = parent.stat()?;
            ctx.check_permissions(&stat, Permission::Write)?;
            parent.delete_dir(filename.into_owned())
        }
    }
}

pub fn hard_link(
    start_dir: DynINode,
    start_path: &Path,
    mut target_dir: DynINode,
    mut target_path: Path,
    symlink_follow: bool,
    ctx: &mut FileAccessContext,
) -> Result<()> {
    let (new_parent, new_filename, _trailing_slash) = find_parent(start_dir, start_path, ctx)?;
    let PathSegment::FileName(new_filename) = new_filename else {
        bail!(Exist);
    };
    let new_filename = new_filename.into_owned();

    let stat = new_parent.stat()?;
    ctx.check_permissions(&stat, Permission::Write)?;

    loop {
        let (old_parent, old_filename, trailing_slash) =
            find_parent(target_dir, &target_path, ctx)?;
        ensure!(!trailing_slash, Perm);
        let PathSegment::FileName(old_filename) = old_filename else {
            bail!(Perm);
        };

        let new_path = old_parent.hard_link(
            old_filename.into_owned(),
            symlink_follow,
            new_parent.clone(),
            new_filename.clone(),
        )?;
        if let Some(new_path) = new_path {
            ctx.follow_symlink()?;

            target_dir = old_parent;
            target_path = new_path;
        } else {
            break;
        }
    }

    Ok(())
}

pub fn rename(
    oldd: DynINode,
    old_path: &Path,
    newd: DynINode,
    new_path: &Path,
    no_replace: bool,
    ctx: &mut FileAccessContext,
) -> Result<()> {
    let (old_parent, segment, _trailing_slash) = find_parent(oldd, old_path, ctx)?;
    let old_name = match segment {
        PathSegment::Root | PathSegment::Empty => bail!(IsDir),
        PathSegment::Dot | PathSegment::DotDot => bail!(Busy),
        PathSegment::FileName(filename) => filename,
    };

    let (new_parent, segment, _trailing_slash) = find_parent(newd, new_path, ctx)?;
    let new_name = match segment {
        PathSegment::Root | PathSegment::Empty | PathSegment::Dot | PathSegment::DotDot => {
            bail!(Exist)
        }
        PathSegment::FileName(filename) => filename,
    };

    let stat = old_parent.stat()?;
    ctx.check_permissions(&stat, Permission::Write)?;
    let stat = new_parent.stat()?;
    ctx.check_permissions(&stat, Permission::Write)?;

    let check_is_dir = old_path.has_trailing_slash() || new_path.has_trailing_slash();
    old_parent.rename(
        old_name.into_owned(),
        check_is_dir,
        new_parent,
        new_name.into_owned(),
        no_replace,
    )?;

    Ok(())
}

pub fn exchange(
    oldd: DynINode,
    old_path: &Path,
    newd: DynINode,
    new_path: &Path,
    ctx: &mut FileAccessContext,
) -> Result<()> {
    let (old_parent, segment, _trailing_slash) = find_parent(oldd, old_path, ctx)?;
    let old_name = match segment {
        PathSegment::Root | PathSegment::Empty => bail!(IsDir),
        PathSegment::Dot | PathSegment::DotDot => bail!(Busy),
        PathSegment::FileName(filename) => filename,
    };

    let (new_parent, segment, _trailing_slash) = find_parent(newd, new_path, ctx)?;
    let new_name = match segment {
        PathSegment::Root | PathSegment::Empty | PathSegment::Dot | PathSegment::DotDot => {
            bail!(IsDir)
        }
        PathSegment::FileName(filename) => filename,
    };

    let stat = old_parent.stat()?;
    ctx.check_permissions(&stat, Permission::Write)?;
    let stat = new_parent.stat()?;
    ctx.check_permissions(&stat, Permission::Write)?;

    old_parent.exchange(old_name.into_owned(), new_parent, new_name.into_owned())?;

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
