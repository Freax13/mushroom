use crate::{
    error::{ensure, Result},
    user::process::{
        syscall::args::FileMode,
        thread::{Gid, Uid},
    },
};

use super::node::FileAccessContext;

#[derive(Clone)]
pub struct Ownership {
    mode: FileMode,
    uid: Uid,
    gid: Gid,
}

impl Ownership {
    pub fn new(mode: FileMode, uid: Uid, gid: Gid) -> Self {
        Self { mode, uid, gid }
    }

    pub fn mode(&self) -> FileMode {
        self.mode
    }

    pub fn chmod(&mut self, mut mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        ctx.check_is_user_or_su(self.uid)?;

        if ctx.filesystem_user_id != Uid::SUPER_USER && !ctx.is_in_group(self.gid) {
            mode.remove(FileMode::SET_GROUP_ID);
        }

        self.mode = mode;

        Ok(())
    }

    pub fn uid(&self) -> Uid {
        self.uid
    }

    pub fn gid(&self) -> Gid {
        self.gid
    }

    pub fn chown(&mut self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        if self.uid != Uid::SUPER_USER {
            // Make sure the current user matches the fsuid.
            ensure!(self.uid == ctx.filesystem_user_id, Perm);

            // Make sure that new user & group are allowed.
            ensure!(ctx.filesystem_user_id == uid, Perm);
            ensure!(
                gid == ctx.filesystem_group_id || ctx.supplementary_group_ids.contains(&gid),
                Perm
            );
        }

        self.uid = uid;
        self.gid = gid;

        Ok(())
    }
}
