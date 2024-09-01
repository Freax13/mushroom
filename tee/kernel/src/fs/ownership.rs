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
        ensure!(ctx.is_user(self.uid), Perm);

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

    pub fn chown(&mut self, mut uid: Uid, mut gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        if uid == Uid::UNCHANGED {
            uid = self.uid;
        }
        if gid == Gid::UNCHANGED {
            gid = self.gid;
        }

        // Make sure the current user matches the fsuid.
        ensure!(ctx.is_user(self.uid), Perm);

        // Make sure that new user & group are allowed.
        ensure!(ctx.is_user(uid), Perm);
        ensure!(ctx.is_in_group(gid), Perm);

        self.uid = uid;
        self.gid = gid;

        Ok(())
    }
}
