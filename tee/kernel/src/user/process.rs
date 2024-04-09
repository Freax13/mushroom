use core::ffi::CStr;

use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};

use crate::{
    error::{Error, Result},
    fs::{
        fd::file::File,
        node::{tmpfs::TmpFsFile, FileAccessContext, INode},
        path::Path,
        INIT,
    },
    rt::{notify::Notify, once::OnceCell},
    spin::mutex::Mutex,
    supervisor,
    user::process::syscall::args::{ExtractableThreadState, FileMode, OpenFlags},
};

use self::{
    futex::Futexes,
    thread::{new_tid, Thread},
};

mod exec;
mod futex;
pub mod memory;
pub mod syscall;
pub mod thread;

pub struct Process {
    pid: u32,
    futexes: Arc<Futexes>,
    exit_status: OnceCell<u8>,
    parent: Weak<Self>,
    children: Mutex<Vec<Arc<Self>>>,
    child_death_notify: Notify,
}

impl Process {
    fn new(first_tid: u32, parent: Weak<Self>) -> Arc<Self> {
        let this = Self {
            pid: first_tid,
            futexes: Arc::new(Futexes::new()),
            exit_status: OnceCell::new(),
            parent: parent.clone(),
            children: Mutex::new(Vec::new()),
            child_death_notify: Notify::new(),
        };
        let arc = Arc::new(this);

        if let Some(parent) = parent.upgrade() {
            parent.children.lock().push(arc.clone());
        }

        arc
    }
    /// Terminate all threads in the thread group.
    ///
    /// The returned exit status may not be the same as the requested
    /// if another thread terminated the thread group at the same time.
    pub fn exit_group(&self, exit_status: u8) {
        if self.pid == 1 {
            // Commit or fail the output depending on the exit status of the
            // init process.
            if exit_status == 0 {
                supervisor::commit_output();
            } else {
                supervisor::fail();
            }
        }

        let set = self.exit_status.set(exit_status);
        if !set {
            return;
        }


        if let Some(parent) = self.parent.upgrade() {
            parent.child_death_notify.notify();
        }
    }

    pub async fn exit_status(&self) -> u8 {
        *self.exit_status.get().await
    }

    pub async fn wait_for_child_death(
        &self,
        pid: Option<u32>,
        no_hang: bool,
    ) -> Result<Option<(u32, u8)>> {
        self.child_death_notify
            .wait_until(|| {
                let mut guard = self.children.lock();
                if guard.is_empty() {
                    return Some(Err(Error::child(())));
                }

                let opt_idx = guard.iter().position(|child| {
                    // If there's a pid, only consider the child with the given pid.
                    if let Some(pid) = pid {
                        if child.pid != pid {
                            return false;
                        }
                    }

                    child.exit_status.try_get().is_some()
                });

                let Some(idx) = opt_idx else {
                    if no_hang {
                        return Some(Ok(None));
                    } else {
                        return None;
                    }
                };
                let child = guard.swap_remove(idx);
                let status = *child.exit_status.try_get().unwrap();
                Some(Ok(Some((child.pid, status))))
            })
            .await
    }
}

pub fn start_init_process() {
    let tid = new_tid();
    assert_eq!(tid, 1);
    let thread = Thread::empty(tid);

    let mut guard = thread.lock();
    let mut ctx = FileAccessContext::extract_from_thread(&guard);

    let file = TmpFsFile::new(FileMode::all());
    file.write(0, *INIT).unwrap();
    let file = file.open(OpenFlags::empty()).unwrap();

    guard
        .start_executable(
            &Path::new(b"/bin/init".to_vec()).unwrap(),
            &*file,
            &[CStr::from_bytes_with_nul(b"/bin/init\0").unwrap()],
            &[] as &[&CStr],
            &mut ctx,
        )
        .unwrap();
    drop(guard);

    thread.spawn();
}
