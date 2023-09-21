use core::ffi::CStr;

use alloc::{borrow::Cow, sync::Arc};

use crate::{
    fs::{
        node::{FileAccessContext, FileSnapshot},
        INIT,
    },
    rt::once::OnceCell,
    supervisor,
    user::process::syscall::args::ExtractableThreadState,
};

use self::{
    futex::Futexes,
    memory::VirtualMemoryActivator,
    thread::{new_tid, Thread},
};

mod elf;
mod futex;
pub mod memory;
pub mod syscall;
pub mod thread;

pub struct Process {
    pid: u32,
    futexes: Arc<Futexes>,
    exit_status: OnceCell<u8>,
}

impl Process {
    fn new(first_tid: u32) -> Self {
        Self {
            pid: first_tid,
            futexes: Arc::new(Futexes::new()),
            exit_status: OnceCell::new(),
        }
    }

    /// Terminate all threads in the thread group.
    ///
    /// The returned exit status may not be the same as the requested
    /// if another thread terminated the thread group at the same time.
    pub fn exit(&self, exit_status: u8) -> u8 {
        if self.pid == 1 {
            // Commit or fail the output depending on the exit status of the
            // init process.
            if exit_status == 0 {
                supervisor::commit_output();
            } else {
                supervisor::fail();
            }
        }

        *self.exit_status.set(exit_status)
    }

    pub async fn exit_status(&self) -> u8 {
        *self.exit_status.get().await
    }
}

pub fn start_init_process(vm_activator: &mut VirtualMemoryActivator) {
    let res = Thread::spawn(|self_weak| {
        let thread = Thread::empty(self_weak, new_tid());

        let mut guard = thread.lock();
        let mut ctx = FileAccessContext::extract_from_thread(&guard);

        let bytes = Cow::Borrowed(*INIT);
        let bytes = Arc::new(bytes);
        let bytes = FileSnapshot::from(bytes);

        guard.start_executable(
            bytes,
            &[CStr::from_bytes_with_nul(b"/bin/init\0").unwrap()],
            &[] as &[&CStr],
            &mut ctx,
            vm_activator,
        )?;
        drop(guard);

        Ok(thread)
    });

    let tid = res.expect("failed to create init process");
    assert_eq!(tid, 1);
}
