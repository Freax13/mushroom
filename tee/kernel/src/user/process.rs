use core::{
    ffi::CStr,
    sync::atomic::{AtomicU16, Ordering},
};

use bit_field::BitField;

use crate::{fs::path::Path, supervisor};

use self::{
    futex::Futexes,
    memory::VirtualMemoryActivator,
    thread::{new_tid, Thread},
};

mod elf;
pub mod fd;
mod futex;
pub mod memory;
pub mod syscall;
pub mod thread;

pub struct Process {
    pid: u32,
    futexes: Futexes,
    exit_status: AtomicU16,
}

impl Process {
    fn new(first_tid: u32) -> Self {
        Self {
            pid: first_tid,
            futexes: Futexes::new(),
            exit_status: AtomicU16::new(0),
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

        let mut encoded_exit_status = u16::from(exit_status);
        encoded_exit_status.set_bit(15, true);

        let res = self.exit_status.compare_exchange(
            0,
            encoded_exit_status,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );

        match res {
            Ok(_) => exit_status,
            Err(exit_status) => {
                assert!(exit_status.get_bit(15));
                exit_status as u8
            }
        }
    }

    pub fn exit_status(&self) -> Option<u8> {
        let exit_status = self.exit_status.load(Ordering::SeqCst);
        exit_status.get_bit(15).then_some(exit_status as u8)
    }
}

pub fn start_init_process(vm_activator: &mut VirtualMemoryActivator) {
    let res = Thread::spawn(|self_weak| {
        let thread = Thread::empty(self_weak, new_tid());

        // Load the init process.
        let path = Path::new(b"/bin/init".to_vec())?;
        let mut guard = thread.lock();
        guard.execve(
            &path,
            &[CStr::from_bytes_with_nul(b"/bin/init\0").unwrap()],
            &[] as &[&CStr],
            vm_activator,
        )?;
        drop(guard);

        Ok(thread)
    });

    let tid = res.expect("failed to create init process");
    assert_eq!(tid, 1);
}
