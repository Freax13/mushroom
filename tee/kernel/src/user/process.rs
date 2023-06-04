use core::{
    ffi::CStr,
    sync::atomic::{AtomicU16, Ordering},
};

use alloc::sync::Arc;
use bit_field::BitField;

use crate::{
    error::{Error, Result},
    fs::{
        node::{lookup_node, Node, ROOT_NODE},
        Path,
    },
    supervisor,
};

use self::{
    fd::FileDescriptorTable,
    futex::Futexes,
    memory::{VirtualMemory, VirtualMemoryActivator},
    syscall::args::FileMode,
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
    pub fn create(
        tid: u32,
        path: &Path,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        vm_activator: &mut VirtualMemoryActivator,
    ) -> Result<()> {
        let node = lookup_node(Node::Directory(ROOT_NODE.clone()), path)?;
        let Node::File(file) = node else { return Err(Error::is_dir()) };
        if !file.mode().contains(FileMode::EXECUTE) {
            return Err(Error::acces());
        }
        let elf_file = file.read_snapshot()?;

        let process = Arc::new(Process::new(tid));

        let virtual_memory = VirtualMemory::new();
        // Create stack.
        let len = 0x1_0000;
        let stack =
            vm_activator.activate(&virtual_memory, |vm| vm.allocate_stack(None, len))? + len;
        // Load the elf.
        let entry = vm_activator.activate(&virtual_memory, |vm| {
            vm.load_elf(elf_file, stack, argv, envp)
        })?;

        let virtual_memory = Arc::new(virtual_memory);

        let fdtable = Arc::new(FileDescriptorTable::new());

        let thread = Thread::new(tid, process, virtual_memory, fdtable, stack.as_u64(), entry);
        thread.spawn();

        Ok(())
    }

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
    let path = Path::new(b"/bin/init");
    Process::create(
        new_tid(),
        &path,
        &[CStr::from_bytes_with_nul(b"/bin/init\0").unwrap()],
        &[] as &[&CStr],
        vm_activator,
    )
    .expect("failed to create init process");
}
