use core::ffi::CStr;

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use spin::mutex::Mutex;
use x86_64::VirtAddr;

use crate::{
    error::{Error, Result},
    fs::{
        node::{lookup_node, Node, ROOT_NODE},
        Path,
    },
};

use self::{
    fd::FileDescriptorTable,
    memory::{VirtualMemory, VirtualMemoryActivator},
    thread::{new_tid, Thread},
};

mod elf;
pub mod fd;
pub mod memory;
mod syscall;
pub mod thread;

pub struct Process {
    waits: Mutex<BTreeMap<VirtAddr, VecDeque<u32>>>,
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
        let Node::File(file) = node else { return Err(Error::IsDir) };
        if !file.is_executable() {
            return Err(Error::Acces);
        }
        let elf_file = file.read_snapshot()?;

        let process = Arc::new(Process::new());

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

    fn new() -> Self {
        Self {
            waits: Mutex::new(BTreeMap::new()),
        }
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
