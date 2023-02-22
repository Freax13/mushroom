use alloc::sync::Arc;
use spin::mutex::Mutex;
use x86_64::VirtAddr;

use crate::{
    error::{Error, Result},
    fs::{
        node::{lookup_node, Node, ROOT_NODE},
        Path,
    },
};

use self::{fd::FileDescriptorTable, memory::VirtualMemory, thread::Thread};

mod elf;
pub mod fd;
pub mod memory;
mod syscall;
pub mod thread;

pub struct Process {}

impl Process {
    pub fn create(path: &Path) -> Result<()> {
        let node = lookup_node(Node::Directory(ROOT_NODE.clone()), path)?;
        let Node::File(file) = node else { return Err(Error::IsDir) };
        if !file.is_executable() {
            return Err(Error::Acces);
        }
        let elf_file = file.read_snapshot()?;

        let process = Arc::new(Process {});

        let mut virtual_memory = VirtualMemory::new();
        // Load the elf.
        let entry = virtual_memory.load_elf(elf_file)?;
        // Create stack.
        let addr = VirtAddr::new(0x7fff_fff0_0000);
        let len = 0x1_0000;
        let stack = virtual_memory.allocate_stack(addr, len)?;

        let virtual_memory = Arc::new(Mutex::new(virtual_memory));

        let fdtable = Arc::new(FileDescriptorTable::new());

        let thread = Thread::new(process, virtual_memory, fdtable, stack.as_u64(), entry);
        thread.spawn();

        Ok(())
    }
}

pub fn start_init_process() {
    let path = Path::new(b"/bin/init");
    Process::create(&path).expect("failed to create init process");
}
