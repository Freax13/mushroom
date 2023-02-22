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

use self::{fd::FileDescriptorTable, memory::VirtualMemory, thread::Thread};

mod elf;
pub mod fd;
pub mod memory;
mod syscall;
pub mod thread;

pub struct Process {
    waits: Mutex<BTreeMap<VirtAddr, VecDeque<u32>>>,
}

impl Process {
    pub fn create(path: &Path) -> Result<()> {
        let node = lookup_node(Node::Directory(ROOT_NODE.clone()), path)?;
        let Node::File(file) = node else { return Err(Error::IsDir) };
        if !file.is_executable() {
            return Err(Error::Acces);
        }
        let elf_file = file.read_snapshot()?;

        let process = Arc::new(Process {
            waits: Mutex::new(BTreeMap::new()),
        });

        let mut virtual_memory = VirtualMemory::new();
        // Create stack.
        let len = 0x1_0000;
        let stack = virtual_memory.allocate_stack(None, len)? + len;
        // Load the elf.
        let entry = virtual_memory.load_elf(elf_file, stack)?;

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
