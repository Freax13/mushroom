use alloc::sync::Arc;
use spin::mutex::Mutex;

use crate::{
    error::{Error, Result},
    fs::{
        node::{lookup_node, Node, ROOT_NODE},
        Path,
    },
};

use self::memory::MemoryManager;

mod elf;
mod memory;
mod syscall;
pub mod thread;

pub struct Process {
    memory_manager: Mutex<MemoryManager>,
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
            memory_manager: Mutex::new(MemoryManager::new()),
        });
        process.load_elf(elf_file)?;

        Ok(())
    }
}

pub fn start_init_process() {
    let path = Path::new(b"/bin/init");
    Process::create(&path).expect("failed to create init process");
}
