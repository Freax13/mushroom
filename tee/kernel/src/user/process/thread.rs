use core::{
    ffi::CStr,
    ops::{BitAndAssign, BitOrAssign, Deref, DerefMut, Not},
    sync::atomic::{AtomicU32, Ordering},
};

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
use futures::{select_biased, FutureExt};
use spin::{Mutex, MutexGuard};
use x86_64::VirtAddr;

use crate::{
    error::{Error, Result},
    fs::{
        node::{lookup_and_resolve_node, File, FileSnapshot, ROOT_NODE},
        path::Path,
    },
    per_cpu::PerCpu,
    rt::{mpmc, once::OnceCell, oneshot, spawn},
};

use super::{
    fd::FileDescriptorTable,
    memory::{VirtualMemory, VirtualMemoryActivator},
    syscall::{args::FileMode, cpu_state::CpuState},
    Process,
};

pub static THREADS: Threads = Threads::new();

pub fn new_tid() -> u32 {
    static PID_COUNTER: AtomicU32 = AtomicU32::new(1);
    PID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

pub struct Threads {
    map: Mutex<BTreeMap<u32, Arc<Thread>>>,
}

impl Threads {
    const fn new() -> Self {
        Self {
            map: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn add(&self, thread: Arc<Thread>) -> u32 {
        let tid = thread.tid;
        self.map.lock().insert(tid, thread);
        tid
    }

    pub fn by_id(&self, tid: u32) -> Option<Arc<Thread>> {
        self.map.lock().get(&tid).cloned()
    }

    pub fn remove(&self, tid: u32) {
        self.map.lock().remove(&tid);
    }
}

pub type WeakThread = Weak<Thread>;

pub struct Thread {
    // Immutable state.
    tid: u32,
    self_weak: WeakThread,
    parent: WeakThread,
    process: Arc<Process>,
    dead_children: mpmc::Receiver<(u32, u8)>,
    exit_status: OnceCell<u8>,

    // Mutable state.
    state: Mutex<ThreadState>,
    // Mutable state specific to the ABI the thread is running with.
    pub cpu_state: Mutex<CpuState>,
}

pub struct ThreadState {
    virtual_memory: Arc<VirtualMemory>,

    pub sigmask: Sigset,
    pub sigaction: [Sigaction; 64],
    pub sigaltstack: Option<Stack>,
    pub clear_child_tid: u64,
    pub notified_parent_about_exit: bool,
    pub cwd: Path,
    pub vfork_done: Option<oneshot::Sender<()>>,
    fdtable: Arc<FileDescriptorTable>,
}

impl Thread {
    #[allow(clippy::too_many_arguments)]
    fn new(
        tid: u32,
        self_weak: WeakThread,
        parent: WeakThread,
        process: Arc<Process>,
        virtual_memory: Arc<VirtualMemory>,
        fdtable: Arc<FileDescriptorTable>,
        cwd: Path,
        vfork_done: Option<oneshot::Sender<()>>,
        cpu_state: CpuState,
    ) -> Self {
        Self {
            tid,
            self_weak,
            parent,
            process,
            dead_children: mpmc::Receiver::new(),
            exit_status: OnceCell::new(),
            state: Mutex::new(ThreadState {
                virtual_memory,
                sigmask: Sigset(0),
                sigaction: [Sigaction::DEFAULT; 64],
                sigaltstack: None,
                clear_child_tid: 0,
                notified_parent_about_exit: false,
                cwd,
                vfork_done,
                fdtable,
            }),
            cpu_state: Mutex::new(cpu_state),
        }
    }

    pub fn spawn(create_thread: impl FnOnce(WeakThread) -> Result<Thread>) -> Result<u32> {
        let mut error = None;

        // Create the thread.
        let arc = Arc::new_cyclic(|self_weak| {
            let res = create_thread(self_weak.clone());
            res.unwrap_or_else(|err| {
                error = Some(err);

                // Create a temporary fake thread.
                // FIXME: Why isn't try_new_cyclic a thing?
                Thread::empty(self_weak.clone(), new_tid())
            })
        });

        if let Some(error) = error {
            return Err(error);
        }

        // Register the thread.
        let tid = THREADS.add(arc.clone());

        spawn(arc.run());

        Ok(tid)
    }

    pub fn empty(self_weak: WeakThread, tid: u32) -> Self {
        Self::new(
            tid,
            self_weak,
            Weak::new(),
            Arc::new(Process::new(tid)),
            Arc::new(VirtualMemory::new()),
            Arc::new(FileDescriptorTable::with_standard_io()),
            Path::new(b"/".to_vec()).unwrap(),
            None,
            CpuState::None,
        )
    }

    pub fn lock(&self) -> ThreadGuard {
        ThreadGuard {
            thread: self,
            state: self.state.lock(),
        }
    }

    pub fn tid(&self) -> u32 {
        self.tid
    }

    pub fn process(&self) -> &Arc<Process> {
        &self.process
    }

    pub async fn run(self: Arc<Self>) {
        let thread_exit_future = self.exit_status.get();
        let process_exit_future = self.process.exit_status();
        let run_future = async {
            loop {
                let clone = self.clone();
                VirtualMemoryActivator::r#do(move |vm_activator| {
                    clone.run_userspace(vm_activator).unwrap();
                })
                .await;

                self.clone().execute_syscall().await;
            }
        };

        select_biased! {
            _ = thread_exit_future.fuse() => {}
            status = process_exit_future.fuse() => self.clone().exit(status).await,
            _ = run_future.fuse() => unreachable!(),
        }
    }

    async fn exit(self: Arc<Self>, status: u8) {
        VirtualMemoryActivator::r#do(move |vm_activator| {
            let mut guard = self.lock();
            guard.exit(vm_activator, status)
        })
        .await
    }

    pub async fn wait_for_exit(&self) -> u8 {
        *self.exit_status.get().await
    }

    pub fn try_wait_for_child_death(&self) -> Option<(u32, u8)> {
        self.dead_children.try_recv()
    }

    pub async fn wait_for_child_death(&self) -> (u32, u8) {
        self.dead_children.recv().await
    }

    pub fn add_child_death(&self, tid: u32, status: u8) {
        let _ = self.dead_children.sender().send((tid, status));
    }

    fn run_userspace(&self, vm_activator: &mut VirtualMemoryActivator) -> Result<()> {
        let virtual_memory = self.lock().virtual_memory().clone();

        let per_cpu = PerCpu::get();
        per_cpu
            .current_virtual_memory
            .set(Some(virtual_memory.clone()));

        vm_activator.activate(&virtual_memory, |_| unsafe {
            let mut guard = self.cpu_state.lock();
            guard.run_userspace()
        })
    }
}

pub struct ThreadGuard<'a> {
    pub thread: &'a Thread,
    state: MutexGuard<'a, ThreadState>,
}

impl ThreadGuard<'_> {
    #[allow(clippy::too_many_arguments)]
    pub fn clone(
        &self,
        new_tid: u32,
        self_weak: WeakThread,
        new_process: Option<Arc<Process>>,
        new_virtual_memory: Option<Arc<VirtualMemory>>,
        fdtable: Arc<FileDescriptorTable>,
        stack: VirtAddr,
        new_clear_child_tid: Option<VirtAddr>,
        new_tls: Option<u64>,
        vfork_done: Option<oneshot::Sender<()>>,
    ) -> Thread {
        let process = new_process.unwrap_or_else(|| self.process().clone());
        let virtual_memory = new_virtual_memory.unwrap_or_else(|| self.virtual_memory().clone());
        let cpu_state = self.thread.cpu_state.lock().clone();

        let thread = Thread::new(
            new_tid,
            self_weak,
            self.weak().clone(),
            process,
            virtual_memory,
            fdtable,
            self.cwd.clone(),
            vfork_done,
            cpu_state,
        );

        let mut guard = thread.lock();
        if let Some(clear_child_tid) = new_clear_child_tid {
            guard.clear_child_tid = clear_child_tid.as_u64();
        }
        drop(guard);

        let mut guard = thread.cpu_state.lock();

        // Set the return value to 0 for the new thread.
        guard.set_syscall_result(Ok(0)).unwrap();

        // Switch to a new stack if one is provided.
        if !stack.is_null() {
            guard.set_stack_pointer(stack.as_u64()).unwrap();
        }

        if let Some(tls) = new_tls {
            guard.set_tls(tls).unwrap();
        }

        drop(guard);

        thread
    }

    pub fn weak(&self) -> &WeakThread {
        &self.thread.self_weak
    }

    pub fn parent(&self) -> &WeakThread {
        &self.thread.parent
    }

    pub fn tid(&self) -> u32 {
        self.thread.tid
    }

    pub fn process(&self) -> &Arc<Process> {
        &self.thread.process
    }

    pub fn virtual_memory(&self) -> &Arc<VirtualMemory> {
        &self.virtual_memory
    }

    pub fn fdtable(&self) -> &Arc<FileDescriptorTable> {
        &self.fdtable
    }

    /// Replaces the file descriptor table with an emtpy one.
    pub fn close_all_fds(&mut self) {
        self.fdtable = Arc::new(FileDescriptorTable::empty());
    }

    pub fn execve(
        &mut self,
        path: &Path,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        vm_activator: &mut VirtualMemoryActivator,
    ) -> Result<()> {
        let node = lookup_and_resolve_node(ROOT_NODE.clone(), path)?;
        let file: Arc<dyn File> = node.try_into()?;
        if !file.mode().contains(FileMode::EXECUTE) {
            return Err(Error::acces(()));
        }
        let bytes = file.read_snapshot()?;

        self.start_executable(bytes, argv, envp, vm_activator)
    }

    pub fn start_executable(
        &mut self,
        bytes: FileSnapshot,
        argv: &[impl AsRef<CStr>],
        envp: &[impl AsRef<CStr>],
        vm_activator: &mut VirtualMemoryActivator,
    ) -> Result<()> {
        let virtual_memory = VirtualMemory::new();

        // Load the elf.
        let cpu_state =
            vm_activator.activate(&virtual_memory, |vm| vm.start_executable(bytes, argv, envp))?;

        // Success! Commit the new state to the thread.

        self.virtual_memory = Arc::new(virtual_memory);
        *self.thread.cpu_state.lock() = cpu_state;
        self.clear_child_tid = 0;

        Ok(())
    }

    pub fn set_exit_status(&self, status: u8) {
        self.thread.exit_status.set(status);
    }
}

impl Deref for ThreadGuard<'_> {
    type Target = ThreadState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl DerefMut for ThreadGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

#[derive(Clone, Copy)]
pub struct KernelRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: u64,
}

impl KernelRegisters {
    pub const ZERO: Self = Self {
        rax: 0,
        rbx: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        rsp: 0,
        rbp: 0,
        r8: 0,
        r9: 0,
        r10: 0,
        r11: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rflags: 0,
    };
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Sigaction {
    sa_handler_or_sigaction: u64,
    sa_mask: Sigset,
    flags: u64,
    sa_restorer: u64,
}

impl Sigaction {
    const DEFAULT: Self = Self {
        sa_handler_or_sigaction: 0,
        sa_mask: Sigset(0),
        flags: 0,
        sa_restorer: 0,
    };
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Sigset(u64);

impl BitOrAssign for Sigset {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAndAssign for Sigset {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl Not for Sigset {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Stack {
    pub ss_sp: u64,
    pub flags: StackFlags,
    _pad: u32,
    pub size: u64,
}

bitflags! {
    #[derive(Pod, Zeroable)]
    #[repr(transparent)]
    pub struct StackFlags: i32 {
        const ONSTACK = 1 << 0;
        const DISABLE = 1 << 1;
        const AUTODISARM = 1 << 31;
    }
}
