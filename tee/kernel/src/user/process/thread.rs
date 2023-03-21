use core::{
    arch::asm,
    ops::{BitAndAssign, BitOrAssign, Not},
    sync::atomic::{AtomicU32, Ordering},
};

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use bitflags::bitflags;
use bytemuck::{offset_of, Pod, Zeroable};
use spin::Mutex;
use x86_64::{
    registers::{
        control::{Cr4, Cr4Flags},
        segmentation::{Segment64, FS},
    },
    VirtAddr,
};

use crate::{
    per_cpu::{PerCpu, KERNEL_REGISTERS_OFFSET, USERSPACE_REGISTERS_OFFSET},
    supervisor::schedule_vcpu,
};

use super::{
    fd::FileDescriptorTable,
    memory::{VirtualMemory, VirtualMemoryActivator},
    Process,
};

pub static THREADS: Mutex<BTreeMap<u32, Arc<Mutex<Thread>>>> = Mutex::new(BTreeMap::new());
static RUNNABLE_THREADS: Mutex<VecDeque<u32>> = Mutex::new(VecDeque::new());

pub fn new_tid() -> u32 {
    static PID_COUNTER: AtomicU32 = AtomicU32::new(1);
    PID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

pub fn schedule_thread(tid: u32) {
    RUNNABLE_THREADS.lock().push_back(tid);

    schedule_vcpu();
}

pub struct Thread {
    process: Arc<Process>,
    virtual_memory: Arc<VirtualMemory>,
    fdtable: Arc<FileDescriptorTable>,

    pub registers: UserspaceRegisters,

    pub tid: u32,

    pub sigmask: Sigset,
    pub sigaction: [Sigaction; 64],
    pub sigaltstack: Option<Stack>,
    pub clear_child_tid: u64,
}

impl Thread {
    pub fn new(
        tid: u32,
        process: Arc<Process>,
        virtual_memory: Arc<VirtualMemory>,
        fdtable: Arc<FileDescriptorTable>,
        stack: u64,
        entry: u64,
    ) -> Self {
        let registers = UserspaceRegisters {
            rax: 0x1000,
            rbx: 0x2000,
            rdx: 0x3000,
            rsi: 0x4000,
            rdi: 0x5000,
            rsp: stack,
            rbp: 0x6000,
            r8: 0x7000,
            r9: 0x8000,
            r10: 0x9000,
            r12: 0xa000,
            r13: 0xb000,
            r14: 0xc000,
            r15: 0xd000,
            rip: entry,
            rflags: 0,
            fs_base: 0,
        };
        Self {
            process,
            virtual_memory,
            fdtable,
            registers,
            tid,
            sigmask: Sigset(0),
            sigaction: [Sigaction::DEFAULT; 64],
            sigaltstack: None,
            clear_child_tid: 0,
        }
    }

    pub fn clone(
        &self,
        new_process: Option<Arc<Process>>,
        new_virtual_memory: Option<Arc<VirtualMemory>>,
        new_fdtable: Option<Arc<FileDescriptorTable>>,
        stack: VirtAddr,
        new_clear_child_tid: Option<VirtAddr>,
        new_tls: Option<u64>,
    ) -> Self {
        let process = new_process.unwrap_or_else(|| self.process.clone());
        let virtual_memory = new_virtual_memory.unwrap_or_else(|| self.virtual_memory.clone());
        let fdtable = new_fdtable.unwrap_or_else(|| Arc::new((*self.fdtable).clone()));

        let mut thread = Self::new(new_tid(), process, virtual_memory, fdtable, 0, 0);

        if let Some(clear_child_tid) = new_clear_child_tid {
            thread.clear_child_tid = clear_child_tid.as_u64();
        }

        // Copy all registers.
        thread.registers = self.registers;

        // Set the return value to 0 for the new thread.
        thread.registers.rax = 0;

        // Switch to a new stack if one is provided.
        if !stack.is_null() {
            thread.registers.rsp = stack.as_u64();
        }

        if let Some(tls) = new_tls {
            thread.registers.fs_base = tls;
        }

        thread
    }

    pub fn process(&self) -> &Arc<Process> {
        &self.process
    }

    pub fn virtual_memory(&self) -> &Arc<VirtualMemory> {
        &self.virtual_memory
    }

    pub fn fdtable(&self) -> &Arc<FileDescriptorTable> {
        &self.fdtable
    }

    pub fn spawn(self) {
        let tid = self.tid;
        let arc = Arc::new(Mutex::new(self));
        THREADS.lock().insert(tid, arc);
        schedule_thread(tid);
    }

    fn run(&mut self, vm_activator: &mut VirtualMemoryActivator) {
        loop {
            self.run_userspace(vm_activator);

            if !self.execute_syscall(vm_activator) {
                break;
            }
        }
    }

    fn run_userspace(&mut self, vm_activator: &mut VirtualMemoryActivator) {
        let actual_kernel_registers_offset = offset_of!(PerCpu::new(), PerCpu, kernel_registers);
        assert_eq!(
            actual_kernel_registers_offset, KERNEL_REGISTERS_OFFSET,
            "the USERSPACE_REGISTERS_OFFSET needs to be adjusted to {actual_kernel_registers_offset}"
        );
        let actual_userspace_registers = offset_of!(PerCpu::new(), PerCpu, userspace_registers);
        assert_eq!(
            actual_userspace_registers, USERSPACE_REGISTERS_OFFSET,
            "the USERSPACE_REGISTERS_OFFSET needs to be adjusted to {actual_userspace_registers}"
        );

        macro_rules! kernel_reg_offset {
            ($ident:ident) => {{
                let registers = KernelRegisters::ZERO;
                let reference = &registers;
                let register = &registers.$ident;

                let reference = reference as *const KernelRegisters;
                let register = register as *const u64;

                let offset = unsafe { register.byte_offset_from(reference) };
                KERNEL_REGISTERS_OFFSET + (offset as usize)
            }};
        }
        macro_rules! userspace_reg_offset {
            ($ident:ident) => {{
                let registers = UserspaceRegisters::ZERO;
                let reference = &registers;
                let register = &registers.$ident;

                let reference = reference as *const UserspaceRegisters;
                let register = register as *const u64;

                let offset = unsafe { register.byte_offset_from(reference) };
                USERSPACE_REGISTERS_OFFSET + (offset as usize)
            }};
        }

        let per_cpu = PerCpu::get();
        per_cpu.userspace_registers.set(self.registers);
        per_cpu
            .current_virtual_memory
            .set(Some(self.virtual_memory.clone()));

        unsafe {
            FS::write_base(VirtAddr::new(self.registers.fs_base));
        }

        let mut cr4 = Cr4::read();
        cr4 |= Cr4Flags::OSFXSR;
        unsafe {
            Cr4::write(cr4);
        }

        vm_activator.activate(&self.virtual_memory, |_| {
            unsafe {
                asm!(
                    // Set LSTAR
                    "lea rax, [rip+66f]",
                    "mov rdx, rax",
                    "shr rdx, 32",
                    "mov ecx, 0xC0000082",
                    "wrmsr",
                    // Save the kernel registers.
                    "mov gs:[{K_RAX_OFFSET}], rax",
                    "mov gs:[{K_RBX_OFFSET}], rbx",
                    "mov gs:[{K_RCX_OFFSET}], rcx",
                    "mov gs:[{K_RDX_OFFSET}], rdx",
                    "mov gs:[{K_RSI_OFFSET}], rsi",
                    "mov gs:[{K_RDI_OFFSET}], rdi",
                    "mov gs:[{K_RSP_OFFSET}], rsp",
                    "mov gs:[{K_RBP_OFFSET}], rbp",
                    "mov gs:[{K_R8_OFFSET}], r8",
                    "mov gs:[{K_R9_OFFSET}], r9",
                    "mov gs:[{K_R10_OFFSET}], r10",
                    "mov gs:[{K_R11_OFFSET}], r11",
                    "mov gs:[{K_R12_OFFSET}], r12",
                    "mov gs:[{K_R13_OFFSET}], r13",
                    "mov gs:[{K_R14_OFFSET}], r14",
                    "mov gs:[{K_R15_OFFSET}], r15",
                    // Save RFLAGS.
                    "pushfq",
                    "pop rax",
                    "mov gs:[{K_RFLAGS_OFFSET}], rax",
                    // Restore userspace registers.
                    "mov rax, gs:[{U_RAX_OFFSET}]",
                    "mov rbx, gs:[{U_RBX_OFFSET}]",
                    "mov rdx, gs:[{U_RDX_OFFSET}]",
                    "mov rsi, gs:[{U_RSI_OFFSET}]",
                    "mov rdi, gs:[{U_RDI_OFFSET}]",
                    "mov rsp, gs:[{U_RSP_OFFSET}]",
                    "mov rbp, gs:[{U_RBP_OFFSET}]",
                    "mov r8, gs:[{U_R8_OFFSET}]",
                    "mov r9, gs:[{U_R9_OFFSET}]",
                    "mov r10, gs:[{U_R10_OFFSET}]",
                    "mov r12, gs:[{U_R12_OFFSET}]",
                    "mov r13, gs:[{U_R13_OFFSET}]",
                    "mov r14, gs:[{U_R14_OFFSET}]",
                    "mov r15, gs:[{U_R15_OFFSET}]",
                    "mov rcx, gs:[{U_RIP_OFFSET}]",
                    "mov r11, gs:[{U_RFLAGS_OFFSET}]",
                    // Swap in userspace GS.
                    "swapgs",
                    // Enter usermdoe
                    "sysretq",
                    "66:",
                    // Swap in kernel GS.
                    "swapgs",
                    // Save userspace registers.
                    "mov gs:[{U_RAX_OFFSET}], rax",
                    "mov gs:[{U_RBX_OFFSET}], rbx",
                    "mov gs:[{U_RDX_OFFSET}], rdx",
                    "mov gs:[{U_RSI_OFFSET}], rsi",
                    "mov gs:[{U_RDI_OFFSET}], rdi",
                    "mov gs:[{U_RSP_OFFSET}], rsp",
                    "mov gs:[{U_RBP_OFFSET}], rbp",
                    "mov gs:[{U_R8_OFFSET}], r8",
                    "mov gs:[{U_R9_OFFSET}], r9",
                    "mov gs:[{U_R10_OFFSET}], r10",
                    "mov gs:[{U_R12_OFFSET}], r12",
                    "mov gs:[{U_R13_OFFSET}], r13",
                    "mov gs:[{U_R14_OFFSET}], r14",
                    "mov gs:[{U_R15_OFFSET}], r15",
                    "mov gs:[{U_RIP_OFFSET}], rcx",
                    "mov gs:[{U_RFLAGS_OFFSET}], r11",
                    // Restore the kernel registers.
                    "mov rax, gs:[{K_RAX_OFFSET}]",
                    "mov rbx, gs:[{K_RBX_OFFSET}]",
                    "mov rcx, gs:[{K_RCX_OFFSET}]",
                    "mov rdx, gs:[{K_RDX_OFFSET}]",
                    "mov rsi, gs:[{K_RSI_OFFSET}]",
                    "mov rdi, gs:[{K_RDI_OFFSET}]",
                    "mov rsp, gs:[{K_RSP_OFFSET}]",
                    "mov rbp, gs:[{K_RBP_OFFSET}]",
                    "mov r8, gs:[{K_R8_OFFSET}]",
                    "mov r9, gs:[{K_R9_OFFSET}]",
                    "mov r10, gs:[{K_R10_OFFSET}]",
                    "mov r11, gs:[{K_R11_OFFSET}]",
                    "mov r12, gs:[{K_R12_OFFSET}]",
                    "mov r13, gs:[{K_R13_OFFSET}]",
                    "mov r14, gs:[{K_R14_OFFSET}]",
                    "mov r15, gs:[{K_R15_OFFSET}]",
                    // Save RFLAGS.
                    "mov rax, gs:[{K_RFLAGS_OFFSET}]",
                    "push rax",
                    "popfq",
                    K_RAX_OFFSET = const kernel_reg_offset!(rax),
                    K_RBX_OFFSET = const kernel_reg_offset!(rbx),
                    K_RCX_OFFSET = const kernel_reg_offset!(rcx),
                    K_RDX_OFFSET = const kernel_reg_offset!(rdx),
                    K_RSI_OFFSET = const kernel_reg_offset!(rsi),
                    K_RDI_OFFSET = const kernel_reg_offset!(rdi),
                    K_RSP_OFFSET = const kernel_reg_offset!(rsp),
                    K_RBP_OFFSET = const kernel_reg_offset!(rbp),
                    K_R8_OFFSET = const kernel_reg_offset!(r8),
                    K_R9_OFFSET = const kernel_reg_offset!(r9),
                    K_R10_OFFSET = const kernel_reg_offset!(r10),
                    K_R11_OFFSET = const kernel_reg_offset!(r11),
                    K_R12_OFFSET = const kernel_reg_offset!(r12),
                    K_R13_OFFSET = const kernel_reg_offset!(r13),
                    K_R14_OFFSET = const kernel_reg_offset!(r14),
                    K_R15_OFFSET = const kernel_reg_offset!(r15),
                    K_RFLAGS_OFFSET = const kernel_reg_offset!(rflags),
                    U_RAX_OFFSET = const userspace_reg_offset!(rax),
                    U_RBX_OFFSET = const userspace_reg_offset!(rbx),
                    U_RDX_OFFSET = const userspace_reg_offset!(rdx),
                    U_RSI_OFFSET = const userspace_reg_offset!(rsi),
                    U_RDI_OFFSET = const userspace_reg_offset!(rdi),
                    U_RSP_OFFSET = const userspace_reg_offset!(rsp),
                    U_RBP_OFFSET = const userspace_reg_offset!(rbp),
                    U_R8_OFFSET = const userspace_reg_offset!(r8),
                    U_R9_OFFSET = const userspace_reg_offset!(r9),
                    U_R10_OFFSET = const userspace_reg_offset!(r10),
                    U_R12_OFFSET = const userspace_reg_offset!(r12),
                    U_R13_OFFSET = const userspace_reg_offset!(r13),
                    U_R14_OFFSET = const userspace_reg_offset!(r14),
                    U_R15_OFFSET = const userspace_reg_offset!(r15),
                    U_RIP_OFFSET = const userspace_reg_offset!(rip),
                    U_RFLAGS_OFFSET = const userspace_reg_offset!(rflags),
                    out("rax") _,
                    out("rdx") _,
                    out("rcx") _,
                    options(preserves_flags)
                );
            }
        });

        self.registers = per_cpu.userspace_registers.get();
    }
}

#[derive(Clone, Copy)]
pub struct KernelRegisters {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rsp: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rflags: u64,
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

#[derive(Debug, Clone, Copy)]
pub struct UserspaceRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub fs_base: u64,
}

impl UserspaceRegisters {
    pub const ZERO: Self = Self {
        rax: 0,
        rbx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        rsp: 0,
        rbp: 0,
        r8: 0,
        r9: 0,
        r10: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rip: 0,
        rflags: 0,
        fs_base: 0,
    };
}

/// Returns true if a thread was run.
pub fn run_thread(vm_activator: &mut VirtualMemoryActivator) -> bool {
    let Some(pid) = RUNNABLE_THREADS.lock().pop_front() else { return false; };

    let thread = THREADS.lock().get(&pid).cloned().unwrap();

    let mut guard = thread.lock();
    guard.run(vm_activator);

    true
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
