use alloc::{vec, vec::Vec};
use core::{
    arch::{
        global_asm,
        x86_64::{__cpuid_count, _xrstor64, _xsaveopt64},
    },
    ffi::c_void,
    mem::{offset_of, size_of},
};

use bit_field::BitField;
use bytemuck::{Pod, Zeroable, bytes_of, bytes_of_mut, from_bytes, from_bytes_mut};
use constants::TIMER_VECTOR;
use usize_conversions::{FromUsize, usize_from};
use x86_64::{
    VirtAddr, align_down,
    instructions::tables::{lgdt, sgdt},
    registers::{
        control::Cr2,
        model_specific::{LStar, SFMask},
        rflags::RFlags,
        xcontrol::{XCr0, XCr0Flags},
    },
    structures::{DescriptorTablePointer, gdt::Entry, idt::PageFaultErrorCode},
};

use super::{
    args::{Pointer, UserDesc, pointee::SizedPointee},
    traits::{Abi, SyscallArgs, SyscallResult},
};
use crate::{
    error::{Result, ensure, err},
    per_cpu::PerCpu,
    spin::lazy::Lazy,
    user::process::{
        memory::{SIGRETURN_TRAMPOLINE_AMD64, SIGRETURN_TRAMPOLINE_I386, VirtualMemory},
        syscall::args::UserDescFlags,
        thread::{
            SigContext, SigInfo, Sigaction, SigactionFlags, Sigset, Stack, StackFlags, UContext,
        },
    },
};

const FP_XSTATE_MAGIC1: u32 = 0x46505853;
const FP_XSTATE_MAGIC2: u32 = 0x46505845;

#[derive(Clone)]
pub struct CpuState {
    pub registers: Registers,
    gdt: Vec<u64>,
    xsave_area: XSaveArea,
    last_exit_was_syscall: bool,
    ignore_syscall_result: bool,
    #[cfg(not(feature = "harden"))]
    last_exit: Option<Exit>,
}

impl CpuState {
    pub fn new(cs: u16, rip: u64, rsp: u64) -> Self {
        let gdt = PerCpu::get()
            .gdt
            .get()
            .unwrap()
            .entries()
            .iter()
            .map(Entry::raw)
            .collect();
        Self {
            registers: Registers {
                cs,
                rip,
                rsp,
                ..Registers::DEFAULT
            },
            gdt,
            xsave_area: XSaveArea::new(),
            last_exit_was_syscall: false,
            ignore_syscall_result: false,
            #[cfg(not(feature = "harden"))]
            last_exit: None,
        }
    }

    pub fn run_user(&mut self, virtual_memory: &VirtualMemory) -> Result<Exit> {
        let per_cpu = PerCpu::get();
        per_cpu.new_userspace_registers.set(self.registers);

        // Save the current GDT.
        let prev_pointer = sgdt();

        // Load the thread's GDT.
        let pointer = DescriptorTablePointer {
            limit: u16::try_from(self.gdt.len() * 8 - 1)?,
            base: VirtAddr::from_ptr(self.gdt.as_ptr()),
        };
        unsafe {
            lgdt(&pointer);
        }

        // Load x87, SSE and AVX state.
        self.xsave_area.load();

        per_cpu.exit_with_sysret.set(self.last_exit_was_syscall);

        virtual_memory.run_with(|| unsafe { enter_userspace() });

        // Save x87, SSE and AVX state.
        self.xsave_area.save();

        // Restore the old GDT.
        unsafe {
            lgdt(&prev_pointer);
        }

        assert!(!self.registers.rsp.get_bit(63));

        self.registers = per_cpu.new_userspace_registers.get();

        let raw_exit = per_cpu.exit.get();
        self.last_exit_was_syscall = matches!(raw_exit, RawExit::Syscall);
        let exit = self.gather_exit(raw_exit);
        #[cfg(not(feature = "harden"))]
        {
            self.last_exit = Some(exit);
        }
        Ok(exit)
    }

    fn gather_exit(&self, raw_exit: RawExit) -> Exit {
        match raw_exit {
            RawExit::Syscall => {
                let Registers {
                    rax: no,
                    rdi: arg0,
                    rsi: arg1,
                    rdx: arg2,
                    r10: arg3,
                    r8: arg4,
                    r9: arg5,
                    ..
                } = self.registers;
                Exit::Syscall(SyscallArgs {
                    abi: Abi::Amd64,
                    no,
                    args: [arg0, arg1, arg2, arg3, arg4, arg5],
                })
            }
            RawExit::Exception => match PerCpu::get().vector.get() {
                0x0 => Exit::DivideError,
                0x6 => Exit::InvalidOpcode,
                0xd => Exit::GeneralProtectionFault,
                0xe => {
                    let code =
                        PageFaultErrorCode::from_bits(PerCpu::get().error_code.get()).unwrap();
                    assert!(code.contains(PageFaultErrorCode::USER_MODE));
                    Exit::PageFault(PageFaultExit {
                        addr: Cr2::read_raw(),
                        code,
                    })
                }
                TIMER_VECTOR => Exit::Timer,
                0x80 => {
                    let no = self.registers.rax as u32;
                    let arg0 = self.registers.rbx as u32;
                    let arg1 = self.registers.rcx as u32;
                    let arg2 = self.registers.rdx as u32;
                    let arg3 = self.registers.rsi as u32;
                    let arg4 = self.registers.rdi as u32;
                    let arg5 = self.registers.rbp as u32;
                    Exit::Syscall(SyscallArgs {
                        abi: Abi::I386,
                        no: u64::from(no),
                        args: [
                            u64::from(arg0),
                            u64::from(arg1),
                            u64::from(arg2),
                            u64::from(arg3),
                            u64::from(arg4),
                            u64::from(arg5),
                        ],
                    })
                }
                vector => unimplemented!("unknown vector: {vector:#02x?}"),
            },
        }
    }

    pub fn set_syscall_result(&mut self, result: SyscallResult) -> Result<()> {
        if core::mem::take(&mut self.ignore_syscall_result) {
            return Ok(());
        }

        let result = match result {
            Ok(result) => {
                let is_error = (-4095..=-1).contains(&(result as i64));
                ensure!(!is_error, Inval);
                result
            }
            Err(err) => (-(err.kind() as i64)) as u64,
        };
        self.registers.rax = result;
        Ok(())
    }

    pub fn restart_syscall(&mut self, no: u64) {
        self.registers.rip -= 2;
        self.registers.rax = no;
    }

    pub fn set_stack_pointer(&mut self, sp: u64) {
        self.registers.rsp = sp;
    }

    pub fn faulting_instruction(&self) -> u64 {
        self.registers.rip
    }

    pub fn set_fs_base(&mut self, tls: u64) {
        self.registers.fs_base = tls;
    }

    pub fn add_user_desc(&mut self, u_info: UserDesc) -> Result<Option<u16>> {
        let mut access_byte = 0u8;
        access_byte.set_bit(7, !u_info.flags.contains(UserDescFlags::SEG_NOT_PRESENT)); // present bit
        access_byte.set_bits(5..=6, 3); // DPL
        access_byte.set_bit(4, true); // descriptor type bit
        access_byte.set_bit(3, u_info.flags.contains(UserDescFlags::READ_EXEC_ONLY)); // executable bit
        access_byte.set_bit(2, false); // DC bit
        access_byte.set_bit(1, true); // RW bit
        access_byte.set_bit(0, true); // accessed bit

        let mut flags = 0u8;
        flags.set_bit(0, false); // reserved
        flags.set_bit(1, u_info.flags.contains(UserDescFlags::LM)); // L bit
        flags.set_bit(2, u_info.flags.contains(UserDescFlags::SEG_32BIT)); // DB bit
        flags.set_bit(3, u_info.flags.contains(UserDescFlags::LIMIT_IN_PAGES)); // DB bit

        let mut desc = 0;
        desc.set_bits(0..=15, u64::from(u_info.limit.get_bits(0..=15)));
        desc.set_bits(48..=51, u64::from(u_info.limit.get_bits(16..=19)));
        desc.set_bits(16..=39, u64::from(u_info.base_addr.get_bits(0..=23)));
        desc.set_bits(56..=63, u64::from(u_info.base_addr.get_bits(24..=31)));
        desc.set_bits(40..=47, u64::from(access_byte));
        desc.set_bits(52..=55, u64::from(flags));

        if u_info.entry_number == !0 {
            self.gdt.push(desc);
            let num = u16::try_from(self.gdt.len() - 1)?;
            Ok(Some(num))
        } else {
            let idx = usize_from(u64::from(u_info.entry_number));
            let entry = self.gdt.get_mut(idx).ok_or(err!(Inval))?;
            *entry = desc;
            Ok(None)
        }
    }

    /// Guess the ABI to be used for signal handling based on the CS register
    /// and GDT entry.
    pub fn abi_from_cs(&self) -> Abi {
        let cs = self.registers.cs;
        let idx = usize::from(cs >> 3);
        let entry = self.gdt.get(idx).copied().unwrap_or_default();
        let l_bit = entry.get_bit(53);
        if l_bit { Abi::Amd64 } else { Abi::I386 }
    }

    pub fn create_sig_context(&self) -> SigContext {
        SigContext {
            r8: self.registers.r8,
            r9: self.registers.r9,
            r10: self.registers.r10,
            r11: self.registers.r11,
            r12: self.registers.r12,
            r13: self.registers.r13,
            r14: self.registers.r14,
            r15: self.registers.r15,
            rdi: self.registers.rdi,
            rsi: self.registers.rsi,
            rbp: self.registers.rbp,
            rbx: self.registers.rbx,
            rdx: self.registers.rdx,
            rax: self.registers.rax,
            rcx: self.registers.rcx,
            rsp: self.registers.rsp,
            rip: self.registers.rip,
            eflags: self.registers.rflags,
            cs: self.registers.cs,
            ds: self.registers.ds,
            es: self.registers.es,
            gs: self.registers.gs,
            fs: self.registers.fs,
            ss: self.registers.ss,
            err: 0,
            trapno: 0,
            oldmask: 0,
            cr2: 0,
            fpstate: Pointer::NULL,
        }
    }

    pub fn load_sig_context(&mut self, sig_context: &SigContext) {
        self.registers.r8 = sig_context.r8;
        self.registers.r9 = sig_context.r9;
        self.registers.r10 = sig_context.r10;
        self.registers.r11 = sig_context.r11;
        self.registers.r12 = sig_context.r12;
        self.registers.r13 = sig_context.r13;
        self.registers.r14 = sig_context.r14;
        self.registers.r15 = sig_context.r15;
        self.registers.rdi = sig_context.rdi;
        self.registers.rsi = sig_context.rsi;
        self.registers.rbp = sig_context.rbp;
        self.registers.rbx = sig_context.rbx;
        self.registers.rdx = sig_context.rdx;
        self.registers.rax = sig_context.rax;
        self.registers.rcx = sig_context.rcx;
        self.registers.rsp = sig_context.rsp;
        self.registers.rip = sig_context.rip;
        self.registers.rflags = sig_context.eflags;
        self.registers.cs = sig_context.cs;
        self.registers.ds = sig_context.ds;
        self.registers.es = sig_context.es;
        self.registers.gs = sig_context.gs;
        self.registers.fs = sig_context.fs;
        self.registers.ss = sig_context.ss;

        self.last_exit_was_syscall = false;
        self.ignore_syscall_result = true;
    }

    pub fn start_signal_handler(
        &mut self,
        sig_info: SigInfo,
        sigaction: Sigaction,
        stack: Stack,
        sigmask: Sigset,
        vm: &VirtualMemory,
    ) -> Result<()> {
        let abi = self.abi_from_cs();
        let mut mcontext = self.create_sig_context();
        let restorer = if sigaction.sa_flags.contains(SigactionFlags::RESTORER) {
            sigaction.sa_restorer
        } else {
            match abi {
                Abi::I386 => SIGRETURN_TRAMPOLINE_I386,
                Abi::Amd64 => SIGRETURN_TRAMPOLINE_AMD64,
            }
        };
        let restorer = Pointer::<c_void>::new(restorer);

        if !stack.flags.contains(StackFlags::DISABLE)
            && sigaction.sa_flags.contains(SigactionFlags::ONSTACK)
        {
            self.registers.rsp = stack.sp + stack.size;
        } else {
            // Skip the red zone.
            self.registers.rsp -= 128;
        }

        // Push information for the signal handler onto the stack.
        self.registers.rsp = align_down(self.registers.rsp, 16);
        // Write sig_info.
        self.registers.rsp -= u64::from_usize(sig_info.size(abi));
        let sig_info_ptr = Pointer::new(self.registers.rsp);
        vm.write_with_abi(sig_info_ptr, sig_info, abi)?;
        // Write fp state.
        let xsave_data = &*self.xsave_area.data;
        let fpstate_ptr = match abi {
            Abi::I386 => {
                let trailer_size = 4;
                let extended_size = size_of::<Fpstate32Header>() + xsave_data.len() + trailer_size;
                self.registers.rsp -= u64::from_usize(extended_size);
                let fpstate_ptr = Pointer::new(self.registers.rsp);
                let ptr = fpstate_ptr;

                // Write the header.
                let fxsave = from_bytes::<FXSave>(&xsave_data[..512]);
                let header = Fpstate32Header {
                    cw: u32::from(fxsave.fcw),
                    sw: u32::from(fxsave.fsw),
                    tag: u32::from(fxsave.ftw),
                    ipoff: fxsave.ipoff,
                    cssel: fxsave.cssel,
                    dataoff: fxsave.dataoff,
                    datasel: fxsave.datasel,
                    st: fxsave.st,
                    status: fxsave.fsw,
                    magic: 0x0000,
                };
                vm.write_bytes(ptr.get(), bytes_of(&header))?;
                let ptr = ptr.bytes_offset(size_of::<Fpstate32Header>());

                // Copy the xsave bytes.
                vm.write_bytes(ptr.get(), xsave_data)?;
                // Fill in the reserved bytes.
                let sw_bytes = FpxSwBytes {
                    magic1: FP_XSTATE_MAGIC1,
                    extended_size: extended_size as u32,
                    xfeatures: XSaveArea::flags().bits(),
                    xstate_size: xsave_data.len() as u32,
                    padding: [0; 7],
                };
                vm.write_bytes(ptr.get() + 0x1a0, bytes_of(&sw_bytes))?;
                let ptr = ptr.bytes_offset(xsave_data.len());

                // Fill in the magic at the end of the area.
                vm.write_bytes(ptr.get(), bytes_of(&FP_XSTATE_MAGIC2))?;

                fpstate_ptr
            }
            Abi::Amd64 => {
                let trailer_size = 4;
                let extended_size = xsave_data.len() + trailer_size;
                self.registers.rsp -= u64::from_usize(extended_size);
                let fpstate_ptr = Pointer::new(self.registers.rsp);
                let ptr = fpstate_ptr;

                // Copy the xsave bytes.
                vm.write_bytes(ptr.get(), xsave_data)?;
                // Fill in the reserved bytes.
                let sw_bytes = FpxSwBytes {
                    magic1: FP_XSTATE_MAGIC1,
                    extended_size: extended_size as u32,
                    xfeatures: XSaveArea::flags().bits(),
                    xstate_size: xsave_data.len() as u32,
                    padding: [0; 7],
                };
                vm.write_bytes(ptr.get() + 0x1a0, bytes_of(&sw_bytes))?;
                let ptr = ptr.bytes_offset(xsave_data.len());

                // Fill in the magic at the end of the area.
                vm.write_bytes(ptr.get(), bytes_of(&FP_XSTATE_MAGIC2))?;

                fpstate_ptr
            }
        };
        mcontext.fpstate = fpstate_ptr;
        // Write ucontext.
        let ucontext = UContext {
            stack,
            mcontext,
            sigmask,
        };
        self.registers.rsp = align_down(self.registers.rsp, 16);
        self.registers.rsp -= u64::from_usize(ucontext.size(abi));
        let ucontext_ptr = Pointer::new(self.registers.rsp);
        vm.write_with_abi(ucontext_ptr, ucontext, abi)?;

        match abi {
            Abi::I386 => {
                self.registers.rsp = align_down(self.registers.rsp, 16) - 4;
                self.registers.rsp -= 12;
                vm.write_with_abi(Pointer::new(self.registers.rsp + 8), ucontext_ptr, abi)?;
                vm.write_with_abi(Pointer::new(self.registers.rsp + 4), sig_info_ptr, abi)?;
                vm.write_with_abi(
                    Pointer::new(self.registers.rsp),
                    sig_info.signal.get() as u32,
                    abi,
                )?;
            }
            Abi::Amd64 => {
                self.registers.rax = 0;
                self.registers.rdi = u64::from_usize(sig_info.signal.get());
                self.registers.rsi = sig_info_ptr.get().as_u64();
                self.registers.rdx = ucontext_ptr.get().as_u64();
            }
        }

        self.registers.rsp -= u64::from_usize(restorer.size(abi));
        vm.write_with_abi(Pointer::new(self.registers.rsp), restorer, abi)?;

        self.registers.rip = sigaction.sa_handler_or_sigaction;

        Ok(())
    }

    pub fn finish_signal_handler(
        &mut self,
        vm: &VirtualMemory,
        abi: Abi,
    ) -> Result<(Stack, Sigset)> {
        let ucontext_ptr: Pointer<UContext> = match abi {
            Abi::I386 => {
                let ucontext_ptr_ptr = Pointer::new(self.registers.rsp + 8);
                vm.read_with_abi(ucontext_ptr_ptr, abi)?
            }
            Abi::Amd64 => Pointer::new(self.registers.rsp),
        };
        let ucontext = vm.read_with_abi(ucontext_ptr, abi)?;
        self.load_sig_context(&ucontext.mcontext);

        // Load the fp state.
        let fpstate = ucontext.mcontext.fpstate;
        if !fpstate.is_null() {
            let xsave_data = &mut *self.xsave_area.data;
            match abi {
                Abi::I386 => {
                    let ptr = fpstate;

                    // Read the 32-bit specific header.
                    let mut header = Fpstate32Header::zeroed();
                    vm.read_bytes(ptr.get(), bytes_of_mut(&mut header))?;
                    let ptr = ptr.bytes_offset(size_of::<Fpstate32Header>());

                    // Load the xsave data.
                    vm.read_bytes(ptr.get(), xsave_data)?;

                    // Restore the fields from the header.
                    let fxsave = from_bytes_mut::<FXSave>(&mut xsave_data[..512]);
                    fxsave.fcw = header.cw as u16;
                    fxsave.fsw = header.sw as u16;
                    fxsave.ftw = header.tag as u8;
                    fxsave.ipoff = header.ipoff;
                    fxsave.cssel = header.cssel;
                    fxsave.dataoff = header.dataoff;
                    fxsave.datasel = header.datasel;
                    fxsave.st = header.st;
                }
                Abi::Amd64 => {
                    // Load the xsave data.
                    vm.read_bytes(fpstate.get(), xsave_data)?;
                    // Clear the bytes reserved for software.
                    xsave_data[0x1a0..0x200].fill(0);
                }
            }
        }

        Ok((ucontext.stack, ucontext.sigmask))
    }

    #[cfg(not(feature = "harden"))]
    pub fn last_exit(&self) -> Option<Exit> {
        self.last_exit
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Registers {
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
    pub rip: u64,
    pub rflags: u64,
    pub fs_base: u64,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
}

impl Registers {
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
        rip: 0,
        rflags: 0,
        fs_base: 0,
        cs: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
        ss: 0,
    };

    pub const DEFAULT: Self = Self {
        cs: 0x1b,
        ds: 0x23,
        es: 0x23,
        fs: 0,
        gs: 0,
        ss: 0x23,
        rflags: 2 | RFlags::INTERRUPT_FLAG.bits(),
        ..Self::ZERO
    };
}

/// The set of kernel registers saved when entering userspace. These correspond
/// to the callee-saved registers of the System V AMD64 ABI.
#[derive(Clone, Copy)]
pub struct KernelRegisters {
    rbx: u64,
    rsp: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rflags: u64,
}

impl KernelRegisters {
    pub const ZERO: Self = Self {
        rbx: 0,
        rsp: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rflags: 0,
    };
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum RawExit {
    /// The process yielded control to the kernel by issueing the `syscall`
    /// instruction.
    Syscall = 0,
    /// The process yielded control to the kernel by issueing the `int 0x80`
    /// instruction or triggering an exception.
    Exception = 1,
}

#[derive(Debug, Clone, Copy)]
pub enum Exit {
    Syscall(SyscallArgs),
    DivideError,
    InvalidOpcode,
    GeneralProtectionFault,
    PageFault(PageFaultExit),
    Timer,
}

#[derive(Debug, Clone, Copy)]
pub struct PageFaultExit {
    pub addr: u64,
    pub code: PageFaultErrorCode,
}

#[derive(Clone)]
struct XSaveArea {
    data: Vec<u8>,
}

impl XSaveArea {
    pub fn new() -> Self {
        static SIZE: Lazy<usize> = Lazy::new(|| {
            let res = unsafe { __cpuid_count(0xd, 0x0) };
            res.ecx as usize
        });

        let mut data = vec![0; *SIZE];
        data[0..2].copy_from_slice(&0x37fu16.to_ne_bytes()); // FCW
        data[5] = 0xff; // FTW
        data[24..28].copy_from_slice(&0x1f80u32.to_ne_bytes()); // MXCSR

        Self { data }
    }

    pub fn flags() -> XCr0Flags {
        XCr0::read()
            & (XCr0Flags::X87
                | XCr0Flags::SSE
                | XCr0Flags::AVX
                | XCr0Flags::OPMASK
                | XCr0Flags::ZMM_HI256
                | XCr0Flags::HI16_ZMM)
    }

    fn save(&mut self) {
        let save_mask = Self::flags();
        unsafe {
            _xsaveopt64(self.data.as_mut_ptr(), save_mask.bits());
        }
    }

    fn load(&self) {
        let rs_mask = Self::flags();
        unsafe {
            _xrstor64(self.data.as_ptr(), rs_mask.bits());
        }
    }
}

/// The first 512 bytes used by the xsave instructions.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C, align(64))]
struct FXSave {
    fcw: u16,
    fsw: u16,
    ftw: u8,
    _padding1: u8,
    fop: u16,
    ipoff: u32,
    cssel: u32,
    dataoff: u32,
    datasel: u32,
    mxcsr: u32,
    mxcsr_mask: u32,
    st: [St; 8],
    xmm: [Xmm; 16],
    _padding2: [u8; 96],
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct St([u8; 16]);

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct Xmm([u8; 16]);

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct Fpstate32Header {
    cw: u32,
    sw: u32,
    tag: u32,
    ipoff: u32,
    cssel: u32,
    dataoff: u32,
    datasel: u32,
    st: [St; 8],
    status: u16,
    magic: u16,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct FpxSwBytes {
    magic1: u32,
    extended_size: u32,
    xfeatures: u64,
    xstate_size: u32,
    padding: [u32; 7],
}

pub fn init() {
    LStar::write(VirtAddr::new(syscall_entry as usize as u64));
    SFMask::write(RFlags::DIRECTION_FLAG | RFlags::INTERRUPT_FLAG);
}

unsafe extern "sysv64" {
    fn enter_userspace();
    pub fn interrupt_entry();
    pub fn exception_entry();
    fn syscall_entry();
}

macro_rules! kernel_reg_offset {
    ($ident:ident) => {{ offset_of!(PerCpu, kernel_registers) + offset_of!(KernelRegisters, $ident) }};
}
macro_rules! userspace_reg_offset {
    ($ident:ident) => {{ offset_of!(PerCpu, new_userspace_registers) + offset_of!(Registers, $ident) }};
}

global_asm!(
    ".global enter_userspace",
    "enter_userspace:",

    // Save kernel state.
    // Save the kernel registers.
    "mov gs:[{K_RBX_OFFSET}], rbx",
    "mov gs:[{K_RSP_OFFSET}], rsp",
    "mov gs:[{K_RBP_OFFSET}], rbp",
    "mov gs:[{K_R12_OFFSET}], r12",
    "mov gs:[{K_R13_OFFSET}], r13",
    "mov gs:[{K_R14_OFFSET}], r14",
    "mov gs:[{K_R15_OFFSET}], r15",
    // Save RFLAGS.
    "pushfq",
    "pop rax",
    "mov gs:[{K_RFLAGS_OFFSET}], rax",

    // Disable interrupts.
    "cli",

    // Restore user state.
    // Restore segment registers.
    "xor rax, rax",
    "mov ax, gs:[{U_DS_OFFSET}]",
    "mov ds, ax",
    "mov ax, gs:[{U_ES_OFFSET}]",
    "mov es, ax",
    "mov ax, gs:[{U_FS_OFFSET}]",
    "mov fs, ax",
    "mov ax, gs:[{U_GS_OFFSET}]",
    "swapgs",
    "mov gs, ax",
    "swapgs",
    // Restore FS base.
    "mov rax, gs:[{U_FS_BASE_OFFSET}]",
    "wrfsbase rax",
    // Restore userspace registers.
    "mov rax, gs:[{U_RAX_OFFSET}]",
    "mov rbx, gs:[{U_RBX_OFFSET}]",
    "mov rcx, gs:[{U_RCX_OFFSET}]",
    "mov rdx, gs:[{U_RDX_OFFSET}]",
    "mov rsi, gs:[{U_RSI_OFFSET}]",
    "mov rdi, gs:[{U_RDI_OFFSET}]",
    "mov rbp, gs:[{U_RBP_OFFSET}]",
    "mov r8, gs:[{U_R8_OFFSET}]",
    "mov r9, gs:[{U_R9_OFFSET}]",
    "mov r10, gs:[{U_R10_OFFSET}]",
    "mov r11, gs:[{U_R11_OFFSET}]",
    "mov r12, gs:[{U_R12_OFFSET}]",
    "mov r13, gs:[{U_R13_OFFSET}]",
    "mov r14, gs:[{U_R14_OFFSET}]",
    "mov r15, gs:[{U_R15_OFFSET}]",

    // Check if we should use the `sysretq` instruction to enter
    // userspace.
    "cmp byte ptr gs:[{EXIT_WITH_SYSRET_OFFSET}], 0",
    "je 65f",

    // Enter userspace using sysretq.
    "mov rcx, gs:[{U_RIP_OFFSET}]",
    "mov r11, gs:[{U_RFLAGS_OFFSET}]",
    "mov rsp, gs:[{U_RSP_OFFSET}]",
    // Swap in userspace GS.
    "swapgs",
    // Enter usermode.
    "sysretq",

    // Enter userspace using iretq.
    "65:",
    // Setup stack frame.
    // SS
    "mov qword ptr [rsp - 8], 0",
    "sub rsp, 6",
    "push word ptr gs:[{U_SS_OFFSET}]",
    // RSP
    "push gs:[{U_RSP_OFFSET}]",
    // RFLAGS
    "push gs:[{U_RFLAGS_OFFSET}]",
    // CS
    "mov qword ptr [rsp - 8], 0",
    "sub rsp, 6",
    "push word ptr gs:[{U_CS_OFFSET}]",
    // RIP
    "push gs:[{U_RIP_OFFSET}]",
    // Swap in userspace GS.
    "swapgs",
    // Enter usermode.
    "iretq",

    // Exit point for an interrupt/exception.
    // Note that `swapgs` was already executed by the interrupt/exception handler.
    ".global interrupt_entry",
    "interrupt_entry:",
    // Exit point for an exception.
    // Note that `swapgs` was already executed by the exception handler.
    ".global exception_entry",
    "exception_entry:",
    // Record the exit reason.
    "mov byte ptr gs:[{EXIT_OFFSET}], {EXIT_EXCP}",
    // Save values from stack frame.
    "mov gs:[{U_RAX_OFFSET}], rax",
    "pop qword ptr gs:[{U_RIP_OFFSET}]", // pop RIP
    "pop rax", // pop CS,
    "mov gs:[{U_CS_OFFSET}], ax",
    "pop qword ptr gs:[{U_RFLAGS_OFFSET}]", // pop RFLAGS
    "pop qword ptr gs:[{U_RSP_OFFSET}]", // pop RSP
    "pop rax", // pop SS
    "mov gs:[{U_SS_OFFSET}], ax",
    // Jump to the common save state code.
    "jmp 68f",

    // Exit point for the `syscall` instruction
    ".global syscall_entry",
    "syscall_entry:",
    // Swap in kernel GS.
    "swapgs",
    // Record the exit reason.
    "mov byte ptr gs:[{EXIT_OFFSET}], {EXIT_SYSCALL}",
    // Save userspace registers.
    "mov gs:[{U_RAX_OFFSET}], rax",
    "mov gs:[{U_RSP_OFFSET}], rsp",
    "mov gs:[{U_RIP_OFFSET}], rcx",
    "mov gs:[{U_RFLAGS_OFFSET}], r11",
    // Fall through to 68f

    // Common user save state code.
    "68:",
    // Save segment registers.
    "mov ax, ds",
    "mov gs:[{U_DS_OFFSET}], ax",
    "mov ax, es",
    "mov gs:[{U_ES_OFFSET}], ax",
    "mov ax, fs",
    "mov gs:[{U_FS_OFFSET}], ax",
    "mov ax, gs",
    "mov gs:[{U_GS_OFFSET}], ax",
    // Save FS base.
    "rdfsbase rax",
    "mov gs:[{U_FS_BASE_OFFSET}], rax",
    // Save registers.
    "mov gs:[{U_RBX_OFFSET}], rbx",
    "mov gs:[{U_RCX_OFFSET}], rcx",
    "mov gs:[{U_RDX_OFFSET}], rdx",
    "mov gs:[{U_RSI_OFFSET}], rsi",
    "mov gs:[{U_RDI_OFFSET}], rdi",
    "mov gs:[{U_RBP_OFFSET}], rbp",
    "mov gs:[{U_R8_OFFSET}], r8",
    "mov gs:[{U_R9_OFFSET}], r9",
    "mov gs:[{U_R10_OFFSET}], r10",
    "mov gs:[{U_R11_OFFSET}], r11",
    "mov gs:[{U_R12_OFFSET}], r12",
    "mov gs:[{U_R13_OFFSET}], r13",
    "mov gs:[{U_R14_OFFSET}], r14",
    "mov gs:[{U_R15_OFFSET}], r15",

    // Restore kernel state.
    // Restore the kernel registers.
    "mov rbx, gs:[{K_RBX_OFFSET}]",
    "mov rsp, gs:[{K_RSP_OFFSET}]",
    "mov rbp, gs:[{K_RBP_OFFSET}]",
    "mov r12, gs:[{K_R12_OFFSET}]",
    "mov r13, gs:[{K_R13_OFFSET}]",
    "mov r14, gs:[{K_R14_OFFSET}]",
    "mov r15, gs:[{K_R15_OFFSET}]",
    // Restore RFLAGS. This implicitly enables interrupts.
    "mov rax, gs:[{K_RFLAGS_OFFSET}]",
    "push rax",
    "popfq",
    "ret",

    EXIT_WITH_SYSRET_OFFSET = const offset_of!(PerCpu, exit_with_sysret),
    EXIT_OFFSET = const offset_of!(PerCpu, exit),
    EXIT_SYSCALL = const RawExit::Syscall as u8,
    EXIT_EXCP = const RawExit::Exception as u8,
    K_RBX_OFFSET = const kernel_reg_offset!(rbx),
    K_RSP_OFFSET = const kernel_reg_offset!(rsp),
    K_RBP_OFFSET = const kernel_reg_offset!(rbp),
    K_R12_OFFSET = const kernel_reg_offset!(r12),
    K_R13_OFFSET = const kernel_reg_offset!(r13),
    K_R14_OFFSET = const kernel_reg_offset!(r14),
    K_R15_OFFSET = const kernel_reg_offset!(r15),
    K_RFLAGS_OFFSET = const kernel_reg_offset!(rflags),
    U_RAX_OFFSET = const userspace_reg_offset!(rax),
    U_RBX_OFFSET = const userspace_reg_offset!(rbx),
    U_RCX_OFFSET = const userspace_reg_offset!(rcx),
    U_RDX_OFFSET = const userspace_reg_offset!(rdx),
    U_RSI_OFFSET = const userspace_reg_offset!(rsi),
    U_RDI_OFFSET = const userspace_reg_offset!(rdi),
    U_RSP_OFFSET = const userspace_reg_offset!(rsp),
    U_RBP_OFFSET = const userspace_reg_offset!(rbp),
    U_R8_OFFSET = const userspace_reg_offset!(r8),
    U_R9_OFFSET = const userspace_reg_offset!(r9),
    U_R10_OFFSET = const userspace_reg_offset!(r10),
    U_R11_OFFSET = const userspace_reg_offset!(r11),
    U_R12_OFFSET = const userspace_reg_offset!(r12),
    U_R13_OFFSET = const userspace_reg_offset!(r13),
    U_R14_OFFSET = const userspace_reg_offset!(r14),
    U_R15_OFFSET = const userspace_reg_offset!(r15),
    U_RIP_OFFSET = const userspace_reg_offset!(rip),
    U_RFLAGS_OFFSET = const userspace_reg_offset!(rflags),
    U_CS_OFFSET = const userspace_reg_offset!(cs),
    U_DS_OFFSET = const userspace_reg_offset!(ds),
    U_ES_OFFSET = const userspace_reg_offset!(es),
    U_FS_OFFSET = const userspace_reg_offset!(fs),
    U_FS_BASE_OFFSET = const userspace_reg_offset!(fs_base),
    U_GS_OFFSET = const userspace_reg_offset!(gs),
    U_SS_OFFSET = const userspace_reg_offset!(ss),
);
