#![cfg(test)]

mod epoll;
mod fs;
mod memfd;
mod mmap;
mod net;
mod ptrace;
mod pty;
mod ready;
mod rlimit;
mod semaphore;
mod timer;
mod uname;
mod unix;
mod unix_file_lock;
mod vdso;

use std::{
    alloc::{Layout, alloc, dealloc},
    arch::asm,
    env::{current_dir, set_current_dir},
    ffi::c_void,
    fs::{create_dir, create_dir_all, remove_dir_all},
    mem::size_of,
    panic::Location,
    path::{Path, PathBuf},
    ptr::{NonNull, null_mut},
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, Ordering},
};

use nix::{
    libc::{SYS_exit, SYS_vfork, sigaltstack, siginfo_t, stack_t},
    sys::{
        mman::{ProtFlags, mprotect},
        prctl,
        signal::{SaFlags, SigAction, SigSet, sigaction},
    },
};

#[test]
fn it_works() {
    let result = 2 + 2;
    assert_eq!(result, 4);
}

#[test]
fn vfork_exit() {
    #[cfg(target_arch = "x86")]
    unsafe {
        asm!(
            "mov eax, {vfork}",
            "int 0x80",
            "test eax, eax",
            "jnz 66f",
            "xor ebx, ebx",
            "mov eax, {exit}",
            "int 0x80",
            "66:",
            vfork = const SYS_vfork,
            exit = const SYS_exit,
        );
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!(
            "mov rax, {vfork}",
            "syscall",
            "test rax, rax",
            "jnz 66f",
            "xor rdi, rdi",
            "mov rax, {exit}",
            "syscall",
            "66:",
            vfork = const SYS_vfork,
            exit = const SYS_exit,
        );
    }
}

#[test]
fn signal_handling() {
    // Some memory for us to mess with.
    #[repr(align(4096))]
    struct Memory {
        value: AtomicU8,
    }
    static SOME_MEMORY: Memory = Memory {
        value: AtomicU8::new(0),
    };

    /// Whether we handled a signal.
    static HANDLED: AtomicBool = AtomicBool::new(false);

    // Take away the write permisssions for SOME_MEMORY.
    unsafe {
        mprotect(
            NonNull::from(&SOME_MEMORY).cast(),
            size_of::<Memory>(),
            ProtFlags::PROT_READ,
        )
        .unwrap();
    }

    extern "C" fn handler(_: i32, _: *mut siginfo_t, _: *mut c_void) {
        // Restore the write permissions.
        unsafe {
            mprotect(
                NonNull::from(&SOME_MEMORY).cast(),
                size_of::<Memory>(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
            .unwrap();
        }

        // Store that we handled a signal.
        HANDLED.store(true, Ordering::SeqCst);
    }
    // Register the signal handler.
    unsafe {
        sigaction(
            nix::sys::signal::Signal::SIGSEGV,
            &SigAction::new(
                nix::sys::signal::SigHandler::SigAction(handler),
                SaFlags::empty(),
                SigSet::empty(),
            ),
        )
        .unwrap();
    }

    assert!(!HANDLED.load(Ordering::SeqCst));

    // Write to SOME_MEMORY to trigger a segfault.
    SOME_MEMORY.value.fetch_add(1, Ordering::SeqCst);

    assert!(HANDLED.load(Ordering::SeqCst));
}

#[test]
fn stack_switch() {
    // Allocate an alternate stack.
    static ALTERNATE_STACK: AtomicPtr<u8> = AtomicPtr::new(null_mut());
    const STACK_SIZE: usize = 0x10000;
    let layout = Layout::array::<u8>(STACK_SIZE)
        .unwrap()
        .align_to(16)
        .unwrap();
    let alternate_stack = unsafe { alloc(layout) };
    assert!(!alternate_stack.is_null());
    ALTERNATE_STACK.store(alternate_stack, Ordering::SeqCst);

    // Setup the alternate stack.
    let ss = stack_t {
        ss_sp: alternate_stack.cast(),
        ss_flags: 0,
        ss_size: STACK_SIZE,
    };
    let mut oss = stack_t {
        ss_sp: null_mut(),
        ss_flags: 0,
        ss_size: 0,
    };
    let res = unsafe { sigaltstack(&ss, &mut oss) };
    assert_eq!(res, 0);

    // Some memory for us to mess with.
    #[repr(align(4096))]
    struct Memory {
        value: AtomicU8,
    }
    static SOME_MEMORY: Memory = Memory {
        value: AtomicU8::new(0),
    };

    /// Whether we handled a signal.
    static HANDLED: AtomicBool = AtomicBool::new(false);

    // Take away the write permisssions for SOME_MEMORY.
    unsafe {
        mprotect(
            NonNull::from(&SOME_MEMORY).cast(),
            size_of::<Memory>(),
            ProtFlags::PROT_READ,
        )
        .unwrap();
    }

    extern "C" fn handler(_: i32, _: *mut siginfo_t, _: *mut c_void) {
        // Make sure that we switch to the other stack.
        let stack_variable = 0;
        let pointer_to_stack = &stack_variable as *const i32;
        let alternate_stack = ALTERNATE_STACK.load(Ordering::SeqCst);
        assert!(
            (alternate_stack..alternate_stack.wrapping_byte_add(STACK_SIZE))
                .contains(&pointer_to_stack.cast_mut().cast())
        );

        // Restore the write permissions.
        unsafe {
            mprotect(
                NonNull::from(&SOME_MEMORY).cast(),
                size_of::<Memory>(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
            .unwrap();
        }

        // Store that we handled a signal.
        HANDLED.store(true, Ordering::SeqCst);
    }

    // Register the signal handler.
    unsafe {
        sigaction(
            nix::sys::signal::Signal::SIGSEGV,
            &SigAction::new(
                nix::sys::signal::SigHandler::SigAction(handler),
                SaFlags::SA_ONSTACK,
                SigSet::empty(),
            ),
        )
        .unwrap();
    }

    assert!(!HANDLED.load(Ordering::SeqCst));

    // Write to SOME_MEMORY to trigger a segfault.
    SOME_MEMORY.value.fetch_add(1, Ordering::SeqCst);

    assert!(HANDLED.load(Ordering::SeqCst));

    // Restore the old stack.
    let res = unsafe { sigaltstack(&oss, null_mut()) };
    assert_eq!(res, 0);

    // Free the alternate stack.
    unsafe {
        dealloc(alternate_stack, layout);
    }
}

struct TmpDirGuard {
    path: PathBuf,
    old_cwd: PathBuf,
}

impl TmpDirGuard {
    #[track_caller]
    pub fn new() -> Self {
        let old_cwd = current_dir().unwrap();

        let base_path: &Path = "/tmp/mushroom-tests".as_ref();
        let test_name = format!("{}", Location::caller());
        let test_name = test_name
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect::<String>();
        let path = base_path.join(test_name);

        let _ = remove_dir_all(&path);
        create_dir_all(&path).unwrap();
        set_current_dir(&path).unwrap();

        Self { path, old_cwd }
    }
}

impl Drop for TmpDirGuard {
    fn drop(&mut self) {
        set_current_dir(&self.old_cwd).unwrap();
        remove_dir_all(&self.path).unwrap();
    }
}

#[test]
fn rename() {
    let _guard = TmpDirGuard::new();

    // Rename a directory.
    let src = "src-1";
    let dst = "dst-1";
    create_dir(src).unwrap();
    std::fs::rename(src, dst).unwrap();

    // Rename a directory (source with trailing slash).
    let src = "src-2";
    let dst = "dst-2";
    create_dir(src).unwrap();
    std::fs::rename(format!("{src}/"), dst).unwrap();

    // Rename a directory (destination with trailing slash).
    let src = "src-3";
    let dst = "dst-3";
    create_dir(src).unwrap();
    std::fs::rename(src, format!("{dst}/")).unwrap();

    // Rename a directory (source and destination with trailing slash).
    let src = "src-4";
    let dst = "dst-4";
    create_dir(src).unwrap();
    std::fs::rename(format!("{src}/"), format!("{dst}/")).unwrap();

    // Rename a file.
    let src = "src-5";
    let dst = "dst-5";
    std::fs::write(src, "").unwrap();
    std::fs::rename(src, dst).unwrap();

    // Fail to rename a file if the source or destination have a trailing
    // slash.
    let src = "src-6";
    let dst = "dst-6";
    std::fs::write(src, "").unwrap();
    std::fs::rename(format!("{src}/"), dst).unwrap_err();
    std::fs::rename(src, format!("{dst}/")).unwrap_err();
    std::fs::rename(format!("{src}/"), format!("{dst}/")).unwrap_err();

    // Rename a dir to an existing empty dir.
    let src = "src-7";
    let dst = "dst-7";
    create_dir(src).unwrap();
    create_dir(dst).unwrap();
    std::fs::rename(src, dst).unwrap();

    // Fail to rename a dir to an existing non-empty dir.
    let src = "src-8";
    let dst = "dst-8";
    create_dir(src).unwrap();
    create_dir(dst).unwrap();
    std::fs::write(format!("{dst}/file"), "").unwrap();
    std::fs::rename(src, dst).unwrap_err();

    // Fail to rename a dir to an existing file.
    let src = "src-9";
    let dst = "dst-9";
    create_dir(src).unwrap();
    std::fs::write(dst, "").unwrap();
    std::fs::rename(src, dst).unwrap_err();

    // Fail to rename a file to an existing dir.
    let src = "src-10";
    let dst = "dst-10";
    std::fs::write(src, "").unwrap();
    create_dir(dst).unwrap();
    std::fs::rename(src, dst).unwrap_err();

    // Rename a file to an existing file.
    let src = "src-11";
    let dst = "dst-11";
    std::fs::write(src, "").unwrap();
    std::fs::write(dst, "").unwrap();
    std::fs::rename(src, dst).unwrap();
}

#[test]
fn mkdir() {
    let _guard = TmpDirGuard::new();

    // Create directory.
    create_dir("dir-1").unwrap();

    // Create directory with trailing slash.
    create_dir("dir-2/").unwrap();
}

#[test]
fn task_name() {
    let default_name = prctl::get_name().unwrap();

    prctl::set_name(c"my thread name").unwrap();
    assert_eq!(prctl::get_name().unwrap().as_c_str(), c"my thread name");
    std::thread::spawn(move || {
        assert_ne!(prctl::get_name().unwrap().as_c_str(), c"my thread name");
        assert_ne!(prctl::get_name().unwrap(), default_name);
    });
}
