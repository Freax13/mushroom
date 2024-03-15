#![cfg(test)]
#![feature(asm_const)]

use std::{
    alloc::{alloc, dealloc, Layout},
    arch::asm,
    ffi::{c_void, OsStr},
    fs::create_dir,
    mem::size_of,
    path::{Path, PathBuf},
    ptr::{null_mut, NonNull},
    sync::{
        atomic::{AtomicBool, AtomicPtr, AtomicU8, Ordering},
        Mutex, PoisonError,
    },
};

use nix::{
    libc::{sigaltstack, siginfo_t, stack_t, SYS_exit, SYS_vfork},
    sys::{
        mman::{mprotect, ProtFlags},
        signal::{sigaction, SaFlags, SigAction, SigSet},
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

// A look to take before changing signal handlers to prevent race-conditions
// between tests.
static SIGNAL_HANDLER_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn signal_handling() {
    let _guard = SIGNAL_HANDLER_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);

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
    let _guard = SIGNAL_HANDLER_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);

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

// Return a path for use in a test.
fn get_temp_dir(test_name: &'static str) -> PathBuf {
    //  Get the directory meant to be used by tests (found in
    // CARGO_TARGET_TMPDIR). This environment variable won't be set in mushroom
    // so we'll default to a different directory if the variable is not set.
    let var = std::env::var_os("CARGO_TARGET_TMPDIR");
    let base_path = var
        .as_deref()
        .unwrap_or_else(|| OsStr::new("/tmp/mushroom-tests"));
    let base_path: &Path = base_path.as_ref();

    // Create a path for the test.
    let path = base_path.join(test_name);

    // Reset the directory.
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();

    path
}

#[test]
fn rename() {
    let base = get_temp_dir("rename");

    // Rename a directory.
    let src = &base.join("src-1");
    let dst = &base.join("dst-1");
    create_dir(src).unwrap();
    std::fs::rename(src, dst).unwrap();

    // Rename a directory (source with trailing slash).
    let src = &base.join("src-2");
    let dst = &base.join("dst-2");
    create_dir(src).unwrap();
    std::fs::rename(src.join(""), dst).unwrap();

    // Rename a directory (destination with trailing slash).
    let src = &base.join("src-3");
    let dst = &base.join("dst-3");
    create_dir(src).unwrap();
    std::fs::rename(src, dst.join("")).unwrap();

    // Rename a directory (source and destination with trailing slash).
    let src = &base.join("src-4");
    let dst = &base.join("dst-4");
    create_dir(src).unwrap();
    std::fs::rename(src.join(""), dst.join("")).unwrap();

    // Rename a file.
    let src = &base.join("src-5");
    let dst = &base.join("dst-5");
    std::fs::write(src, "").unwrap();
    std::fs::rename(src, dst).unwrap();

    // Fail to rename a file if the source or destination have a trailing
    // slash.
    let src = &base.join("src-6");
    let dst = &base.join("dst-6");
    std::fs::write(src, "").unwrap();
    std::fs::rename(src.join(""), dst).unwrap_err();
    std::fs::rename(src, dst.join("")).unwrap_err();
    std::fs::rename(src.join(""), dst.join("")).unwrap_err();

    // Rename a dir to an existing empty dir.
    let src = &base.join("src-7");
    let dst = &base.join("dst-7");
    create_dir(src).unwrap();
    create_dir(dst).unwrap();
    std::fs::rename(src, dst).unwrap();

    // Fail to rename a dir to an existing non-empty dir.
    let src = &base.join("src-8");
    let dst = &base.join("dst-8");
    create_dir(src).unwrap();
    create_dir(dst).unwrap();
    std::fs::write(dst.join("file"), "").unwrap();
    std::fs::rename(src, dst).unwrap_err();

    // Fail to rename a dir to an existing file.
    let src = &base.join("src-9");
    let dst = &base.join("dst-9");
    create_dir(src).unwrap();
    std::fs::write(dst, "").unwrap();
    std::fs::rename(src, dst).unwrap_err();

    // Fail to rename a file to an existing dir.
    let src = &base.join("src-10");
    let dst = &base.join("dst-10");
    std::fs::write(src, "").unwrap();
    create_dir(dst).unwrap();
    std::fs::rename(src, dst).unwrap_err();

    // Rename a file to an existing file.
    let src = &base.join("src-11");
    let dst = &base.join("dst-11");
    std::fs::write(src, "").unwrap();
    std::fs::write(dst, "").unwrap();
    std::fs::rename(src, dst).unwrap();
}

#[test]
fn mkdir() {
    let base = get_temp_dir("mkdir");

    // Create directory.
    let src = &base.join("dir-1");
    create_dir(src).unwrap();

    // Create directory with trailing slash.
    let src = &base.join("dir-2");
    create_dir(src.join("")).unwrap();
}
