use core::arch::{asm, global_asm};

use crate::main;

global_asm!(include_str!("reset_vector.s"));

#[export_name = "_start"]
#[naked]
extern "sysv64" fn start() -> ! {
    const STACK_SIZE: usize = 32 * 4096;
    #[link_section = ".stack"]
    static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

    unsafe {
        asm!(
            "lea rsp, [rip + {STACK} + {STACK_SIZE}]",
            "and rsp, ~15",
            "call {PREMAIN}",
            "int3",
            STACK = sym STACK,
            STACK_SIZE = const STACK_SIZE,
            PREMAIN = sym premain,
            options(noreturn)
        );
    }
}

extern "sysv64" fn premain() {
    main();
}
