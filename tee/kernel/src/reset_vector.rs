use crate::main;

#[no_mangle]
#[link_section = ".reset_vector"]
unsafe extern "sysv64" fn start() -> ! {
    unsafe {
        main();
    }
}

/// This memory is used as stack memory before each vCPU allocated its own
/// stack.
#[used]
#[link_section = ".stack"]
static mut INIT_STACK: [u8; 4 * 4096] = [0; 4 * 4096];
