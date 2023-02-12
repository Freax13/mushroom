use crate::main;

#[no_mangle]
#[link_section = ".reset_vector"]
unsafe extern "sysv64" fn start() -> ! {
    unsafe {
        main();
    }
}
