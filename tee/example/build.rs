use std::fs::exists;

const GCC_ARCHIVE: &str = "gcc.tar.gz";

fn main() {
    // The example includes an archive containing gcc. If that archive hasn't
    // been built yet, we still want this example crate to compile. We set a
    // cfg flag if the file exists and omit it if it doesn't exist. main.rs
    // uses this flag to include the file - or not.
    println!("cargo:rerun-if-changed={GCC_ARCHIVE}");
    if exists(GCC_ARCHIVE).unwrap() {
        println!("cargo:rustc-cfg=has_gcc_archive")
    }
    println!("cargo:rustc-check-cfg=cfg(has_gcc_archive)");
}
