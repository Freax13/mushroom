fn main() {
    // https://github.com/rust-lang/cargo/issues/10527
    println!("cargo:rerun-if-changed=kernel/");
}
