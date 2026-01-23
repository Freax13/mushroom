use std::path::Path;

fn main() {
    let local_path = Path::new(env!("CARGO_MANIFEST_DIR"));

    let pointer_width = std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap();
    let linker_file = format!("linker-{pointer_width}.ld");

    println!(
        "cargo:rustc-link-arg=--script={}",
        local_path.join(&linker_file).display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        local_path.join(&linker_file).display()
    );
}
