use std::{
    env::current_dir,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let root_dir = current_dir().unwrap().join("..").join("..");

    println!(
        "cargo:rerun-if-changed={}",
        root_dir.join("common").display()
    );
    println!("cargo:rerun-if-changed={}", root_dir.join("tee").display());

    let profile = match std::env::var("PROFILE").unwrap().as_str() {
        "debug" => Profile::Debug,
        "release" => Profile::Release,
        profile => panic!("unsupported profile {profile}"),
    };

    build_supervisor(&root_dir, &out_dir, profile);
    build_kernel(&root_dir, &out_dir, profile);
}

fn build_supervisor(root_dir: &Path, out_dir: &Path, profile: Profile) {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(root_dir.join("tee"));
    cmd.env_remove("RUSTFLAGS");
    cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");
    cmd.arg("build").arg("-p").arg("supervisor");
    cmd.arg("--target").arg("supervisor/supervisor.json");
    cmd.arg("--target-dir").arg(out_dir);

    cmd.arg("-Z").arg("build-std=core,alloc,compiler_builtins");
    let profile_str;
    match profile {
        Profile::Debug => {
            profile_str = "supervisor";
            cmd.arg("-Z")
                .arg("build-std-features=compiler-builtins-mem");
        }
        Profile::Release => {
            profile_str = "supervisor-release";
            cmd.arg("-Z")
                .arg("build-std-features=compiler-builtins-mem,panic_immediate_abort");
            cmd.arg("--features").arg("harden");
        }
    }
    cmd.arg("--profile").arg(profile_str);

    let status = cmd
        .status()
        .expect("failed to run cargo build for supervisor");
    if status.success() {
        let path = out_dir
            .join("supervisor")
            .join(profile_str)
            .join("supervisor");
        assert!(
            path.exists(),
            "supervisor executable does not exist after building"
        );
        println!(
            "cargo:rustc-env=CARGO_BIN_FILE_SUPERVISOR={}",
            path.display()
        );
    } else {
        panic!("failed to build supervisor");
    }
}

fn build_kernel(root_dir: &Path, out_dir: &Path, profile: Profile) {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(root_dir.join("tee"));
    cmd.arg("build").arg("-p").arg("kernel");
    cmd.arg("--target").arg("x86_64-unknown-none");
    cmd.arg("--target-dir").arg(out_dir);
    cmd.arg("--profile").arg("kernel");
    cmd.arg("-Z").arg("build-std=core,alloc");
    cmd.env_remove("RUSTFLAGS");
    cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");

    match profile {
        Profile::Debug => {}
        Profile::Release => {
            cmd.arg("--features").arg("harden");
        }
    }

    let status = cmd.status().expect("failed to run cargo build for kernel");
    if status.success() {
        let path = out_dir
            .join("x86_64-unknown-none")
            .join("kernel")
            .join("kernel");
        assert!(
            path.exists(),
            "kernel executable does not exist after building"
        );
        println!("cargo:rustc-env=CARGO_BIN_FILE_KERNEL={}", path.display());
    } else {
        panic!("failed to build kernel");
    }
}

#[derive(Clone, Copy)]
enum Profile {
    Debug,
    Release,
}
