use std::{
    fs::File,
    io::{Result, Write},
    path::Path,
};

use goblin::elf::program_header::{PT_DYNAMIC, PT_GNU_EH_FRAME, PT_LOAD};

fn main() -> Result<()> {
    let local_path = Path::new(env!("CARGO_MANIFEST_DIR"));
    println!(
        "cargo:rustc-link-arg-bins=--script={}",
        local_path.join("linker.ld").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        local_path.join("linker.ld").display()
    );

    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let out_dir: &Path = out_dir.as_ref();
    let mut file = File::create(out_dir.join("vdso_files.rs")).unwrap();
    if let Some(entry_i386) = preprocess_vdso("VDSO_I386")?
        && let Some(entry_amd64) = preprocess_vdso("VDSO_AMD64")?
    {
        file.write_all(b"const fn vdso_i386_bytes() -> &'static [u8] {\n")?;
        file.write_all(b"    include_bytes!(concat!(env!(\"OUT_DIR\"),\"/VDSO_I386\"))\n")?;
        file.write_all(b"}\n\n")?;

        file.write_all(b"const fn vdso_amd64_bytes() -> &'static [u8] {\n")?;
        file.write_all(b"    include_bytes!(concat!(env!(\"OUT_DIR\"),\"/VDSO_AMD64\"))\n")?;
        file.write_all(b"}\n\n")?;

        file.write_all(b"const fn vdso_i386_entry() -> u64 {\n")?;
        writeln!(file, "    {entry_i386}")?;
        file.write_all(b"}\n")?;
        file.write_all(b"const fn vdso_amd64_entry() -> u64 {\n")?;
        writeln!(file, "    {entry_amd64}")?;
        file.write_all(b"}\n")?;
    } else {
        file.write_all(b"const fn vdso_i386_bytes() -> &'static [u8] {\n")?;
        file.write_all(b"    panic!(\"kernel was compiled without vDSO\")\n")?;
        file.write_all(b"}\n\n")?;

        file.write_all(b"const fn vdso_amd64_bytes() -> &'static [u8] {\n")?;
        file.write_all(b"    panic!(\"kernel was compiled without vDSO\")\n")?;
        file.write_all(b"}\n\n")?;

        file.write_all(b"const fn vdso_i386_entry() -> u64 {\n")?;
        file.write_all(b"    panic!(\"kernel was compiled without vDSO\")\n")?;
        file.write_all(b"}\n")?;
        file.write_all(b"const fn vdso_amd64_entry() -> u64 {\n")?;
        file.write_all(b"    panic!(\"kernel was compiled without vDSO\")\n")?;
        file.write_all(b"}\n")?;
    }
    Ok(())
}

fn preprocess_vdso(name: &str) -> Result<Option<u64>> {
    let Ok(vdso) = std::env::var(name) else {
        return Ok(None);
    };
    println!("cargo:rerun-if-changed={vdso}");

    let Ok(buf) = std::fs::read(&vdso) else {
        return Ok(None);
    };

    let Ok(elf) = goblin::elf::Elf::parse(&buf) else {
        return Ok(None);
    };

    assert!(elf.is_lib);
    assert_eq!(elf.program_headers.len(), 3);

    // The first segment must be a load segment.
    let load_segment = &elf.program_headers[0];
    assert_eq!(load_segment.p_type, PT_LOAD);
    assert!(load_segment.is_read());
    assert!(!load_segment.is_write());
    assert!(load_segment.is_executable());
    assert!(load_segment.p_filesz <= load_segment.p_memsz);
    assert!(load_segment.p_align <= 0x1000);

    // The second segment must be a dynamic segment.
    let dynamic_segment = &elf.program_headers[1];
    assert_eq!(dynamic_segment.p_type, PT_DYNAMIC);
    assert!(dynamic_segment.is_read());
    assert!(!dynamic_segment.is_write());
    assert!(!dynamic_segment.is_executable());
    assert!(dynamic_segment.p_filesz <= dynamic_segment.p_memsz);
    assert!(dynamic_segment.p_align <= 0x1000);

    // The third segment must be a dynamic segment.
    let gnu_eh_frame_segment = &elf.program_headers[2];
    assert_eq!(gnu_eh_frame_segment.p_type, PT_GNU_EH_FRAME);
    assert!(gnu_eh_frame_segment.is_read());
    assert!(!gnu_eh_frame_segment.is_write());
    assert!(!gnu_eh_frame_segment.is_executable());
    assert!(gnu_eh_frame_segment.p_filesz <= gnu_eh_frame_segment.p_memsz);
    assert!(gnu_eh_frame_segment.p_align <= 0x1000);

    assert!(load_segment.p_vaddr < dynamic_segment.p_vaddr);
    assert!(dynamic_segment.p_vaddr < gnu_eh_frame_segment.p_vaddr);

    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let out_dir: &Path = out_dir.as_ref();

    std::fs::copy(vdso, out_dir.join(name))?;

    Ok(Some(elf.entry))
}
