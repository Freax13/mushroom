use core::mem::size_of;

use bit_field::BitField;
use bytemuck::checked::pod_read_unaligned;
use constants::physical_address::{INIT_FILE, INPUT_FILE};
use io::input::{Hasher, Header};
use log::info;
use tdx_types::tdcall::GpaAttr;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{Page, PhysFrame, Size4KiB},
};

use crate::tdcall::{self, Tdcall};

pub fn init() {
    // Fetch the input data for the workload.
    verify_and_load();

    // Make the kernel and the init binary accessible to the L2 VM.
    load_kernel();
    load_init();
}

/// Verify the input and make it accessible to the L2 VM.
fn verify_and_load() {
    let mut page_index = 0;

    // Verify the input header.
    let mr_config_id = Tdcall::mr_report([0; 64]).td_info.base.mr_config_id;
    assert_eq!(mr_config_id[32..], [0; 16]);
    let mut next_hash = <[u8; 32]>::try_from(&mr_config_id[0..32]).unwrap();
    loop {
        // Read the input header.
        let header_page_bytes = convert_to_private_in_place(page_index);
        let header_bytes = &header_page_bytes[..size_of::<Header>()];
        let header = pod_read_unaligned::<Header>(header_bytes);
        page_index += 1;

        // Verify the input header.
        assert!(header.verify(next_hash), "header doesn't match");

        if header == Header::end() {
            break;
        }

        // Hash the input.

        let mut hasher = Hasher::new(header.hash_type);

        // Copy pages one at a time.
        let mut remaining_len = usize::try_from(header.input_len).unwrap();
        while remaining_len >= 0x1000 {
            let input_bytes = convert_to_private_in_place(page_index);
            page_index += 1;
            hasher.update(&input_bytes);
            remaining_len -= 0x1000;
        }

        // The last page may not be a full page.
        if remaining_len > 0 {
            let input_bytes = convert_to_private_in_place(page_index);
            page_index += 1;
            let (input_bytes, rest) = input_bytes.split_at(remaining_len);
            hasher.update(input_bytes);

            // The page must be zero past the end of the input.
            assert_eq!(rest, &[0; 4096][remaining_len..]);
        }

        // Verify the input.
        hasher.verify(header.hash);

        next_hash = header.next_hash;
    }

    info!("verified input");
}

/// This converts a page of the input file to private memory. Returns the
/// content of the page.
fn convert_to_private_in_place(index: u64) -> [u8; 0x1000] {
    let shared_mapping =
        Page::<Size4KiB>::from_start_address(VirtAddr::new(0x1000000000)).unwrap() + index;
    let private_mapping =
        Page::<Size4KiB>::from_start_address(VirtAddr::new(0x2000000000)).unwrap() + index;
    let frame = PhysFrame::<Size4KiB>::from_start_address(INPUT_FILE.start.start_address())
        .unwrap()
        + index;

    // Copy to content out of the shared mapping.
    let mut content = [0u8; 0x1000];
    unsafe {
        core::intrinsics::volatile_copy_nonoverlapping_memory(
            &mut content,
            shared_mapping.start_address().as_ptr(),
            1,
        );
    }

    // Tell the Hypervisor that we want to change the page to private.
    tdcall::Vmcall::map_gpa(PhysFrame::range(frame, frame + 1), true);

    // Validate the page.
    unsafe {
        Tdcall::mem_page_accept(frame);
    }

    // Copy the content back in.
    unsafe {
        core::intrinsics::volatile_copy_nonoverlapping_memory(
            private_mapping.start_address().as_mut_ptr(),
            &content,
            1,
        );
    }

    // Adjust the permissions for the L2 VM.
    unsafe {
        Tdcall::mem_page_attr_wr(frame, GpaAttr::READ | GpaAttr::VALID, GpaAttr::READ, true);
    }

    content
}

#[repr(C)]
struct KernelElfHeader {
    _unused1: [u8; 0x38],
    e_phnum: u16,
    _unused2: [u8; 6],
    program_headers: [ProgramHeader; 0x100],
}

impl KernelElfHeader {
    fn get() -> &'static Self {
        unsafe extern "C" {
            #[link_name = "kernel_elf_header"]
            static KERNEL_ELF_HEADER: KernelElfHeader;
        }
        unsafe { &KERNEL_ELF_HEADER }
    }

    fn program_headers(&self) -> &[ProgramHeader] {
        &self.program_headers[..usize::from(self.e_phnum)]
    }
}

#[derive(Debug)]
#[repr(C)]
struct ProgramHeader {
    ty: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

/// Make the kernel accessible to the L2 VM.
fn load_kernel() {
    let kernel_elf_header = KernelElfHeader::get();

    for ph in kernel_elf_header
        .program_headers()
        .iter()
        .filter(|ph| ph.ty == 1)
        .filter(|ph| ph.memsz > 0)
        .filter(|ph| !ph.flags.get_bit(30))
    {
        let mut attrs = GpaAttr::VALID;
        attrs.set(GpaAttr::READ, ph.flags.get_bit(2));
        attrs.set(GpaAttr::WRITE, ph.flags.get_bit(1));
        attrs.set(GpaAttr::EXECUTE_SUPERVISOR, ph.flags.get_bit(0));

        let start = PhysAddr::new(ph.paddr);
        let end = start + (ph.memsz - 1);
        let start = PhysFrame::<Size4KiB>::containing_address(start);
        let end = PhysFrame::<Size4KiB>::containing_address(end);
        for frame in PhysFrame::range_inclusive(start, end) {
            unsafe {
                Tdcall::mem_page_attr_wr(frame, attrs, attrs & !GpaAttr::VALID, false);
            }
        }
    }
}

/// Make the init binary file accessible to the L2 VM.
fn load_init() {
    let header = unsafe { &*(0x3000000000 as *const Header) };

    let start_address = INIT_FILE.start.start_address();
    let end_address = start_address + 0x1000 + header.input_len - 1;
    let start = PhysFrame::<Size4KiB>::containing_address(start_address);
    let end = PhysFrame::<Size4KiB>::containing_address(end_address) + 1;
    for frame in PhysFrame::range_inclusive(start, end) {
        unsafe {
            Tdcall::mem_page_attr_wr(frame, GpaAttr::READ | GpaAttr::VALID, GpaAttr::READ, true);
        }
    }
}
