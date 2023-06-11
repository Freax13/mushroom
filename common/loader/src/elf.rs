use std::cmp;

use bit_field::BitField;
use bytemuck::Zeroable;
use goblin::{elf::Elf, elf64::program_header::PT_LOAD};
use raw_cpuid::cpuid;
use snp_types::{
    cpuid::{CpuidFunction, CpuidPage},
    VmplPermissions,
};
use x86_64::{structures::paging::PhysFrame, PhysAddr};

use crate::{LoadCommand, LoadCommandPayload};

pub fn load(
    elf_bytes: &'static [u8],
    vmpl1_perms_mask: VmplPermissions,
) -> impl Iterator<Item = LoadCommand> {
    let elf = Elf::parse(elf_bytes).unwrap();
    assert!(elf.is_64);

    elf.program_headers
        .into_iter()
        .filter(|ph| matches!(ph.p_type, PT_LOAD))
        .flat_map(move |ph| {
            let execute = ph.p_flags.get_bit(0);
            let write = ph.p_flags.get_bit(1);
            let read = ph.p_flags.get_bit(2);
            let cpuid_page = ph.p_flags.get_bit(28);
            let secrets_page = ph.p_flags.get_bit(29);
            let shared_page = ph.p_flags.get_bit(30);

            let mut vmpl1_perms = VmplPermissions::empty();
            if execute {
                vmpl1_perms |= VmplPermissions::EXECUTE_USER;
                vmpl1_perms |= VmplPermissions::EXECUTE_SUPERVISOR;
            }
            if write {
                vmpl1_perms |= VmplPermissions::WRITE;
            }
            if read {
                vmpl1_perms |= VmplPermissions::READ;
            }
            let vmpl1_perms = vmpl1_perms & vmpl1_perms_mask;

            let start_addr = PhysAddr::new(ph.p_paddr);
            let start_frame = PhysFrame::containing_address(start_addr);
            let end_inclusive_file_addr = start_addr + (ph.p_filesz - 1);
            let end_inclusive_addr = start_addr + (ph.p_memsz - 1);
            let end_inclusive_frame = PhysFrame::containing_address(end_inclusive_addr);

            PhysFrame::range_inclusive(start_frame, end_inclusive_frame)
                .into_iter()
                .map(move |frame| {
                    assert!(!(cpuid_page & secrets_page));
                    assert!(!(cpuid_page & shared_page));
                    assert!(!(secrets_page & shared_page));

                    let payload = if cpuid_page {
                        let cpuid_page = create_cpuid_page();
                        LoadCommandPayload::Cpuid(cpuid_page)
                    } else if secrets_page {
                        LoadCommandPayload::Secrets
                    } else {
                        let mut bytes = [0; 4096];

                        let copy_start = cmp::max(start_addr, frame.start_address());
                        let copy_end_inclusive =
                            cmp::min(end_inclusive_file_addr, frame.start_address() + 4095u64);

                        let copy_start_in_frame = (copy_start.as_u64() & 0xFFF) as usize;
                        let copy_end_inclusive_in_frame =
                            (copy_end_inclusive.as_u64() & 0xFFF) as usize;

                        let offset_start =
                            usize::try_from(ph.p_offset + (copy_start - start_addr)).unwrap();
                        let offset_end_inclusive =
                            usize::try_from(ph.p_offset + (copy_end_inclusive - start_addr))
                                .unwrap();

                        bytes[copy_start_in_frame..=copy_end_inclusive_in_frame]
                            .copy_from_slice(&elf_bytes[offset_start..=offset_end_inclusive]);

                        if shared_page {
                            LoadCommandPayload::Shared(bytes)
                        } else {
                            LoadCommandPayload::Normal(bytes)
                        }
                    };
                    LoadCommand {
                        physical_address: frame,
                        vmpl1_perms,
                        payload,
                    }
                })
        })
}

fn create_cpuid_page() -> CpuidPage {
    fn query_function(eax: u32, xcr0: u64) -> CpuidFunction {
        let result = cpuid!(eax);
        CpuidFunction::new(
            eax, 0, xcr0, 0, result.eax, result.ebx, result.ecx, result.edx,
        )
    }
    let functions = [
        query_function(1, 7),
        query_function(0x8000_0001, 7),
        query_function(0x8000_0008, 7),
        query_function(0x8000_001f, 1),
    ];

    let mut initialized = 0;
    let mut fns = [CpuidFunction::zeroed(); snp_types::cpuid::COUNT_MAX];
    fns.iter_mut().zip(functions).for_each(|(dest, src)| {
        *dest = src;
        initialized += 1;
    });

    CpuidPage::new(&fns[..initialized])
}
