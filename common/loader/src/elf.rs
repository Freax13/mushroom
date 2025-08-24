use std::{
    cmp,
    iter::{from_fn, once},
};

use bit_field::BitField;
use bytemuck::Zeroable;
use goblin::{elf::Elf, elf64::program_header::PT_LOAD};
use raw_cpuid::cpuid;
use snp_types::{
    VmplPermissions,
    cpuid::{CpuidFunction, CpuidPage},
};
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{Page, PhysFrame},
};

use crate::{LoadCommand, LoadCommandPayload};

pub fn load(
    elf_bytes: &[u8],
    vmpl1_perms_mask: VmplPermissions,
) -> impl Iterator<Item = LoadCommand> + '_ {
    let elf = Elf::parse(elf_bytes).unwrap();
    assert!(elf.is_64);

    elf.program_headers
        .into_iter()
        .filter(|ph| matches!(ph.p_type, PT_LOAD))
        .filter(|ph| {
            let no_load_page = ph.p_flags.get_bit(31);
            !no_load_page
        })
        .flat_map(move |ph| {
            let execute = ph.p_flags.get_bit(0);
            let write = ph.p_flags.get_bit(1);
            let read = ph.p_flags.get_bit(2);
            let paging_write_access = ph.p_flags.get_bit(26);
            let vmsa_page = ph.p_flags.get_bit(27);
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
            // AMD CPUs don't support PWA, so we also need to set the WRITE
            // bit for these pages.
            if paging_write_access {
                vmpl1_perms |= VmplPermissions::WRITE;
            }
            if read {
                vmpl1_perms |= VmplPermissions::READ;
            }
            let vmpl1_perms = vmpl1_perms & vmpl1_perms_mask;

            let start_addr = PhysAddr::new(ph.p_paddr);
            let start_frame = PhysFrame::containing_address(start_addr);
            let end_inclusive_file_addr = start_addr + (ph.p_filesz - 1);
            let end_inclusive_file_file = PhysFrame::containing_address(end_inclusive_file_addr);
            let end_inclusive_addr = start_addr + (ph.p_memsz - 1);
            let end_inclusive_frame = PhysFrame::containing_address(end_inclusive_addr);

            PhysFrame::range_inclusive(start_frame, end_inclusive_frame)
                .into_iter()
                .enumerate()
                .map(move |(i, frame)| {
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

                        if frame <= end_inclusive_file_file {
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
                        }

                        if vmsa_page {
                            LoadCommandPayload::Vmsa(bytes)
                        } else if shared_page {
                            LoadCommandPayload::Shared(bytes)
                        } else {
                            LoadCommandPayload::Normal(bytes)
                        }
                    };

                    let vcpu_id = if vmsa_page { i as u32 } else { 0 };

                    LoadCommand {
                        physical_address: frame,
                        vcpu_id,
                        vmpl1_perms,
                        payload,
                    }
                })
        })
}

pub fn load_shadow_mapping(
    elf_bytes: &[u8],
    vmpl1_perms_mask: VmplPermissions,
) -> impl Iterator<Item = LoadCommand> + '_ {
    let elf = Elf::parse(elf_bytes).unwrap();
    assert!(elf.is_64);

    fn shadow_mapping_addr(page: Page) -> PhysAddr {
        const KASAN_SHADOW_SCALE_SHIFT: u64 = 3;
        /// Note that this is the physical address.
        const KASAN_SHADOW_OFFSET: u64 = 0x180_0000_0000;

        let start_address = page.start_address();
        let offset = start_address.as_u64() - 0xffff_8000_0000_0000;
        let scaled = offset >> KASAN_SHADOW_SCALE_SHIFT;
        let addr = scaled + KASAN_SHADOW_OFFSET;
        PhysAddr::new(addr)
    }

    elf.program_headers
        .into_iter()
        .filter(|ph| matches!(ph.p_type, PT_LOAD))
        .filter(|ph| ph.p_vaddr > 0x8000_0000_0000_0000)
        .flat_map(move |ph| {
            let start_addr = VirtAddr::new(ph.p_vaddr);
            let end_inclusive_addr = start_addr + ph.p_memsz;
            let start_page = Page::containing_address(start_addr);
            let end_inclusive_page = Page::containing_address(end_inclusive_addr);

            let mut vmpl1_perms = VmplPermissions::empty();
            vmpl1_perms.set(
                VmplPermissions::READ,
                ph.is_read() || ph.is_executable() || ph.is_write(),
            );
            vmpl1_perms.set(VmplPermissions::WRITE, ph.is_write());
            vmpl1_perms &= vmpl1_perms_mask;

            let mut iter = Page::range_inclusive(start_page, end_inclusive_page).peekable();
            from_fn(move || {
                let page = iter.next()?;

                let mapping_addr = shadow_mapping_addr(page);
                let mapping_frame = PhysFrame::containing_address(mapping_addr);

                let following_pages = from_fn(|| {
                    iter.next_if(|&page| {
                        let mapping_addr = shadow_mapping_addr(page);
                        mapping_frame == PhysFrame::containing_address(mapping_addr)
                    })
                });

                // Start with all markers indicated invalid memory.
                const ASAN_GLOBAL_REDZONE_MAGIC: u8 = 0xf9;
                let mut payload = [ASAN_GLOBAL_REDZONE_MAGIC; 0x1000];

                // Allow access to individual pages.
                for page in once(page).chain(following_pages) {
                    let addr = shadow_mapping_addr(page);
                    let offset = (addr.as_u64() & 0xfff) as usize;
                    payload[offset..][..512].fill(0);
                }

                Some(LoadCommand {
                    physical_address: mapping_frame,
                    vcpu_id: 0,
                    vmpl1_perms,
                    payload: LoadCommandPayload::Normal(payload),
                })
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
