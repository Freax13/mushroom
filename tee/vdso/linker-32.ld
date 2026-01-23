ENTRY(__kernel_vsyscall)

PHDRS
{
    vdso         PT_LOAD FILEHDR PHDRS  FLAGS(1 << 0 | 1 << 2);
    dynamic      PT_DYNAMIC FLAGS(1 << 2);
    eh_frame_hdr PT_GNU_EH_FRAME;
}

SECTIONS {
    . = SIZEOF_HEADERS;

    .hash :
    {
        *(.hash .hash.*)
    } :vdso

    .gnu.hash :
    {
        *(.gnu.hash .gnu.hash.*)
    } :vdso

    .dynsym :
    {
        *(.dynsym .dynsym.*)
    } :vdso

    .dynstr :
    {
        *(.dynstr .dynstr.*)
    } :vdso

    .dynamic :
    {
        *(.dynamic .dynamic.*)
    } :vdso :dynamic

    .rodata :
    {
        *(.rodata .rodata.*)
    } :vdso

	.eh_frame_hdr :
    {
        KEEP(*(.eh_frame_hdr .eh_frame_hdr.*))
    } :vdso :eh_frame_hdr		
	
    .eh_frame : {
        KEEP (*(.eh_frame .eh_frame.*))
    } :vdso

    .text :
    {
        *(.text .text.*)
    } :vdso

    .data :
    {
        *(.data .data.*)
        *(.bss .bss.*)
    } :vdso
    ASSERT(SIZEOF(.data) == 0, "The .data section should be empty")

    .comment :
    {
        *(.comment .comment.*)
    }

    .shstrtab :
    {
        *(.shstrtab .shstrtab.*)
    }

    /DISCARD/ :
    {
        *(.got .got.*)
        *(.symtab .symtab.*)
        *(.strtab .strtab.*)
        *(.debug_frame .debug_frame.*)
        *(.debug_line .debug_line.*)
        *(.debug_abbrev .debug_abbrev.*)
        *(.debug_info .debug_info.*)
        *(.debug_aranges .debug_aranges.*)
        *(.debug_ranges .debug_ranges.*)
        *(.debug_str .debug_str.*)
    }
}

VERSION
{
	LINUX_2.5 {
	global:
		__kernel_vsyscall;
	local: *;
	};
}
