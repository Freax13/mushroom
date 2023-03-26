ENTRY(reset_vector)

PHDRS
{
    cpuid_page   PT_LOAD FLAGS((1 << 2) | (1 << 28));
    pagetables   PT_LOAD;
    reset_vector PT_LOAD;
    text         PT_LOAD AT(0x00100000000);
    rodata       PT_LOAD AT(0x00140000000);
    data         PT_LOAD AT(0x00180000000);
    stack        PT_LOAD AT(0x001c0000000);
    secrets      PT_LOAD AT(0x00200000000) FLAGS((1 << 1) | (1 << 2) | (1 << 29));
    shared       PT_LOAD AT(0x00240000000) FLAGS((1 << 2) | (1 << 30));
}

SECTIONS {
    .cpuid_page (0xffa00000) : 
    {
        KEEP(*(.cpuid_page .cpuid_page.*))
    } :cpuid_page

    .pagetables (0xffc00000) : 
    {
        KEEP(*(.pagetables .pagetables.*))
    } :pagetables

    .reset_vector (0xfffff000) : 
    {
        KEEP(*(.reset_vector .reset_vector.*))
        . = 0xfffffff0;
        KEEP(*(.reset_vector_table))
    } :reset_vector
    
    .text (0xffff800000000000) :
    {
        KEEP(*(.text .text.*))
    } :text

    .rodata (0xffff800001000000) :
    {
        *(.rodata .rodata.*)
        *(.eh_frame .eh_frame.*)
        *(.eh_frame_hdr .eh_frame_hdr.*)
    } :rodata

    .data (0xffff800002000000) :
    {
        *(.data .data.*)
        *(.got .got.*)
        *(.bss .bss.*)
    } :data

    .stack (0xffff800003200000) :
    {
        *(.stack .stack.*)
    } :stack

    .secrets (0xffff800003600000) :
    {
        *(.secrets .secrets.*)
    } :secrets

    .shared (0xffff800004000000) :
    {
        *(.shared .shared.*)
    } :shared
}
