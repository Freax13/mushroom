ENTRY(reset_vector)

PHDRS
{
    pagetables   PT_LOAD AT(0x10000000000);
    reset_vector PT_LOAD AT(0x10040000000);
    text         PT_LOAD AT(0x10040200000);
    rodata       PT_LOAD AT(0x10080000000);
    data         PT_LOAD AT(0x100c0000000);
    tdata        PT_TLS  AT(0x10100000000);
    stack        PT_LOAD AT(0x10140000000);
}

SECTIONS {
    .pagetables (0x10000000000) : 
    {
        KEEP(*(.pagetables .pagetables.*))
    } :pagetables

    .reset_vector (0xffff800000000000) : 
    {
        KEEP(*(.reset_vector .reset_vector.*))
    } :reset_vector
    
    .text (0xffff800000200000) :
    {
        KEEP(*(.text .text.*))
    } :text

    .rodata (0xffff800001000000) :
    {
        *(.rodata .rodata.*)
        *(.eh_frame .eh_frame.*)
        *(.eh_frame_hdr .eh_frame_hdr.*)
        __recoverable_start = .;
        *(.recoverable .recoverable.*)
        __recoverable_end = .;
    } :rodata

    .data (0xffff800002000000) :
    {
        *(.data .data.*)
        *(.ldata .ldata.*)
        *(.got .got.*)
        *(.bss .bss.*)
    } :data

    .tdata (0xffff800003000000) :
    {
        _tdata_start = .;
        *(.tdata .tdata.*)
        *(.tbss .tbss.*)
        _tdata_end = .;
    } :tdata

    .stack (0xffff800004000000) :
    {
        KEEP(*(.stack .stack.*))
    } :stack
}
