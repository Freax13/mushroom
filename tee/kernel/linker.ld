ENTRY(reset_vector)

PHDRS
{
    headers             PT_LOAD FILEHDR PHDRS AT(0x08000000000) FLAGS(0);
    pagetables          PT_LOAD AT(0x10000000000) FLAGS((1 << 1) | (1 << 2) | (1 << 25));
    ropagetables        PT_LOAD AT(0x10000010000) FLAGS((1 << 2) | (1 << 26));
    reset_vector        PT_LOAD AT(0x10040000000);
    text                PT_LOAD AT(0x10040200000);
    rodata              PT_LOAD AT(0x10080000000);
    data                PT_LOAD AT(0x100c0000000);
    stack               PT_LOAD AT(0x10140000000);
    init_file           PT_LOAD AT(0x30000000000) FLAGS((1 << 2) | (1 << 31));
    input_file          PT_LOAD AT(0x40000000000) FLAGS((1 << 2) | (1 << 31));
    profiler_control    PT_LOAD AT(0x80000000000) FLAGS((1 << 30));
    profiler_buffer     PT_LOAD AT(0x80040000000) FLAGS((1 << 30));
    log_buffer          PT_LOAD AT(0x90000000000) FLAGS((1 << 1) | (1 << 30));
}

SECTIONS {
    .pagetables (0x10000000000) : 
    {
        . = 0x10000000000;
        KEEP(*(.pagetables.pml4 .pagetables.pml4.*))
        . = 0x10000001000;
        KEEP(*(.pagetables.tdx.pml4 .pagetables.tdx.pml4.*))
        KEEP(*(.pagetables .pagetables.*))
    } :pagetables

    .ropagetables (0x10000010000) : 
    {
        . = 0x10000010000;
        KEEP(*(.ropagetables.tdx.pml4 .ropagetables.tdx.pml4.*))
        KEEP(*(.ropagetables .ropagetables.*))
    } :ropagetables

    .reset_vector (0xffff800000000000) : 
    {
        KEEP(*(.reset_vector .reset_vector.*))
    } :reset_vector
    
    .text (0xffff800000200000) :
    {
        *(.text .text.*)
        *(.ltext .ltext.*)
    } :text

    .rodata (0xffff800001000000) :
    {
        *(.rodata .rodata.*)
        *(.lrodata .lrodata.*)
        *(.eh_frame .eh_frame.*)
        *(.eh_frame_hdr .eh_frame_hdr.*)
        __recoverable_start = .;
        *(.recoverable .recoverable.*)
        __recoverable_end = .;

        __start_linkme_REGISTRATIONS = .;
        KEEP(*(linkme_REGISTRATIONS linkme_REGISTRATIONS.*))
        __stop_linkme_REGISTRATIONS = .;
        __start_linkm2_REGISTRATIONS = .;
        KEEP(*(linkm2_REGISTRATIONS linkm2_REGISTRATIONS.*))
        __stop_linkm2_REGISTRATIONS = .;
    } :rodata

    .data (0xffff800002000000) :
    {
        *(.data .data.*)
        *(.ldata .ldata.*)
        *(.got .got.*)
        *(.bss .bss.*)
        *(.lbss .lbss.*)
    } :data

    .stack (0xffff800004000000) :
    {
        KEEP(*(.stack .stack.*))
    } :stack

    .profiler_control (0xffff800005000000) :
    {
        KEEP(*(.profiler_control .profiler_control.*))
    } :profiler_control

    .profiler_buffer (0xffff800040000000) :
    {
        KEEP(*(.profiler_buffer .profiler_buffer.*))
    } :profiler_buffer

    .supervisor_services (0xffff800006000000) :
    {
        KEEP(*(.supervisor_services .supervisor_services.*))
    } :supervisor_services

    .log_buffer (0xffff800007000000) :
    {
        KEEP(*(.log_buffer .log_buffer.*))
    } :log_buffer

    .init_file (0xffff80a000000000) :
    {
        init_file = .;
        . += 8;
    } :init_file

    .input_file (0xffff80b000000000) :
    {
        input_file = .;
        . += 8;
    } :input_file
}
