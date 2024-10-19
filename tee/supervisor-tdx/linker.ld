ENTRY(reset_vector)

PHDRS
{
    text                PT_LOAD AT(0x40000000);
    rodata              PT_LOAD AT(0x41000000);
    data                PT_LOAD AT(0x42000000);
    stack               PT_LOAD AT(0x43200000);
    shared              PT_LOAD AT(0x44000000) FLAGS((1 << 30));
    kernel_elf_header   PT_LOAD AT(0x08000000000);
    log_buffer          PT_LOAD AT(0x90000200000) FLAGS((1 << 30));
    pagetables          PT_LOAD FLAGS((1 << 2));
    reset_vector        PT_LOAD;
    supervisor_services PT_LOAD FLAGS(1 << 31);
}

SECTIONS {
    .text (0x40000000) :
    {
        KEEP(*(.text .text.*))
    } :text

    .rodata (0x41000000) :
    {
        *(.rodata .rodata.*)
        *(.eh_frame .eh_frame.*)
        *(.eh_frame_hdr .eh_frame_hdr.*)
    } :rodata

    .data (0x42000000) :
    {
        *(.data .data.*)
        *(.got .got.*)
        *(.bss .bss.*)
    } :data

    .stack (0x43200000) :
    {
        *(.stack .stack.*)
    } :stack

    .shared (0x44000000) :
    {
        *(.shared .shared.*)
    } :shared

    .supervisor_services (0x44400000) :
    {
        supervisor_services_shared = .;
    } :supervisor_services

    .log_buffer (0x44800000) :
    {
        *(.log_buffer .log_buffer.*)
    } :log_buffer

    .kernel_elf_header (0x45000000) : {
        // This only exists to satisfy the linker. The actual content comes from the kernel.
        kernel_elf_header = .;
    }

    .pagetables (0xffc00000) : 
    {
        __pagetables_start = .;
        KEEP(*(.pagetables .pagetables.*))
        __pagetables_end = .;
    } :pagetables

    .reset_vector (0xfffff000) : 
    {
        KEEP(*(.reset_vector .reset_vector.*))
        . = 0xfffffff0;
        KEEP(*(.reset_vector_table))
    } :reset_vector
}
