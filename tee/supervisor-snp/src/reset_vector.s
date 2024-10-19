# Shadow stack
.section .shadow_stack, "a"
.align 4096
.set SHADOW_STACK_SIZE, 4096
shadow_stack:
.fill SHADOW_STACK_SIZE - 8, 1, 0
.quad shadow_stack + SHADOW_STACK_SIZE + 1

.section .reset_vector, "ax"
.code16
entry16bit:

# 1. Load a GDT.
.byte 0x66
lgdt dword ptr cs:(gdt_pointer-0xFFFF0000)

# 2. Enter Protected Mode.
# 2.1 Set the PE flag in CR0.
mov eax, cr0
or eax, 1 << 0
mov cr0, eax

# 2.2 Serialize the processor by doing a long jump.
# LJMP 0x20, (entry32bit-0xFFFFF000)
# FIXME: Can we do this without directives?
.byte 0xea
.short (entry_32bit_segmented-0xFFFF0000)
.short 0x20

.code32
entry_32bit_segmented:

# 2.3 Long jump to a code segment without a base.
# LJMP 0x18:entry_32bit_flat
# FIXME: Can we do this without directives?
.byte 0xea
.long entry_32bit_flat
.short 0x18
entry_32bit_flat:
# 2.4 Setup data segment register
mov ax, 0x10
mov ds, ax

# 3. Set C bit in page tables.
# 3.1 Find the C bit location in the cpuid page.
mov eax, dword ptr [CPUID_PAGE]
lea ecx, dword ptr [CPUID_PAGE + 16]
check_next_entry:
test eax, eax
je fail_32bit
# Compare all the input parameters.
cmp dword ptr [ecx], 0x8000001F # eax_in
jne wrong_entry
cmp dword ptr [ecx+4], 0 # ecx_in
jne wrong_entry
cmp dword ptr [ecx+8], 1 # xcr0_in (lower half)
jne wrong_entry
cmp dword ptr [ecx+12], 0 # xcr0_in (upper half)
jne wrong_entry
cmp dword ptr [ecx+16], 0 # xss_in (lower half)
jne wrong_entry
cmp dword ptr [ecx+20], 0 # xss_in (upper half)
jne wrong_entry
cmp dword ptr [ecx+40], 0 # Reserved. Must be zero.
je found_entry
wrong_entry:
dec eax
add ecx, 0x30
jmp check_next_entry
found_entry:
mov cl, byte ptr [ecx+28]
and cl, 0x3f
# Check the we can support the C-bit position.
cmp cl, 32
jl fail_32bit
# 3.2 Fix the C-bit in the page tables.
# By default, we set bit 51 in the page tables. This is the C-bit for Zen 3
# based CPUs. To support other generations, we test for bit 51 and replace it
# with the appropriate bit.
# Prepare a mask to XOR into the upper half of the page table entries, to unset
# bit 51 and set the C-bit instead (this will do nothing if the C-bit is at
# position 51).
sub ecx, 32
mov ebx, 1
shl ebx, cl
xor ebx, 0x00080000
# Loop start
lea eax, dword ptr [__pagetables_start]
lea edx, dword ptr [__pagetables_end]
# Loop condition
fix_next_entry:
cmp eax, edx
je done_fixing_entries
# Loop body
# Is bit 51 set?
test byte ptr [eax + 6], 0x08
je done_fixing_entry
# If so, clear bit 51 and set the C-bit instead.
xor dword ptr [eax + 4], ebx
done_fixing_entry:
add eax, 8
jmp fix_next_entry
done_fixing_entries:

# 4. Enter Compatibility Mode.
# 4.1 Set the PAE flag in CR4.
mov eax, cr4
or eax, 1 << 5
mov cr4, eax

# 4.2 Set the LME flag in the EFER MSR.
# We also set the NXE bit.
mov ecx, 0xc0000080
rdmsr
or eax, (1 << 8) | (1 << 11)
wrmsr

# 4.3 Load the pml4 into CR3.
lea eax, [pml4]
mov cr3, eax

# 4.4 Set the PG flag in CR0.
mov eax, cr0
or eax, (1 << 31)
mov cr0, eax

# 5. Enter 64-bit Mode.
# 5.1 Long jump to a 64-bit segment.
# FIXME: Can we do this without directives?
.byte 0xea
.int entry64bit
.short 0x8

fail_32bit:
int3
jmp fail_32bit

.code64
entry64bit:

# 6. Fill the SS, DS and CS registers.
mov eax, 0x10
mov ss, ax
mov ds, ax
mov es, ax

# 7. Enable CPU Extensions
# 7.1 Enable SSE
mov rax, cr0
or rax, 1 << 1
mov cr0, rax
mov rax, cr4
or rax, (1 << 9) | (1 << 10) | (1 << 18)
mov cr4, rax
# 7.2 Enable AVX
xor rcx, rcx
xgetbv
or rax, 7
xsetbv
# 7.3 Enable Write Protection
mov rax, cr0
or rax, 1 << 16
mov cr0, rax

# 8. Enable Shadow Stacks
# 8.1 Enable CR4.CET
mov rax, cr4
or rax, 1 << 23
mov cr4, rax
# 8.2 Enable Shadow Stacks in in SCET MSR
mov ecx, 0x6a2
xor edx, edx
mov eax, 1
wrmsr
# 8.3 Load SSP
mov rax, [rip+shadow_stack_token_addr]
rstorssp [rax]

# 9. Enter the Kernel
mov rax, qword ptr [rip+start_addr]
jmp rax

# Addresses
shadow_stack_token_addr:
.quad shadow_stack + SHADOW_STACK_SIZE - 8
start_addr:
.quad _start

.align 32, 0xcc
# Global Descriptor Table Pointer
gdt_pointer:
.short (gdt_end-gdt_start-1)
.long gdt_start

.align 32, 0xcc
# Global Descriptor Table
gdt_start:
.quad 0 # Null descriptor
.quad 0x00af9b000000ffff # 64-bit Code descriptor
.quad 0x00cf93000000ffff # Data descriptor
.quad 0x00cf9b000000ffff # 32-bit Code descriptor
.quad 0xffcf9bff0000ffff # 32-bit Code descriptor with base=0xffff_0000
gdt_end:

# Reset vector
.section .reset_vector_table, "ax"
.code16
reset_vector:
jmp entry16bit
