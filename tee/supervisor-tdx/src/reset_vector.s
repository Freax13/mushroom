# Stack
.section .stack, "a"
.align 4096
.set SHADOW_STACK_SIZE, 4096
stack:
.set i, 0
.rept {MAX_APS_COUNT}
    .fill SHADOW_STACK_SIZE - 8, 1, 0
    .quad stack + {STACK_SIZE} * i + SHADOW_STACK_SIZE + 1
    .fill {STACK_SIZE} - SHADOW_STACK_SIZE, 1, 0
    .set i, i+1
.endr

.section .reset_vector, "ax"
.code32
entry32bit:

# 1. Sanitize & check initial registers.
# 1.1 Clean RCX. This registers is controlled by the hypervisor
xor ecx, ecx
# 1.2 Clean RDX
xor edx, edx
# 1.3 Check the GPAW
cmp ebx, 52
jne fail_32bit

# 2. Enter Compatibility Mode.
# 2.1 Set the PAE flag in CR4.
mov eax, cr4
or eax, 1 << 5
mov cr4, eax
# 2.2 Load the pml4 into CR3.
lea eax, [pml4]
mov cr3, eax
# 2.3 Set the PG flag in CR0.
mov eax, cr0
or eax, (1 << 31)
mov cr0, eax

# 3. Enter 64-bit Mode.
# 3.1 Load a GDT
lgdt dword ptr cs:(gdt_pointer)
# 3.2 Long jump to a 64-bit segment.
# FIXME: Can we do this without directives?
.byte 0xea
.int entry64bit
.short 0x8

fail_32bit:
int3
jmp fail_32bit

.code64
entry64bit:
# 3.3 Clean R8. This registers is controlled by the hypervisor
xor r8, r8

# 4. Fill the SS, DS and CS registers.
mov eax, 0x10
mov ss, ax
mov ds, ax
mov es, ax

# 5. Enable CPU Extensions
# 5.1 Enable SSE
mov rax, cr0
or rax, 1 << 1
mov cr0, rax
mov rax, cr4
or rax, (1 << 9) | (1 << 10) | (1 << 18)
mov cr4, rax
# 5.2 Enable AVX
xor rcx, rcx
xgetbv
or rax, 7
xsetbv
# 5.3 Enable Write Protection
mov rax, cr0
or rax, 1 << 16
mov cr0, rax

# 6. Determine CPU-local addresses
# 6.1 Calculate stack base address
mov r8, qword ptr [rip+stack_addr]
mov rbx, rsi # RSI contains the vCPU index as part of the initial guest state
imul rbx, {STACK_SIZE}
add r8, rbx
# 6.2 Calculate stack address
mov rsp, r8
add rsp, {STACK_SIZE}
# 6.3 Calculate shadow stack address
add r8, SHADOW_STACK_SIZE - 8

# 7. Enable Shadow Stacks
# 7.1 Enable CR4.CET
mov rax, cr4
or rax, 1 << 23
mov cr4, rax
# 7.2 Enable SH_STK_EN, ENBR_EN, and NO_TRACK_EN in in SCET MSR
mov ecx, 0x6a2
xor edx, edx
mov eax, (1 << 0) | (1 << 2) | (1 << 4)
wrmsr
# 7.3 Load SSP
rstorssp [r8]

# 8. Enter the Kernel
# 8.1 Copy RSI (vCPU index) to RDI (first argument)
mov rdi, rsi
# 8.2 Jump to _start
jmp qword ptr [rip+start_addr]

# Addresses
stack_addr:
.quad stack
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
.quad 0x00af9a000000ffff # 64-bit Code descriptor
.quad 0x00cf92000000ffff # Data descriptor
gdt_end:

# Reset vector
.section .reset_vector_table, "ax"
.code32
reset_vector:
jmp entry32bit
