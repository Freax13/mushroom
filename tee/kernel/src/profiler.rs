use core::arch::{asm, global_asm};
use core::mem::{offset_of, size_of};

use constants::{AtomicApBitmap, MAX_APS_COUNT};
use profiler_types::{
    AllEntries, CALL_STACK_CAPACITY, Entry, PROFILER_ENTRIES, PerCpuEntries, PerCpuHeader,
    ProfilerControl,
};
use x86_64::registers::model_specific::Msr;

/// Flush profiler data.
pub fn flush() {
    // Call the `flush` function declared in the `global_asm` block below.
    unsafe extern "C" {
        fn flush() -> u32;
    }
    unsafe {
        flush();
    }
}

#[unsafe(link_section = ".profiler_control")]
static mut PROFILER_CONTROL: ProfilerControl = ProfilerControl {
    notify_flags: AtomicApBitmap::empty(),
    headers: [PerCpuHeader {
        start_idx: 0,
        len: 0,
        lost: false,
    }; MAX_APS_COUNT as usize],
    tsc_mhz: 0,
};

/// Initialize the control area.
///
/// # Safety
///
/// This function must only be called once.
pub unsafe fn init() {
    // Use the `GUEST_TSC_FREQ` MSR to read the effective TSC frequency.
    const GUEST_TSC_FREQ: u32 = 0xC001_0134;
    let guest_tsc_freq = Msr::new(GUEST_TSC_FREQ);
    let guest_tsc_freq = unsafe { guest_tsc_freq.read() };

    // Write guest_tsc_freq into PROFILER_CONTROL.tsc_mhz.
    // FIXME: This is a hack to prevent the compiler from creating a relocation
    // to `PROFILER_CONTROL`. Otherwise the compiler will try to use a 32-bit
    // relocation even though `PROFILER_CONTROL` cannot be referenced using a
    // 32-bit address.
    unsafe {
        asm!(
            "mov [rip + {PROFILER_CONTROL} + {tsc_mhz_offset}], {guest_tsc_freq}",
            guest_tsc_freq = in(reg) guest_tsc_freq,
            PROFILER_CONTROL = sym PROFILER_CONTROL,
            tsc_mhz_offset = const offset_of!(ProfilerControl, tsc_mhz),
        );
    }
}

#[unsafe(link_section = ".profiler_buffer")]
static mut PROFILER_BUFFERS: AllEntries = [PerCpuEntries {
    entries: [Entry { time: 0, event: 0 }; PROFILER_ENTRIES],
}; MAX_APS_COUNT as usize];

#[derive(Clone, Copy)]
#[repr(C, align(128))]
struct LocalHeader {
    header: PerCpuHeader,
    call_stack_len: usize,
    call_stack: [u64; CALL_STACK_CAPACITY],
    return_address_stack: [u64; CALL_STACK_CAPACITY],
}

static mut LOCAL_HEADERS: [LocalHeader; MAX_APS_COUNT as usize] = [LocalHeader {
    header: PerCpuHeader {
        start_idx: 0,
        len: 0,
        lost: false,
    },
    call_stack_len: 0,
    call_stack: [0; CALL_STACK_CAPACITY],
    return_address_stack: [0; CALL_STACK_CAPACITY],
}; MAX_APS_COUNT as usize];

global_asm!(
    ".section .text, \"ax\"",

    // ------------------------------------------------------------------------
    // start of mcount
    ".global mcount",
    "mcount:",

    // Add the return address to the call stack.
    "call get_local_header",
    // Get the current depth.
    "mov rsi, [rax + {LOCAL_HEADER_CALL_STACK_LEN}]",
    // Make sure the depth is not already at capacity.
    "cmp rsi, {CALL_STACK_CAPACITY}",
    "je 67f",
    // Get the call address.
    "mov rdi, [rsp]",
    // Offset into the call stack.
    "lea r8, [rax + {LOCAL_HEADER_CALL_STACK} + rsi * 8]",
    // Copy the return address into the call stack.
    "mov [r8], rdi",
    // Get the return address.
    "mov rdi, [rbp + 8]",
    // Offset into the return address stack.
    "lea r8, [rax + {LOCAL_HEADER_RETURN_ADDRESS_STACK} + rsi * 8]",
    // Copy the return address into the return address stack.
    "mov [r8], rdi",
    // Increase the depth.
    "inc rsi",
    // Keep the depth around for later.
    "mov r10, rsi",
    // Write the depth back.
    "mov [rax + {LOCAL_HEADER_CALL_STACK_LEN}], rsi",

    // Replace the return address with the trampoline.
    "lea rax, [rip+trampoline]",
    "mov [rbp + 8], rax",

    // Put the timestamp into the first 8 bytes of the entry (rdi).
    "rdtsc",
    "shl rdx, 32",
    "mov rdi, rax",
    "or rdi, rdx",

    // Prepare the second 8 bytes (rsi).
    // Get the real return address.
    "mov rsi, [rsp]",
    // Mask to 47 bits.
    "shl rsi, 17",
    "shr rsi, 1",
    // type=Entry (0), more=0, magic=0b101
    "or rsi, 0x28",
    // Depth
    "shl r10, 6",
    "or rsi, r10",

    // Tail call add_entry.
    "jmp add_entry",

    "66:",
    "ret",

    "67:",
    // Record that data went missing.
    "mov byte ptr [rax + {PER_CPU_HEADER_LOST}], 1",
    "jmp 66b",

    // end of mcount
    // ------------------------------------------------------------------------
    // start of trampoline

    // This function is put at the return address in the stack to record exits.
    "trampoline:",

    // Preserve registers.
    "push rax",
    "push rdx",
    "push rbx",

    // Add the return address to the call stack.
    "call get_local_header",
    // Get the current depth.
    "mov rsi, [rax + {LOCAL_HEADER_CALL_STACK_LEN}]",
    // Keep the depth around for later.
    "mov r10, rsi",
    // Decrease the depth.
    "dec rsi",
    // Write the depth back.
    "mov [rax + {LOCAL_HEADER_CALL_STACK_LEN}], rsi",
    // Offset into the call stack.
    "lea r8, [rax + {LOCAL_HEADER_RETURN_ADDRESS_STACK} + rsi * 8]",
    // Get the return address.
    "mov rbx, [r8]",
    // Offset into the call stack.
    "lea r8, [rax + {LOCAL_HEADER_CALL_STACK} + rsi * 8]",
    // Get the call address.
    "mov rsi, [r8]",

    // Put the timestamp into the first 8 bytes of the entry (rdi).
    "rdtsc",
    "shl rdx, 32",
    "mov rdi, rax",
    "or rdi, rdx",

    // Prepare the second 8 bytes (rsi).
    // Mask to 47 bits.
    "shl rsi, 17",
    "shr rsi, 1",
    // type=Exit (1), more=0, magic=0b101
    "or rsi, 0x29",
    // Depth
    "shl r10, 6",
    "or rsi, r10",

    // Call add_entry.
    "call add_entry",

    // Move the real return address to a scratch register.
    "mov rdi, rbx",

    // Restore registers.
    "pop rbx",
    "pop rdx",
    "pop rax",

    // Jump to the real return address.
    "jmp rdi",

    // end of trampoline
    // ------------------------------------------------------------------------
    // start of get_local_header

    // This function returns a pointer to the local header.

    "get_local_header:",
    // Get a pointer to the local headers array.
    "lea rax, [rip + {LOCAL_HEADERS}]",
    // Calculate the offset into the array.
    "rdpid rdi",
    "imul rdi, {LOCAL_HEADER_ENTRY_SIZE}",
    // Offset into the array.
    "lea rax, [rax + rdi]",
    "ret",

    // end of get_local_header
    // ------------------------------------------------------------------------
    // start of add_entry

    // This function tries to add an entry.
    // inputs:
    // - rdi:rsi: entry

    "add_entry:",
    // Preserve registers.
    "push rbx",
    "push r12",
    "push r13",
    // Preserve inputs.
    "mov r12, rdi",
    "mov r13, rsi",

    // Check if we can fit another entry in the chunk. Flush if not.
    "call get_local_header",
    "mov rbx, rax",
    "mov rdx, [rbx+{PER_CPU_HEADER_LEN}]",
    "cmp rdx, {PROFILER_ENTRIES_HALF}",
    "je 66f",

    "64:",
    // Get a pointer to the buffers array.
    "lea r9, [rip + {PROFILER_BUFFERS}]",
    // Calculate the offset into the buffers array.
    "rdpid r10",
    "imul r10, {PER_CPU_ENTRIES_SIZE}",
    // Index into the buffers.
    "lea r9, [r9 + r10]",
    // Get the start index.
    "mov r8, [rbx + {PER_CPU_HEADER_START_IDX}]",
    // Get the index of the next entry.
    "add r8, rdx",
    // Convert the index to an offset.
    "shl r8, 4",
    // Index into the buffer.
    "lea r9, [r9 + r8]",
    // Store the entry.
    "mov [r9], r12",
    "mov [r9 + 8], r13",
    // Increase the length.
    "add rdx, 1",
    // Store the new length.
    "mov [rbx + {PER_CPU_HEADER_LEN}], rdx",

    // end
    "65:",
    "pop r13",
    "pop r12",
    "pop rbx",
    "ret",

    // Try to flush the header.
    "66:",
    "mov rdi, r14",
    "call flush",
    // Reload the length.
    "mov rdx, [rbx + {PER_CPU_HEADER_LEN}]",
    "jmp 64b",

    // end of add_entry
    // ------------------------------------------------------------------------
    // start of flush

    // This function flushes the local header to the host.

    ".global flush",
    "flush:",

    // Don't flush if there are no entries in the buffer.
    "call get_local_header",
    "mov rdx, [rax + {PER_CPU_HEADER_LEN}]",
    "test rdx, rdx",
    "je 66f",

    // Calculate the index into the array.
    "rdpid rcx",
    "mov r9, rcx",
    "shr r9, 3",
    // Calculate the bit mask.
    "and cl, 7",
    "mov r10, 1",
    "shl r10, cl",
    // Get a pointer to the notify array.
    "lea r8, [rip + {PROFILER_CONTROL}]",
    "lea r8, [r8 + {PROFILER_CONTROL_NOTIFY_FLAGS}]",

    // Spin until the notify bit isn't set.
    "64:",
    // Load the flag byte.
    "mov r11, [r8 + r9]",
    // Check that the notify bit isn't already set.
    "test r11, r10",
    "je 65f", // It's not set, continue.
    // The bit is set. Pause and try again.
    "pause",
    "jmp 64b",

    "65:",
    // Get a pointer to the headers array.
    "lea r11, [rip + {PROFILER_CONTROL}]",
    "lea r11, [r11 + {PROFILER_CONTROL_HEADERS}]",
    // Calculate the offset into the array.
    "rdpid rsi",
    "imul rsi, {PER_CPU_HEADER_SIZE}",
    // Offset into the array.
    "lea r11, [r11 + rsi]",

    // Copy the local header to the header.
    "mov rdx, [rax + {PER_CPU_HEADER_LEN}]",
    "mov [r11 + {PER_CPU_HEADER_LEN}], rdx",
    "mov rdx, [rax + {PER_CPU_HEADER_START_IDX}]",
    "mov [r11 + {PER_CPU_HEADER_START_IDX}], rdx",
    "mov dl, [rax + {PER_CPU_HEADER_LOST}]",
    "mov [r11 + {PER_CPU_HEADER_LOST}], dl",

    // Set the notify bit.
    "lock or byte ptr [r8 + r9], r10b",

    // Reset the local header.

    // Increase the start index by half the capacity.
    "mov rsi, [rax + {PER_CPU_HEADER_START_IDX}]",
    "add rsi, {PROFILER_ENTRIES_HALF}",
    // Wrap start index around.
    "and rsi, {PROFILER_ENTRIES_M1}",
    // Write start index back.
    "mov [rax + {PER_CPU_HEADER_START_IDX}], rsi",
    // Reset the length.
    "mov qword ptr [rax + {PER_CPU_HEADER_LEN}], 0",
    // Reset lost.
    "mov byte ptr [rax + {PER_CPU_HEADER_LOST}], 0",

    // end
    "66:",
    "ret",

    // end of flush
    // ------------------------------------------------------------------------

    LOCAL_HEADERS = sym LOCAL_HEADERS,
    LOCAL_HEADER_ENTRY_SIZE = const size_of::<LocalHeader>(),
    LOCAL_HEADER_CALL_STACK_LEN = const offset_of!(LocalHeader, call_stack_len),
    LOCAL_HEADER_CALL_STACK = const offset_of!(LocalHeader, call_stack),
    LOCAL_HEADER_RETURN_ADDRESS_STACK = const offset_of!(LocalHeader, return_address_stack),
    CALL_STACK_CAPACITY = const CALL_STACK_CAPACITY,
    PER_CPU_HEADER_SIZE = const size_of::<PerCpuHeader>(),
    PER_CPU_HEADER_START_IDX = const offset_of!(PerCpuHeader, start_idx),
    PER_CPU_HEADER_LEN = const offset_of!(PerCpuHeader, len),
    PER_CPU_HEADER_LOST = const offset_of!(PerCpuHeader, lost),
    PROFILER_ENTRIES_HALF = const PROFILER_ENTRIES / 2,
    PROFILER_ENTRIES_M1 = const PROFILER_ENTRIES - 1,
    PROFILER_CONTROL = sym PROFILER_CONTROL,
    PROFILER_CONTROL_HEADERS = const offset_of!(ProfilerControl, headers),
    PROFILER_CONTROL_NOTIFY_FLAGS = const offset_of!(ProfilerControl, notify_flags),
    PROFILER_BUFFERS = sym PROFILER_BUFFERS,
    PER_CPU_ENTRIES_SIZE = const size_of::<PerCpuEntries>(),
);
