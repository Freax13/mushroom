use core::cell::{LazyCell, SyncUnsafeCell};

use snp_types::cpuid::CpuidPage;

use bit_field::BitField;
use log::{trace, warn};

use crate::FakeSync;

pub fn c_bit_location() -> usize {
    static C_BIT: FakeSync<LazyCell<usize>> = FakeSync::new(LazyCell::new(|| {
        let function = lookup_provided_cpuid_function(0x8000001F, 0, 1, 0).unwrap();
        (function.ebx & 0x3f) as usize
    }));
    **C_BIT
}

/// Look up the host-provided values for a given function. In theory the
/// SEV-SNP firmware has verified these values, but for some values there is
/// some leeway as to what's regarded as valid (e.g. the host can disable most
/// features bits), so handle these with care.
pub fn lookup_provided_cpuid_function(
    eax: u32,
    ecx: u32,
    xcr0: u64,
    xss: u64,
) -> Option<snp_types::cpuid::CpuidFunction> {
    // Rust/LLVM is a bit to eager while inlining statics:
    // The contents of this page are filled in by the SEV-SNP firmware and
    // aren't actually zero. The compiler see that we never write to this page
    // and incorrectly assumes that the page always stays all zeroes.
    // To work around this we volatilely copy the page into a separate static
    // variable which we then access like normal.
    static CPUID_PAGE: FakeSync<LazyCell<CpuidPage>> = FakeSync::new(LazyCell::new(|| {
        /// This is the actual page that is filled in by the firmware.
        #[no_mangle]
        #[link_section = ".cpuid_page"]
        static CPUID_PAGE: SyncUnsafeCell<CpuidPage> = SyncUnsafeCell::new(CpuidPage::zero());

        let mut cpuid_page = CpuidPage::zero();
        unsafe {
            core::intrinsics::volatile_copy_nonoverlapping_memory(
                &mut cpuid_page,
                CPUID_PAGE.get(),
                1,
            );
        }
        cpuid_page
    }));

    let size = usize::try_from(CPUID_PAGE.count).unwrap();
    CPUID_PAGE.functions[..size]
        .iter()
        .find(|function| function.matches(eax, ecx, xcr0, xss))
        .copied()
}

/// Simulate the CPUID instruction with the given inputs.
pub fn get_cpuid_value(eax: u32, ecx: u32, xcr0: u64, xss: u64) -> (u32, u32, u32, u32) {
    trace!("simulating cpuid eax={eax:#x} ecx={ecx} xcr0={xcr0} xss={xss}");

    // Try to find a cpuid function.
    let index = usize::try_from(eax & !0x8000_0000).unwrap();
    let is_extended = eax.get_bit(31);
    let function = if !is_extended {
        STANDARD_FUNCTIONS.get(index)
    } else {
        EXTENDED_FUNCTIONS.get(index)
    };

    // Execute the cpuid function or fall back to zeroes.
    if let Some((function_eax, function_ebx, function_ecx, function_edx)) = function {
        (
            function_eax(eax, ecx, xcr0, xss),
            function_ebx(eax, ecx, xcr0, xss),
            function_ecx(eax, ecx, xcr0, xss),
            function_edx(eax, ecx, xcr0, xss),
        )
    } else {
        warn!("cpuid function not found eax={eax:#x} ecx={ecx:#x} xcr0={xcr0:#x} xss={xss:#x}");
        (0, 0, 0, 0)
    }
}

type CpuidFunction = fn(eax: u32, ecx: u32, xcr0: u64, xss: u64) -> u32;
type CpuidFunctions = (CpuidFunction, CpuidFunction, CpuidFunction, CpuidFunction);

const STANDARD_FUNCTIONS: &[CpuidFunctions] = &[
    (
        fn_0000_0000_eax,
        fn_0000_0000_ebx,
        fn_0000_0000_ecx,
        fn_0000_0000_edx,
    ),
    (
        fn_0000_0001_eax,
        fn_0000_0001_ebx,
        fn_0000_0001_ecx,
        fn_0000_0001_edx,
    ),
];

const EXTENDED_FUNCTIONS: &[CpuidFunctions] = &[
    (
        fn_8000_0000_eax,
        fn_8000_0000_ebx,
        fn_8000_0000_ecx,
        fn_8000_0000_edx,
    ),
    (
        fn_8000_0001_eax,
        fn_8000_0001_ebx,
        fn_8000_0001_ecx,
        fn_8000_0001_edx,
    ),
    UNIMPLEMENTED,
    UNIMPLEMENTED,
    UNIMPLEMENTED,
    UNIMPLEMENTED,
    UNIMPLEMENTED,
    UNIMPLEMENTED,
    (
        fn_8000_0008_eax,
        fn_8000_0008_ebx,
        fn_8000_0008_ecx,
        fn_8000_0008_edx,
    ),
];

const UNIMPLEMENTED: CpuidFunctions = (unimplemented, unimplemented, unimplemented, unimplemented);

fn unimplemented(eax: u32, ecx: u32, _xcr0: u64, _xss: u64) -> u32 {
    todo!("unimplemented function eax={eax:08x} ecx={ecx:x}")
}

const VENDOR_EBX: u32 = 0x6874_7541;
const VENDOR_ECX: u32 = 0x444D_4163;
const VENDOR_EDX: u32 = 0x6974_6E65;

fn fn_0000_0000_eax(_eax: u32, _ecx: u32, _xcr0: u64, _xss: u64) -> u32 {
    let larged_supported_value = STANDARD_FUNCTIONS.len() - 1;
    u32::try_from(larged_supported_value).unwrap()
}

fn fn_0000_0000_ebx(_eax: u32, _ecx: u32, _xcr0: u64, _xss: u64) -> u32 {
    VENDOR_EBX
}

fn fn_0000_0000_ecx(_eax: u32, _ecx: u32, _xcr0: u64, _xss: u64) -> u32 {
    VENDOR_ECX
}

fn fn_0000_0000_edx(_eax: u32, _ecx: u32, _xcr0: u64, _xss: u64) -> u32 {
    VENDOR_EDX
}

fn fn_0000_0001_eax(_eax: u32, _ecx: u32, _xcr0: u64, _xss: u64) -> u32 {
    // Hard-coded values for an AMD EPYC Milan.
    const STEPPING: u32 = 1;
    const BASE_MODEL: u32 = 1;
    const BASE_FAMILY: u32 = 15;
    const EXTENDED_MODEL: u32 = 0;
    const EXTENDED_FAMILY: u32 = 10;

    let mut eax = 0;
    eax.set_bits(0..=3, STEPPING);
    eax.set_bits(4..=7, BASE_MODEL);
    eax.set_bits(8..=11, BASE_FAMILY);
    eax.set_bits(16..=19, EXTENDED_MODEL);
    eax.set_bits(20..=27, EXTENDED_FAMILY);
    eax
}

fn fn_0000_0001_ebx(eax: u32, _ecx: u32, xcr0: u64, xss: u64) -> u32 {
    let provided_value = lookup_provided_cpuid_function(eax, 0, xcr0, xss)
        .unwrap()
        .ebx;
    let provided_cl_flush = provided_value.get_bits(8..=15);

    let brand_id = 0;
    // FIXME: Fill in values that will work will multi tasking.
    let logical_processor_count = 1;
    let local_apic_id = 0;

    let mut ebx = 0;
    ebx.set_bits(0..=7, brand_id);
    ebx.set_bits(8..=15, provided_cl_flush);
    ebx.set_bits(16..=23, logical_processor_count);
    ebx.set_bits(24..=31, local_apic_id);
    ebx
}

fn fn_0000_0001_ecx(eax: u32, _ecx: u32, xcr0: u64, xss: u64) -> u32 {
    lookup_provided_cpuid_function(eax, 0, xcr0, xss)
        .unwrap()
        .ecx
}

fn fn_0000_0001_edx(eax: u32, _ecx: u32, xcr0: u64, xss: u64) -> u32 {
    lookup_provided_cpuid_function(eax, 0, xcr0, xss)
        .unwrap()
        .edx
}

fn fn_8000_0000_eax(_eax: u32, _ecx: u32, _xcr0: u64, _xss: u64) -> u32 {
    let larged_supported_value = 0x8000_0000 + (EXTENDED_FUNCTIONS.len() - 1);
    u32::try_from(larged_supported_value).unwrap()
}

fn fn_8000_0000_ebx(_eax: u32, _ecx: u32, _xcr0: u64, _xss: u64) -> u32 {
    VENDOR_EBX
}

fn fn_8000_0000_ecx(_eax: u32, _ecx: u32, _xcr0: u64, _xss: u64) -> u32 {
    VENDOR_ECX
}

fn fn_8000_0000_edx(_eax: u32, _ecx: u32, _xcr0: u64, _xss: u64) -> u32 {
    VENDOR_EDX
}

fn fn_8000_0001_eax(eax: u32, ecx: u32, xcr0: u64, xss: u64) -> u32 {
    fn_0000_0001_eax(eax, ecx, xcr0, xss)
}

fn fn_8000_0001_ebx(_eax: u32, _ecx: u32, _xcr0: u64, _xss: u64) -> u32 {
    // Hard-coded values for an AMD EPYC Milan.
    const BRAND_ID: u16 = 0;
    const PKG_TYPE: u8 = 4;

    let mut ebx = 0;
    ebx.set_bits(0..=15, u32::from(BRAND_ID));
    ebx.set_bits(28..=31, u32::from(PKG_TYPE));
    ebx
}

fn fn_8000_0001_ecx(eax: u32, ecx: u32, xcr0: u64, xss: u64) -> u32 {
    lookup_provided_cpuid_function(eax, ecx, xcr0, xss)
        .unwrap()
        .ecx
}

fn fn_8000_0001_edx(eax: u32, ecx: u32, xcr0: u64, xss: u64) -> u32 {
    lookup_provided_cpuid_function(eax, ecx, xcr0, xss)
        .unwrap()
        .edx
}

fn fn_8000_0008_eax(eax: u32, ecx: u32, xcr0: u64, xss: u64) -> u32 {
    lookup_provided_cpuid_function(eax, ecx, xcr0, xss)
        .unwrap()
        .eax
}

fn fn_8000_0008_ebx(eax: u32, ecx: u32, xcr0: u64, xss: u64) -> u32 {
    lookup_provided_cpuid_function(eax, ecx, xcr0, xss)
        .unwrap()
        .ebx
}

fn fn_8000_0008_ecx(eax: u32, ecx: u32, xcr0: u64, xss: u64) -> u32 {
    // FIXME: Does we have to check the APIC ID size?
    lookup_provided_cpuid_function(eax, ecx, xcr0, xss)
        .unwrap()
        .ecx
}

fn fn_8000_0008_edx(eax: u32, ecx: u32, xcr0: u64, xss: u64) -> u32 {
    lookup_provided_cpuid_function(eax, ecx, xcr0, xss)
        .unwrap()
        .edx
}
