use bytemuck::{Pod, Zeroable};

pub const COUNT_MAX: usize = 64;

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C, align(4096))]
pub struct CpuidPage {
    pub count: u32,
    _reserved1: u32,
    _reserved2: u64,
    pub functions: [CpuidFunction; 64],
    _padding: [u8; 1008],
}

impl CpuidPage {
    pub fn new(functions: &[CpuidFunction]) -> Self {
        assert!(functions.len() <= COUNT_MAX);
        Self {
            count: functions.len() as u32,
            _reserved1: 0,
            _reserved2: 0,
            functions: {
                let mut fns = [CpuidFunction::zeroed(); COUNT_MAX];
                fns[..functions.len()].copy_from_slice(functions);
                fns
            },
            _padding: [0; 1008],
        }
    }

    pub const fn zero() -> Self {
        Self {
            count: 0,
            _reserved1: 0,
            _reserved2: 0,
            functions: [CpuidFunction {
                eax_in: 0,
                ecx_in: 0,
                xcr0_in: 0,
                xss_in: 0,
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
                _reserved: 0,
            }; 64],
            _padding: [0; 1008],
        }
    }
}

impl core::fmt::Debug for CpuidPage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CpuidPage")
            .field("count", &self.count)
            .field("functions", &self.functions)
            .finish()
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct CpuidFunction {
    pub eax_in: u32,
    pub ecx_in: u32,
    pub xcr0_in: u64,
    pub xss_in: u64,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    _reserved: u64,
}

impl CpuidFunction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        eax_in: u32,
        ecx_in: u32,
        xcr0_in: u64,
        xss_in: u64,
        eax: u32,
        ebx: u32,
        ecx: u32,
        edx: u32,
    ) -> Self {
        Self {
            eax_in,
            ecx_in,
            xcr0_in,
            xss_in,
            eax,
            ebx,
            ecx,
            edx,
            _reserved: 0,
        }
    }

    pub fn matches(&self, eax: u32, ecx: Option<u32>, xcr0: u64, xss: u64) -> bool {
        self.eax_in == eax
            && ecx.map_or(true, |ecx| self.ecx_in == ecx)
            && self.xcr0_in == xcr0
            && self.xss_in == xss
            && self._reserved == 0
    }
}

impl core::fmt::Debug for CpuidFunction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CpuidFunction")
            .field("eax_in", &self.eax_in)
            .field("ecx_in", &self.ecx_in)
            .field("xcr0_in", &self.xcr0_in)
            .field("xss_in", &self.xss_in)
            .field("eax", &self.eax)
            .field("ebx", &self.ebx)
            .field("ecx", &self.ecx)
            .field("edx", &self.edx)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::CpuidPage;

    #[test]
    fn test_size() {
        assert_eq!(size_of::<CpuidPage>(), 0x1000);
        assert_eq!(align_of::<CpuidPage>(), 0x1000);
    }
}
