use bit_field::BitField;
use bytemuck::CheckedBitPattern;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct GuestPolicy {
    policy: u64,
}

impl GuestPolicy {
    pub fn new(abi_major: u8, abi_minor: u8) -> Self {
        let mut policy = 0;
        policy.set_bits(0..=7, u64::from(abi_minor));
        policy.set_bits(8..=15, u64::from(abi_major));
        policy.set_bit(17, true); // Reserved. Must be one.
        Self { policy }
    }

    pub fn abi_major(&self) -> u8 {
        self.policy.get_bits(8..=15) as u8
    }

    pub fn abi_minor(&self) -> u8 {
        self.policy.get_bits(0..=7) as u8
    }

    pub fn allow_smt(self) -> bool {
        self.policy.get_bit(16)
    }

    pub fn with_allow_smt(self, allow: bool) -> Self {
        let mut policy = self.policy;
        policy.set_bit(16, allow);
        Self { policy }
    }

    pub fn allow_migration_agent_association(self) -> bool {
        self.policy.get_bit(18)
    }

    pub fn with_allow_migration_agent_association(self, allow: bool) -> Self {
        let mut policy = self.policy;
        policy.set_bit(18, allow);
        Self { policy }
    }

    pub fn allow_debugging(self) -> bool {
        self.policy.get_bit(19)
    }

    pub fn with_allow_debugging(self, allow: bool) -> Self {
        let mut policy = self.policy;
        policy.set_bit(19, allow);
        Self { policy }
    }

    pub fn single_socket_only(self) -> bool {
        self.policy.get_bit(17)
    }

    pub fn with_single_socket_only(self, only: bool) -> Self {
        let mut policy = self.policy;
        policy.set_bit(17, only);
        Self { policy }
    }
}

unsafe impl CheckedBitPattern for GuestPolicy {
    type Bits = u64;

    fn is_valid_bit_pattern(bits: &Self::Bits) -> bool {
        bits.get_bit(17) && bits.get_bits(20..) == 0
    }
}

impl core::fmt::Debug for GuestPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuestPolicy")
            .field("abi_major", &self.abi_major())
            .field("abi_minor", &self.abi_minor())
            .field("allow_smt", &self.allow_smt())
            .field("single_socket_only", &self.single_socket_only())
            .field(
                "allow_migration_agent_association",
                &self.allow_migration_agent_association(),
            )
            .field("allow_debugging", &self.allow_debugging())
            .finish()
    }
}
