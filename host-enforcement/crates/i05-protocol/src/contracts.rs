//! The pinned contract data this crate interprets, embedded byte for byte from `host-enforcement/contracts/`
//! (harness-onion `a2eab93`; digests in `contracts/PROVENANCE.md`).

/// `planeon.internal.effect-gate-frame/v3` (sha256 `3bfee13c…`).
pub const I05_V3_SCHEMA: &[u8] = include_bytes!("../../../contracts/i05-v3/channel.schema.json");

/// `planeon.internal.effect-gate-outcome-mapping/v2` as published with I05 v3 (sha256 `4466f379…`).
pub const I05_V3_OUTCOME_MAPPING: &[u8] = include_bytes!("../../../contracts/i05-v3/outcome-mapping.json");

/// `planeon.internal.policy-write-frame/v3` (sha256 `c68721a1…`), checked through the same frame pipeline.
pub const I07_V3_SCHEMA: &[u8] = include_bytes!("../../../contracts/i07-v3/channel.schema.json");

/// The closed I07 v3 policy-kind table `policy-kinds.json` (sha256 `4e427204…`), which the gate binary hands to
/// `PolicyGate` (HE-003D DESIGN section 3.6, gap G3).
pub const I07_V3_POLICY_KINDS: &[u8] = include_bytes!("../../../contracts/i07-v3/policy-kinds.json");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    #[test]
    fn embedded_bytes_are_the_pinned_contract() {
        assert_eq!(sha256::hex(&sha256::digest(I05_V3_SCHEMA)),
                   "3bfee13c9d32e82fe5ab908eb6f716bc11881f9d57b324f8ea4a21a3ad35356f");
        assert_eq!(sha256::hex(&sha256::digest(I05_V3_OUTCOME_MAPPING)),
                   "4466f379f1cc669e047cffd8afa5fa88b2cc7648a51e2d38b17f0bd5e2252a3a");
        assert_eq!(sha256::hex(&sha256::digest(I07_V3_SCHEMA)),
                   "c68721a1002fccc7d6e59eeee9016a0a0f4a7428fad714e5a3d90a362d30ce09");
    }

    /// HE-003D DESIGN section 3.6: the embedded table is the bytes `tools/gate.py` registers (CONTRACTS).
    #[test]
    fn the_policy_kinds_table_is_the_pinned_contract() {
        assert_eq!(sha256::hex(&sha256::digest(I07_V3_POLICY_KINDS)),
                   "4e427204b89959cb855d8641c3fa6f95d358b0b6a6a7730bfc7776adc4a173c0");
    }
}
