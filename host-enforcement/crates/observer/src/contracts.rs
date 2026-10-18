//! The contract data the observer's RBAC snapshot check reads, embedded byte for byte from `host-enforcement/contracts/`
//! (HE-004B1 DESIGN-B sections 2, 4.3 and 6). This is the observer's one module of embedded contract bytes: `tools/gate.py`
//! requires every `include_bytes!` here to name a file it registers (`CONTRACTS`), and refuses the macro in the HE-004B1
//! modules. The digests, provenance and edge rows are in `contracts/PROVENANCE.md`; the tests pin each digest again.
//! The I07 v3 policy-kind table OR02 reads is i05-protocol's own embedded copy (`i05_protocol::contracts`).

/// The identity closure `planeon.internal.i06-identity-closure/v1` (I06 v1, sha256 `0a9b82ff…`).
pub const IDENTITY_CLOSURE: &[u8] = include_bytes!("../../../contracts/i06-v1/identity-closure.json");

/// The writer inventory `planeon.internal.i06-writer-inventory/v1` (I06 v1, sha256 `8e6b3b75…`): the controller accounts.
pub const WRITER_INVENTORY: &[u8] = include_bytes!("../../../contracts/i06-v1/writer-inventory.json");

/// The upstream bootstrap RBAC of Kubernetes v1.37.1 `planeon.internal.i06-upstream-bootstrap-rbac/v1` (I06 v1, sha256
/// `7529c2a7…`): each bootstrap subject's effective rules, the baseline of a dormant controller account.
pub const BOOTSTRAP_RBAC: &[u8] = include_bytes!("../../../contracts/i06-v1/upstream-bootstrap-rbac-v1.37.1.json");

/// The registered sha256 of each embedded file, as `tools/gate.py` pins them.
pub const IDENTITY_CLOSURE_SHA256: &str = "0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb";
pub const WRITER_INVENTORY_SHA256: &str = "8e6b3b7565cfc93a61162b84d740cffb2871eb66ab85e8c4e80ac813f1af3077";
pub const BOOTSTRAP_RBAC_SHA256: &str = "7529c2a713af2fb90163175924c264d95f4242d7e0c26b1452c77febb13ed50e";

/// The registered sha256 of `contracts/i07-v3/policy-kinds.json`, which i05-protocol embeds and OR02 re-checks before it
/// reads the kind set (DESIGN-B section 4.4, D3-2).
pub const I07_V3_POLICY_KINDS_SHA256: &str = "4e427204b89959cb855d8641c3fa6f95d358b0b6a6a7730bfc7776adc4a173c0";
