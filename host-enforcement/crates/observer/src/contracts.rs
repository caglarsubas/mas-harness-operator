//! The contract data the observer's RBAC snapshot check reads, embedded byte for byte from `host-enforcement/contracts/`
//! (HE-004B1 DESIGN-B sections 2, 4.3 and 6). This is the observer's one module of embedded contract bytes: `tools/gate.py`
//! requires every `include_bytes!` here to name a file it registers (`CONTRACTS`), and refuses the macro in the HE-004B1
//! modules. The digests, provenance and edge rows are in `contracts/PROVENANCE.md`; the tests pin each digest again.
//! The I07 v3 policy-kind table OR02 reads is i05-protocol's own embedded copy (`i05_protocol::contracts`). HE-004D1
//! (DESIGN-D1 section 2) adds native-profile v4's schema for the kernel captures' checks; HE-004D2 (DESIGN-D2 section 4.1,
//! unit B1) adds native-profile v5's capture schema, and the v4 schema stays for the record.

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

/// HE-004D1 (DESIGN-D1 sections 2 and 6; G-D1-9): native-profile v4's qualification schema (edge record v5, sha256
/// `c3e91c08…`), loaded once, in `CaptureSchema::embedded`, its one use site, for the record's validator (HE-004D2: the
/// captures' validators come from the v5 schema). The binary holds these bytes exactly once (G-D1-16).
pub const NATIVE_PROFILE_V4_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v4/qualification.schema.json");

/// The registered sha256 of the native-profile v4 schema, as `tools/gate.py` pins it.
pub const NATIVE_PROFILE_V4_SCHEMA_SHA256: &str = "c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10";

/// HE-004D2 (DESIGN-D2 section 4.1, G-D2-3): native-profile v5's capture schema (edge record v7, sha256 `70bda124…`), from
/// which the capture validators are built, in `CaptureSchema::embedded`, its one use site. The record validator stays
/// native-profile v4's.
pub const NATIVE_PROFILE_V5_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v5/qualification.schema.json");

/// The registered sha256 of the native-profile v5 schema, as `tools/gate.py` pins it.
pub const NATIVE_PROFILE_V5_SCHEMA_SHA256: &str = "70bda12463cee83301bc10fa6285023dc0e07b281a87ca70d44ec746cf262113";
