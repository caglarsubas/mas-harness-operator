//! HE-004B1 DESIGN-B sections 2 and 4.4: the contract bytes the observer embeds are the registered ones (edge record v4,
//! rows 34-43, and `tools/gate.py`'s `CONTRACTS`), and i05-protocol's embedded I07 v3 policy-kind table, which OR02
//! reads, is still the registered file at this build base (D3-2).

use i05_protocol::sha256;
use planeon_observer::contracts;

fn hex(data: &[u8]) -> String {
    sha256::hex(&sha256::digest(data))
}

#[test]
fn the_embedded_i06_files_are_the_registered_bytes() {
    assert_eq!(hex(contracts::IDENTITY_CLOSURE), contracts::IDENTITY_CLOSURE_SHA256);
    assert_eq!(hex(contracts::WRITER_INVENTORY), contracts::WRITER_INVENTORY_SHA256);
    assert_eq!(hex(contracts::BOOTSTRAP_RBAC), contracts::BOOTSTRAP_RBAC_SHA256);
    assert_eq!((contracts::IDENTITY_CLOSURE.len(), contracts::WRITER_INVENTORY.len(), contracts::BOOTSTRAP_RBAC.len()),
               (46703, 40914, 88532));
    assert_eq!(contracts::IDENTITY_CLOSURE_SHA256, "0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb");
    assert_eq!(contracts::WRITER_INVENTORY_SHA256, "8e6b3b7565cfc93a61162b84d740cffb2871eb66ab85e8c4e80ac813f1af3077");
    assert_eq!(contracts::BOOTSTRAP_RBAC_SHA256, "7529c2a713af2fb90163175924c264d95f4242d7e0c26b1452c77febb13ed50e");
}

#[test]
fn the_policy_kind_table_is_still_the_registered_file() {
    assert_eq!(hex(i05_protocol::contracts::I07_V3_POLICY_KINDS), contracts::I07_V3_POLICY_KINDS_SHA256);
    assert_eq!(contracts::I07_V3_POLICY_KINDS_SHA256, "4e427204b89959cb855d8641c3fa6f95d358b0b6a6a7730bfc7776adc4a173c0");
}

#[test]
fn the_test_only_contract_files_are_the_registered_bytes() {
    for (text, expected, length) in [
        (include_str!("../../../contracts/i06-v2/vectors.json"),
         "1a5e168f0d8fff233f5072b1440e75a633b38e428f87b2893a96e579122a430e", 213022),
        (include_str!("../../../contracts/i06-v2/criteria.json"),
         "026206c57d3025c0f0129b6615e46c83d5a8000ddc3288f000a1fe4570050cda", 10154),
        (include_str!("../../../contracts/i06-v2/README.md"),
         "553880b957586dbfa50eabc4a99d51735eef2a1b0a82641ea51d8e3ea8cf72eb", 15911),
        (include_str!("../../../contracts/i06-v1/README.md"),
         "ccf952d40b4f6229c0cdea79f976253cd4abb19438c1eebc5794e748a708e4b7", 19633),
        (include_str!("../../../contracts/admission-v3/vectors.json"),
         "a3e2dc9818742ae2188e0e83cf91bb833be836115975b3fb23d5f280f6928cc1", 249833),
        (include_str!("../../../contracts/admission-v3/README.md"),
         "c3106482b4ff79649cbef7c65797c6fcd6b64f8419e871ae7d89eecad3ff98ab", 25310),
        (include_str!("../../../contracts/admission-v3/admission-manifests/planeon-a2.json"),
         "1096b3cc71c4fe6b5a17ed61e8bf8c17ee17fcf52b192503534d60aed9ce4741", 8126),
    ] {
        assert_eq!((hex(text.as_bytes()), text.len()), (expected.to_string(), length));
    }
}
