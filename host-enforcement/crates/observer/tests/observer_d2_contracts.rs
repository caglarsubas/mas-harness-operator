//! HE-004D2 DESIGN-D2 sections 2 and 15.1: edge record v6's five and edge record v7's six HE-004D2 files are the
//! registered bytes (`tools/gate.py`'s `CONTRACTS`), `contracts.rs` embeds only the files G-D2-2 admits (the v5 schema
//! among them since unit B1, mirroring HE-004D1's v4 assertions), and the native-profile schemas hash to the canonical
//! pins the models name (`native_qualification_v4.py` lines 44-47, `native_qualification_v5.py` line 36).

use i05_protocol::json;
use i05_protocol::sha256;
use planeon_observer::contracts;

fn hex(data: &[u8]) -> String {
    sha256::hex(&sha256::digest(data))
}

const V1_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v1/qualification.schema.json");
const V2_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v2/qualification.schema.json");
const V3_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v3/qualification.schema.json");
const V4_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v4/qualification.schema.json");
const V5_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v5/qualification.schema.json");

#[test]
fn edge_v6_s_five_files_are_the_registered_bytes() {
    for (bytes, expected, length) in [
        (V1_SCHEMA, "bef248bfa82b234124c014f98e40c5791bced3171bb118b7ed1bb7b8daaf95c3", 37185),
        (V2_SCHEMA, "55bd641fd229f21e04ec00813bcfe600890584e982e290a210720ac5cb160ab0", 65003),
        (include_bytes!("../../../contracts/i06-v3/vectors.json").as_slice(),
         "4752b648abdd82d21ea622a1b26c721143577478c0a2491204e0d584c1d6f081", 213011),
        (include_bytes!("../../../contracts/i06-v3/criteria.json").as_slice(),
         "752533c57b5f93e4c4158a9c17b52eb88d236a3632ab0b66b669e8f8041f57c7", 10561),
        (include_bytes!("../../../contracts/i06-v3/README.md").as_slice(),
         "9ee406f43060f266a7b5dd2679aa8352f0815584c45e33d0ab193ea7f90c0c77", 14910),
    ] {
        assert_eq!((hex(bytes), bytes.len()), (expected.to_string(), length));
    }
}

#[test]
fn contracts_rs_embeds_only_the_admitted_files() {
    // G-D2-2: I06 v1's three files (HE-004B1) and the v4 schema (HE-004D1), each the vendored bytes at its pin.
    for (embedded, vendored, pin) in [
        (contracts::IDENTITY_CLOSURE, include_bytes!("../../../contracts/i06-v1/identity-closure.json").as_slice(),
         contracts::IDENTITY_CLOSURE_SHA256),
        (contracts::WRITER_INVENTORY, include_bytes!("../../../contracts/i06-v1/writer-inventory.json").as_slice(),
         contracts::WRITER_INVENTORY_SHA256),
        (contracts::BOOTSTRAP_RBAC,
         include_bytes!("../../../contracts/i06-v1/upstream-bootstrap-rbac-v1.37.1.json").as_slice(),
         contracts::BOOTSTRAP_RBAC_SHA256),
        (contracts::NATIVE_PROFILE_V4_SCHEMA, V4_SCHEMA, contracts::NATIVE_PROFILE_V4_SCHEMA_SHA256),
        (contracts::NATIVE_PROFILE_V5_SCHEMA, V5_SCHEMA, contracts::NATIVE_PROFILE_V5_SCHEMA_SHA256),
    ] {
        assert_eq!(embedded, vendored);
        assert_eq!(hex(embedded), pin);
    }
}

#[test]
fn the_native_profile_schemas_hash_to_the_model_s_canonical_pins() {
    for (bytes, pin) in [
        (V1_SCHEMA, "8e184d60df63863bc627c1655887c32012490e3c7211f8f9a38baee67f64d4cf"),
        (V2_SCHEMA, "fd1657c9a9ea437df2d48f03c69a1de62013a47a9fc62ad7776db2fc7029c0c5"),
        (V3_SCHEMA, "1c7930351e58a12cdf8bf8ef0df1f971eddceb8d17268f73541425258e9657d2"),
        (V4_SCHEMA, "3bf244b21f91e30062ad56a7a21f3f0b4554daa71a0c3b624bcac058fee58d80"),
        (V5_SCHEMA, "5f6703ca38d0919f6446772e8edd75e92609a9a3971b8cb052b53a7e9ab50393"),
    ] {
        let value = json::parse(std::str::from_utf8(bytes).expect("UTF-8")).expect("a JSON document");
        assert_eq!(hex(&json::canonical(&value).expect("a canonical encoding")), pin);
    }
}

#[test]
fn edge_v7_s_six_files_are_the_registered_bytes() {
    for (bytes, expected, length) in [
        (V5_SCHEMA, "70bda12463cee83301bc10fa6285023dc0e07b281a87ca70d44ec746cf262113", 46190),
        (include_bytes!("../../../contracts/native-profile-v5/vectors.json").as_slice(),
         "b630c362b20bfa7b362bb2ee28734a403303a0dc54b2d627c11a332b226333a1", 630987),
        (include_bytes!("../../../contracts/native-profile-v5/README.md").as_slice(),
         "76b584ca769f0afdd5142fcf3f96e3b5b2d053a172d5713f970dc77594e77692", 32146),
        (include_bytes!("../../../contracts/native-profile-v1/vectors.json").as_slice(),
         "cd1be009b721bb596887335184a33ab8e1f24aed8215477b63e28f058110748f", 212215),
        (include_bytes!("../../../contracts/native-profile-v2/vectors.json").as_slice(),
         "6d58d1f36b7bce5739b94dd89512d358b96878c70e1de7cf8f399050b881b396", 481933),
        (include_bytes!("../../../contracts/native-profile-v3/vectors.json").as_slice(),
         "14af47a69c972039294be8659c31332acd5326bfb0a3a38384a2c6bf9d11fe6d", 560411),
    ] {
        assert_eq!((hex(bytes), bytes.len()), (expected.to_string(), length));
    }
}

#[test]
fn the_embedded_v5_schema_is_the_vendored_file() {
    assert_eq!(contracts::NATIVE_PROFILE_V5_SCHEMA, V5_SCHEMA);
    assert_eq!(hex(contracts::NATIVE_PROFILE_V5_SCHEMA), contracts::NATIVE_PROFILE_V5_SCHEMA_SHA256);
    assert_eq!(contracts::NATIVE_PROFILE_V5_SCHEMA_SHA256, "70bda12463cee83301bc10fa6285023dc0e07b281a87ca70d44ec746cf262113");
    assert_eq!(contracts::NATIVE_PROFILE_V5_SCHEMA.len(), 46190);
    assert_eq!(contracts::NATIVE_PROFILE_V5_SCHEMA.first(), Some(&b'{'));
    assert!(contracts::NATIVE_PROFILE_V5_SCHEMA.ends_with(b"}\n"));
    // G-D1-16's scan reads these bytes whole: they hold none of the host-path needles.
    for needle in [b"/Users/".as_slice(), b"/opt/planeon/", b"/private/tmp/", b"/private/var/"] {
        assert!(!contracts::NATIVE_PROFILE_V5_SCHEMA.windows(needle.len()).any(|window| window == needle));
    }
}
