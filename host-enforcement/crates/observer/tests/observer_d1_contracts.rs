//! HE-004D1 DESIGN-D1 sections 2 and 20: the four native-profile contract files are the registered bytes (edge record
//! v5's three HE-004D1 rows and its native-profile v3 schema row; `tools/gate.py`'s `CONTRACTS`), and the schema the
//! observer embeds is the vendored file.

use i05_protocol::sha256;
use planeon_observer::contracts;

fn hex(data: &[u8]) -> String {
    sha256::hex(&sha256::digest(data))
}

#[test]
fn the_four_native_profile_files_are_the_registered_bytes() {
    for (bytes, expected, length) in [
        (include_bytes!("../../../contracts/native-profile-v4/qualification.schema.json").as_slice(),
         "c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10", 93041),
        (include_bytes!("../../../contracts/native-profile-v4/vectors.json").as_slice(),
         "dede64ab3202a9e28094f062b5dad868c13ca02423e2380af8666ecf2e7a86e6", 802048),
        (include_bytes!("../../../contracts/native-profile-v4/README.md").as_slice(),
         "a4205a5388dc83827bb39670bcc9477b030f29829128abf19f7578321c170174", 62643),
        (include_bytes!("../../../contracts/native-profile-v3/qualification.schema.json").as_slice(),
         "ae5cbb6aa39f4edfa2d9919f25e55bad9ab214a99ca927c5afe7e2d943946ac5", 78375),
    ] {
        assert_eq!((hex(bytes), bytes.len()), (expected.to_string(), length));
    }
}

#[test]
fn the_embedded_schema_is_the_vendored_file() {
    let vendored: &[u8] = include_bytes!("../../../contracts/native-profile-v4/qualification.schema.json");
    assert_eq!(contracts::NATIVE_PROFILE_V4_SCHEMA, vendored);
    assert_eq!(hex(contracts::NATIVE_PROFILE_V4_SCHEMA), contracts::NATIVE_PROFILE_V4_SCHEMA_SHA256);
    assert_eq!(contracts::NATIVE_PROFILE_V4_SCHEMA_SHA256, "c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10");
    assert_eq!(contracts::NATIVE_PROFILE_V4_SCHEMA.len(), 93041);
    // G-D1-16's span cannot be split, and no host-path needle can straddle its edges: it starts with `{` and ends with
    // `}` and a newline.
    assert_eq!(contracts::NATIVE_PROFILE_V4_SCHEMA.first(), Some(&b'{'));
    assert!(contracts::NATIVE_PROFILE_V4_SCHEMA.ends_with(b"}\n"));
}
