//! The I05 v3 frame (34), byte (14) and agreement (42) checks of `contracts/i05-v3/vectors.json`, compared with the
//! exact refusal text as the pinned validator compares them. The transcripts and configuration refusals run in
//! `effect-gate`.

mod support;

use i05_protocol::json::Value;
use i05_protocol::{decode_frame, Datagram, Identity, Kind, OutcomeMapping, Verb};
use support::*;

const VECTORS: &str = include_str!("../../../contracts/i05-v3/vectors.json");

#[test]
fn frame_checks() {
    let vectors = load(VECTORS);
    let schema = i05_protocol::i05_v3_schema().expect("schema");
    let frames = rows(&vectors, "frames");
    assert_eq!(frames.len(), 34);
    for row in frames {
        let id = text(row, "id");
        let frame = field(row, "frame");
        let got = i05_protocol::check_frame(frame, &schema).err().map(|error| error.message().to_string());
        assert_eq!(got, expect(row), "frame check {id}");
        assert_bytes_path_agrees(frame, &schema, id);
    }
}

#[test]
fn byte_checks() {
    let vectors = load(VECTORS);
    let schema = i05_protocol::i05_v3_schema().expect("schema");
    let checks = rows(&vectors, "byteFrames");
    let ids: Vec<&str> = checks.iter().map(|row| text(row, "id")).collect();
    let expected_ids: Vec<String> = (1..=14).map(|n| format!("B{n:02}")).collect();
    assert_eq!(ids, expected_ids, "byte checks in order");
    for row in checks {
        let id = text(row, "id");
        let raw = vector_bytes(text(row, "base64"));
        // The validator's inputType mapping: bytes stay bytes; a bytearray or a str (ASCII) is not a byte string.
        let datagram = match text(row, "inputType") {
            "bytes" => Datagram::Bytes(&raw),
            "bytearray" => Datagram::NotBytes,
            "str" => {
                assert!(raw.is_ascii(), "{id}: a str input decodes as ASCII");
                Datagram::NotBytes
            }
            other => panic!("{id}: unknown inputType {other}"),
        };
        let got = decode_frame(datagram, &schema).err().map(|error| error.message().to_string());
        assert_eq!(got, expect(row), "byte check {id}");
    }
}

#[test]
fn agreement_checks() {
    let vectors = load(VECTORS);
    let mapping = OutcomeMapping::i05_v3().expect("mapping");
    let checks = rows(&vectors, "agreement");
    assert_eq!(checks.len(), 42);
    for row in checks {
        let id = text(row, "id");
        let verb = Verb::parse(text(row, "verb")).expect("verb");
        let identity = field(row, "identity");
        let identity = Identity {
            api_version: text(identity, "apiVersion").to_string(),
            kind: Kind::parse(text(identity, "kind")).expect("kind"),
            namespace: text(identity, "namespace").to_string(),
            name: text(identity, "name").to_string(),
        };
        let got = mapping
            .check_agreement(verb, &identity, field(row, "outcome"), field(row, "resourceResult"))
            .map(|mismatch| mismatch.message().to_string());
        assert_eq!(got, expect(row), "agreement check {id}");
    }
}

#[test]
fn vector_file_shape() {
    let vectors = load(VECTORS);
    let keys: Vec<&str> = vectors.as_object().expect("object").iter().filter_map(|(key, _)| key.as_str()).collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, ["agreement", "byteFrames", "configRefusals", "configs", "evidenceClass", "frames", "transcripts"]);
    assert!(matches!(field(&vectors, "evidenceClass"), Value::Str(text) if text.as_str() == Some("DATA_CHECK_ONLY")));
}
