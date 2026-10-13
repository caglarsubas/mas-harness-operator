//! The I07 v3 frame (48) and byte (9) checks of `contracts/i07-v3/vectors.json`, run through the same frame pipeline
//! against the I07 v3 schema. As the pinned validator does, only the refusal code (`F00` to `F07`) is compared.

mod support;

use i05_protocol::{check_frame, decode_frame, Datagram};
use support::*;

const VECTORS: &str = include_str!("../../../contracts/i07-v3/vectors.json");

#[test]
fn frame_checks() {
    let vectors = load(VECTORS);
    let schema = i05_protocol::i07_v3_schema().expect("schema");
    let frames = rows(&vectors, "frames");
    assert_eq!(frames.len(), 48);
    for row in frames {
        let id = text(row, "id");
        let frame = field(row, "frame");
        let got = check_frame(frame, &schema).err().map(|error| error.code().to_string());
        assert_eq!(got, expect(row), "I07 frame check {id}");
        assert_bytes_path_agrees(frame, &schema, id);
    }
}

#[test]
fn byte_checks() {
    let vectors = load(VECTORS);
    let schema = i05_protocol::i07_v3_schema().expect("schema");
    let checks = rows(&vectors, "byteFrames");
    assert_eq!(checks.len(), 9);
    for row in checks {
        let id = text(row, "id");
        let raw = vector_bytes(text(row, "base64"));
        let got = decode_frame(Datagram::Bytes(&raw), &schema).err().map(|error| error.code().to_string());
        assert_eq!(got, expect(row), "I07 byte check {id}");
    }
}
