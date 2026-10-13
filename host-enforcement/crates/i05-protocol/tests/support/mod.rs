//! Shared helpers for the contract-vector tests: the vectors are parsed with this crate's own JSON parser.
#![allow(dead_code)]

use i05_protocol::json::{self, Value};
use i05_protocol::{base64, frame, Datagram, FrameError, Schema};

pub fn load(text: &str) -> Value {
    json::parse(text).expect("vector file parses")
}

pub fn field<'a>(row: &'a Value, key: &str) -> &'a Value {
    row.get(key).unwrap_or_else(|| panic!("missing {key}"))
}

pub fn text<'a>(row: &'a Value, key: &str) -> &'a str {
    field(row, key).as_str().unwrap_or_else(|| panic!("{key} is not text"))
}

pub fn rows<'a>(document: &'a Value, key: &str) -> &'a [Value] {
    field(document, key).as_array().unwrap_or_else(|| panic!("{key} is not an array"))
}

/// The expected refusal: a string, or null for acceptance.
pub fn expect(row: &Value) -> Option<String> {
    match field(row, "expect") {
        Value::Null => None,
        other => Some(other.as_str().expect("expect is text or null").to_string()),
    }
}

/// The validator's `_base64`: strict, and canonical (re-encoding gives the same text).
pub fn vector_bytes(encoded: &str) -> Vec<u8> {
    let raw = base64::decode_strict(encoded.as_bytes()).expect("strict base64");
    assert_eq!(base64::encode(&raw), encoded, "canonical base64");
    raw
}

/// E12-style consistency: when a frame value has a canonical encoding within 16 KiB, the bytes decoder reaches the same
/// verdict as `check_frame` on the value.
pub fn assert_bytes_path_agrees(frame_value: &Value, schema: &Schema, id: &str) {
    let by_value = frame::check_frame(frame_value, schema);
    let Ok(encoded) = json::canonical(frame_value) else {
        assert!(by_value.is_err(), "{id}: a value without a canonical encoding passed check_frame");
        return;
    };
    let by_bytes = frame::decode_frame(Datagram::Bytes(&encoded), schema).map(|_| ());
    if encoded.len() > frame::MAX_FRAME_BYTES {
        assert_eq!(by_bytes, Err(FrameError::F02), "{id}");
        assert!(by_value.is_err(), "{id}: an oversize frame passed check_frame");
    } else {
        assert_eq!(by_bytes, by_value, "{id}: bytes and value paths disagree");
    }
}
