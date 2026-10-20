//! Shared helpers for HE-004D2's tests (DESIGN-D2 section 15.1): the vector readers and the case builder of the
//! native-profile v4 record family (`profileOps`, `endpointOps`, `ops`, `rebindProfile`), over B1's `apply`, with the
//! I06 v3 and v2 vectors the evidence replay reads; phase B adds native-profile v5's vectors, the v1-v3 history vectors
//! (each set's positive records, the model's histories) and the migration case builder (`v1Ops`, `v2Ops`, `v3Ops`).
#![allow(dead_code)]

use i05_protocol::json::{self, JStr, Value};
use i05_protocol::sha256;

use crate::b1_support::apply;

pub const V4_VECTORS: &str = include_str!("../../../../contracts/native-profile-v4/vectors.json");
pub const V4_SCHEMA: &str = include_str!("../../../../contracts/native-profile-v4/qualification.schema.json");
pub const V3_SCHEMA: &str = include_str!("../../../../contracts/native-profile-v3/qualification.schema.json");
pub const I06_V3_VECTORS: &str = include_str!("../../../../contracts/i06-v3/vectors.json");
pub const I06_V2_VECTORS: &str = include_str!("../../../../contracts/i06-v2/vectors.json");
pub const V5_VECTORS: &str = include_str!("../../../../contracts/native-profile-v5/vectors.json");
pub const V1_VECTORS: &str = include_str!("../../../../contracts/native-profile-v1/vectors.json");
pub const V2_VECTORS: &str = include_str!("../../../../contracts/native-profile-v2/vectors.json");
pub const V3_VECTORS: &str = include_str!("../../../../contracts/native-profile-v3/vectors.json");

pub fn parse(text: &str) -> Value {
    json::parse(text).expect("test JSON parses")
}

pub fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or_else(|| panic!("missing {key}"))
}

pub fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    field(value, key).as_array().unwrap_or_else(|| panic!("{key} is not a list"))
}

pub fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key).as_str().unwrap_or_else(|| panic!("{key} is not text"))
}

pub fn index(value: &Value, key: &str) -> usize {
    usize::try_from(field(value, key).as_int().and_then(|int| int.to_u64()).expect("an index")).expect("a small index")
}

/// A row's optional operation list (absent is empty).
pub fn ops<'a>(row: &'a Value, key: &str) -> &'a [Value] {
    row.get(key).and_then(Value::as_array).unwrap_or_default()
}

/// `"sha256:"` and the hex of a value's canonical encoding.
pub fn canonical_digest(value: &Value) -> String {
    sha256::prefixed(&json::canonical(value).expect("canonical"))
}

/// The value with `key` set to `member` (an object's member replaced or added).
pub fn with_member(value: &Value, key: &str, member: Value) -> Value {
    let mut value = value.clone();
    match &mut value {
        Value::Object(object) => object.insert(JStr::new(key), member),
        _ => panic!("an object"),
    }
    value
}

/// The model's case builder for the record family: the positive's profile and endpoints with the row's `profileOps`
/// and `endpointOps`, its record with the row's `ops`, and the record's profile digest rebound when `rebindProfile`.
/// (record, profile, endpoints).
pub fn record_case(positives: &[Value], row: &Value) -> (Value, Value, Value) {
    let positive = &positives[index(row, "positive")];
    let profile = apply(field(positive, "profile"), ops(row, "profileOps"));
    let endpoints = apply(field(positive, "endpoints"), ops(row, "endpointOps"));
    let mut record = apply(field(positive, "record"), ops(row, "ops"));
    if row.get("rebindProfile").and_then(Value::as_bool) == Some(true) {
        record = with_member(&record, "profileDigest", Value::str(&canonical_digest(&profile)));
    }
    (record, profile, endpoints)
}

/// A vector set's positive records (the model's `histories`: `[row["record"] for row in vectors["positive"]]`).
pub fn positive_records(vectors: &str) -> Vec<Value> {
    list(&parse(vectors), "positive").iter().map(|positive| field(positive, "record").clone()).collect()
}

/// The model's migration case: the record, profile and endpoints as `record_case` builds them, and each history the
/// row's `vNPositives` indices of the full histories with its `vNOps` applied (`{index, ops}` each).
pub fn migration_histories(row: &Value, full: &[Vec<Value>; 3]) -> [Vec<Value>; 3] {
    let mut olds: [Vec<Value>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for (slot, (key, changes)) in [("v1Positives", "v1Ops"), ("v2Positives", "v2Ops"), ("v3Positives", "v3Ops")].iter().enumerate() {
        olds[slot] = list(row, key).iter().map(|position| {
            let position = usize::try_from(position.as_int().and_then(|int| int.to_u64()).expect("an index")).expect("small");
            full[slot][position].clone()
        }).collect();
        for change in ops(row, changes) {
            let position = index(change, "index");
            olds[slot][position] = apply(&olds[slot][position], list(change, "ops"));
        }
    }
    olds
}
