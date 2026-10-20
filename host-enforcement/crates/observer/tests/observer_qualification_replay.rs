//! HE-004D2 DESIGN-D2 sections 6 and 11 (MODEL_DEFINED R140, R141, R145): `qualification::check_qualification` (v5) and
//! `check_migration` over the vendored native-profile v1, v2 and v3 schemas and history vectors: the five v5 positives
//! accepted with the v1-v3 positives' records as histories (each token's record digest, window and fixture flag
//! asserted), the nineteen qualification cases (each its pinned text), and native-profile v4's twenty-two migration cases
//! (M07 and M08 without predecessor records, the other twenty over the histories): 46 checks. Then R10's local cases:
//! the three schema pins at construction, the inputs' types, the attested-empty, reboot, nonce and validity rules on
//! records built from the v4 positive, and the qualification's input shapes.

mod b1_support;
mod d2_support;

use std::collections::BTreeMap;

use b1_support::apply;
use d2_support::{canonical_digest, field, index, list, migration_histories, parse, positive_records, record_case, text,
                 with_member, V1_VECTORS, V2_VECTORS, V3_VECTORS, V4_VECTORS, V5_VECTORS};
use i05_protocol::json::{JStr, Object, Value};
use planeon_observer::capture_check::Refusal;
use planeon_observer::capture_schema::{CaptureSchema, RecordSchema};
use planeon_observer::kernel_text;
use planeon_observer::qualification::{check_migration, check_qualification, Histories, PredecessorSchemas, QualificationInput};

const V1_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v1/qualification.schema.json");
const V2_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v2/qualification.schema.json");
const V3_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v3/qualification.schema.json");

fn schemas() -> (CaptureSchema, RecordSchema) {
    CaptureSchema::embedded().expect("the embedded schemas")
}

fn record_schema() -> RecordSchema {
    schemas().1
}

fn predecessors() -> PredecessorSchemas {
    PredecessorSchemas::from_bytes(V1_SCHEMA, V2_SCHEMA, V3_SCHEMA).unwrap_or_else(|refusal| panic!("{refusal:?}"))
}

fn histories(v1: Vec<Value>, v2: Vec<Value>, v3: Vec<Value>) -> Histories {
    Histories::new(Value::Array(v1), Value::Array(v2), Value::Array(v3))
}

/// The model's histories: every positive record of the v1, v2 and v3 vectors.
fn full_histories() -> [Vec<Value>; 3] {
    [positive_records(V1_VECTORS), positive_records(V2_VECTORS), positive_records(V3_VECTORS)]
}

/// The model's `qualify(p, bundle)`: the positive's record, profile and endpoints, the bundle's captures, the full
/// histories, no attestation.
fn input(positive: &Value, bundle: &Value) -> QualificationInput {
    let [v1, v2, v3] = full_histories();
    QualificationInput {
        record: field(positive, "record").clone(),
        profile: field(positive, "profile").clone(),
        endpoints: field(positive, "endpoints").clone(),
        captures: field(bundle, "captures").clone(),
        lifecycle: field(bundle, "lifecycle").clone(),
        backend_captures: field(bundle, "backendCaptures").clone(),
        histories: histories(v1, v2, v3),
        no_earlier_history: false,
    }
}

/// A positive's captures as the model's bundle `{captures, lifecycle, backendCaptures}`.
fn bundle(positive: &Value) -> Value {
    let mut members = Object::new();
    for key in ["captures", "lifecycle", "backendCaptures"] {
        members.insert(JStr::new(key), field(positive, key).clone());
    }
    Value::Object(members)
}

/// The pinned qualification texts (Appendix A.3) as `'static` strings.
const PINNED: [&str; 13] = [
    "one capture per resident role",
    "one process reported twice",
    "one inode reported for two files",
    "one file reported at two inodes",
    "test-only implementation profile",
    "containment subject still resident",
    "one observation per backend component",
    "worker capture outside a frozen bracket",
    "role-domain process outside its role cgroup",
    "census lists a cgroup below a role cgroup",
    "worker is not a child of the original broker",
    "census children of the delegated broker service differ",
    "census reports a cgroup with captured processes as unpopulated",
];

fn pinned(found: &str) -> &'static str {
    PINNED.iter().copied().find(|text| *text == found).unwrap_or_else(|| panic!("an unpinned text {found}"))
}

#[test]
fn the_qualification_replay_makes_46_checks() {
    let vectors = parse(V5_VECTORS);
    let positives = list(&vectors, "positive");
    let (schema, record_schema) = schemas();
    let predecessors = predecessors();
    let mut checks = 0usize;

    // The five positives, each accepted in a fixture call; the token binds the record's canonical digest and window.
    for (number, positive) in positives.iter().enumerate() {
        let token = check_qualification(&input(positive, &bundle(positive)), &schema, &record_schema, &predecessors, true)
            .unwrap_or_else(|refusal| panic!("positive {number}: {refusal:?}"));
        let record = field(positive, "record");
        let scope = field(record, "scope");
        assert_eq!(token.record_digest(), canonical_digest(record));
        assert_eq!(Some(token.valid_from()), kernel_text::utc_seconds(text(scope, "validFrom")));
        assert_eq!(Some(token.expires_at()), kernel_text::utc_seconds(text(scope, "expiresAt")));
        assert!(token.fixture());
        checks += 1;
    }
    assert_eq!(checks, 5);

    // The nineteen qualification cases: the row's operations on the bundle, `testFixture` (default true).
    let mut texts: BTreeMap<String, usize> = BTreeMap::new();
    let mut ids = Vec::new();
    for group in ["negative", "accepted"] {
        for row in list(&vectors, group) {
            if text(row, "target") != "qualification" {
                continue;
            }
            assert_eq!(group, "negative", "no accepted qualification case");
            let positive = &positives[index(row, "positive")];
            let edited = apply(&bundle(positive), list(row, "ops"));
            let fixture = row.get("testFixture").and_then(Value::as_bool).unwrap_or(true);
            let verdict = check_qualification(&input(positive, &edited), &schema, &record_schema, &predecessors, fixture);
            let refusal = text(row, "refusal");
            assert_eq!(verdict.map(|_| ()), Err(Refusal::Model(pinned(refusal))), "{}", text(row, "id"));
            *texts.entry(refusal.to_string()).or_default() += 1;
            ids.push(text(row, "id").to_string());
            checks += 1;
        }
    }
    assert_eq!(ids, ["Q01", "Q02", "Q03", "Q04", "Q05", "Q06", "Q07", "V10", "V11", "V12", "V13", "V14", "V18", "V24", "V43",
                     "V44", "V56", "N96", "N97"]);
    assert_eq!((texts.len(), texts.values().sum::<usize>()), (13, 19), "Appendix A.3");
    assert_eq!(checks, 24);

    // Native-profile v4's twenty-two migration cases over the v1-v3 histories (M07 and M08 need no predecessor record).
    let old = parse(V4_VECTORS);
    let full = full_histories();
    let mut migration = Vec::new();
    for row in list(&old, "migration") {
        let (record, profile, _) = record_case(list(&old, "positive"), row);
        let [v1, v2, v3] = migration_histories(row, &full);
        let attested = row.get("noEarlierHistory").and_then(Value::as_bool).unwrap_or(false);
        let verdict = check_migration(&histories(v1, v2, v3), &record, &profile, &predecessors, &record_schema, attested);
        match field(row, "expect").as_str() {
            None => assert_eq!(verdict, Ok(()), "{}", text(row, "id")),
            Some(expected) => {
                assert!(matches!(verdict, Err(Refusal::Model(found)) if found == expected), "{}: {verdict:?}", text(row, "id"))
            }
        }
        migration.push(text(row, "id").to_string());
        checks += 1;
    }
    assert_eq!(migration.len(), 22);
    assert_eq!(migration.first().map(String::as_str), Some("M01"));
    assert_eq!(migration.last().map(String::as_str), Some("M22"));
    assert_eq!(checks, 46);
}

#[test]
fn the_v5_positives_records_are_the_v4_positives_records() {
    let (new, old) = (parse(V5_VECTORS), parse(V4_VECTORS));
    for (one, other) in list(&new, "positive").iter().zip(list(&old, "positive")) {
        for key in ["record", "profile", "endpoints"] {
            assert!(i05_protocol::json::py_eq(field(one, key), field(other, key)), "{key}");
        }
    }
}

#[test]
fn r10_local_qualification_cases() {
    let vectors = parse(V5_VECTORS);
    let positive = &list(&vectors, "positive")[1];
    let (schema, record_schema) = schemas();
    let predecessors = predecessors();
    let refused = |input: &QualificationInput, fixture: bool| {
        check_qualification(input, &schema, &record_schema, &predecessors, fixture).map(|_| ())
    };
    let whole = bundle(positive);
    // A capture list that is not a list, or an empty one: the role-set text; a capture that is not an object: Missing.
    for captures in [Value::Null, Value::Array(Vec::new())] {
        let edited = with_member(&whole, "captures", captures);
        assert_eq!(refused(&input(positive, &edited), true), Err(Refusal::Model("one capture per resident role")));
    }
    let mut odd = list(&whole, "captures").to_vec();
    odd.push(Value::str("SERVER"));
    assert_eq!(refused(&input(positive, &with_member(&whole, "captures", Value::Array(odd))), true), Err(Refusal::Missing));
    // A role that is not text among several captures meets the sort: Missing (Python's TypeError); alone: the text.
    let mut unnamed = list(&whole, "captures").to_vec();
    unnamed[0] = with_member(&unnamed[0], "role", Value::Null);
    assert_eq!(refused(&input(positive, &with_member(&whole, "captures", Value::Array(unnamed.clone()))), true),
               Err(Refusal::Missing));
    let alone = Value::Array(vec![unnamed[0].clone()]);
    assert_eq!(refused(&input(positive, &with_member(&whole, "captures", alone)), true),
               Err(Refusal::Model("one capture per resident role")));
    // The backend list's own shape.
    assert_eq!(refused(&input(positive, &with_member(&whole, "backendCaptures", Value::str("none"))), true),
               Err(Refusal::Model("one observation per backend component")));
    // The record comes first: a v3 record is "not a v4 record" before any capture is read.
    let mut early = input(positive, &with_member(&whole, "captures", Value::Null));
    early.record = with_member(&early.record, "schemaVersion", Value::str("planeon.internal.native-qualification/v3"));
    assert_eq!(refused(&early, true), Err(Refusal::Model("not a v4 record")));
    // The migration comes last: the accepted bundle with an attested empty history beside the retained records.
    let mut late = input(positive, &whole);
    late.no_earlier_history = true;
    assert_eq!(refused(&late, true), Err(Refusal::Model("attested empty history with earlier records")));
    // A production call refuses the test-only backend whatever the captures.
    assert_eq!(refused(&input(positive, &with_member(&whole, "captures", Value::Null)), false),
               Err(Refusal::Model("test-only implementation profile")));
}

#[test]
fn the_three_pins_are_checked_at_construction() {
    assert!(PredecessorSchemas::from_bytes(V1_SCHEMA, V2_SCHEMA, V3_SCHEMA).is_ok());
    let altered = |bytes: &[u8]| {
        let text = std::str::from_utf8(bytes).expect("UTF-8");
        text.replacen("\"$defs\"", "\"$comment\": \"altered\", \"$defs\"", 1).into_bytes()
    };
    let (v1, v2, v3) = (altered(V1_SCHEMA), altered(V2_SCHEMA), altered(V3_SCHEMA));
    for (case, expected) in [((v1.as_slice(), V2_SCHEMA, V3_SCHEMA), "unreviewed v1 schema"),
                             ((V1_SCHEMA, v2.as_slice(), V3_SCHEMA), "unreviewed v2 schema"),
                             ((V1_SCHEMA, V2_SCHEMA, v3.as_slice()), "unreviewed v3 schema"),
                             ((V2_SCHEMA, V1_SCHEMA, V3_SCHEMA), "unreviewed v1 schema"),
                             ((b"{".as_slice(), V2_SCHEMA, V3_SCHEMA), "unreviewed v1 schema"),
                             ((V1_SCHEMA, V2_SCHEMA, b"\xff".as_slice()), "unreviewed v3 schema")] {
        assert!(matches!(PredecessorSchemas::from_bytes(case.0, case.1, case.2), Err(Refusal::Model(found)) if found == expected), "{expected}");
    }
    // Whitespace and member order are not the pin: the canonical encoding is.
    let spaced = String::from_utf8(V2_SCHEMA.to_vec()).expect("UTF-8").replace(",\n", ",\n ");
    assert!(PredecessorSchemas::from_bytes(V1_SCHEMA, spaced.as_bytes(), V3_SCHEMA).is_ok());
}

#[test]
fn r10_local_migration_cases() {
    let vectors = parse(V4_VECTORS);
    let positive = &list(&vectors, "positive")[1];
    let (record, profile) = (field(positive, "record"), field(positive, "profile"));
    let (schema, schemas) = (record_schema(), predecessors());
    let refused = |histories: &Histories, record: &Value, attested: bool| check_migration(histories, record, profile, &schemas, &schema, attested);
    // The inputs' types.
    for bad in [Histories::new(Value::Null, Value::Array(Vec::new()), Value::Array(Vec::new())),
                Histories::new(Value::Array(Vec::new()), Value::str("[]"), Value::Array(Vec::new()))] {
        assert_eq!(refused(&bad, record, true), Err(Refusal::Model("migration inputs")));
    }
    // The record's own shape and its profile binding come first.
    let unbound = with_member(record, "profileDigest", Value::str(&format!("sha256:{}", "0".repeat(64))));
    assert_eq!(refused(&histories(Vec::new(), Vec::new(), Vec::new()), &unbound, true), Err(Refusal::Model("profile substitution")));
    let invalid = with_member(record, "t04Proofs", Value::Array(Vec::new()));
    assert_eq!(refused(&histories(Vec::new(), Vec::new(), Vec::new()), &invalid, true), Err(Refusal::Schema));
    // A predecessor that is not a valid record of its version, in v1, v2, v3 order.
    let v4 = record.clone();
    for (index, expected) in [(0, "predecessor is not a valid v1 record"), (1, "predecessor is not a valid v2 record"),
                              (2, "predecessor is not a valid v3 record")] {
        let mut lists = [Vec::new(), Vec::new(), Vec::new()];
        lists[index].push(v4.clone());
        let [v1, v2, v3] = lists;
        assert_eq!(refused(&histories(v1, v2, v3), record, false), Err(Refusal::Model(expected)));
        assert_eq!(refused(&histories(vec![Value::Null], Vec::new(), Vec::new()), record, false),
                   Err(Refusal::Model("predecessor is not a valid v1 record")));
    }
    // Attested empty history with a record, and no record without the attestation.
    assert_eq!(refused(&histories(vec![Value::Null], Vec::new(), Vec::new()), record, true),
               Err(Refusal::Model("attested empty history with earlier records")));
    assert_eq!(refused(&histories(Vec::new(), Vec::new(), Vec::new()), record, false),
               Err(Refusal::Model("retained earlier records required")));
}
