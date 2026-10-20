//! HE-004D2 DESIGN-D2 sections 7 and 11 (MODEL_DEFINED R142, R145): the replay of I06 v3's vectors through
//! `i06_evidence::check_evidence` (evidence) and B1's snapshot check (the snapshot cases I06 v3 carries from v2): the
//! three positive checks (the evidence accepted as a fixture and refused in production, the snapshot accepted), 7
//! accepted evidence variants, 5 accepted snapshot variants, 91 evidence negatives, 38 snapshot negatives and the v3
//! halves of the 7 cross-version cases: 151 checks. A W02a schema refusal reported by SC00 is localised on the bound
//! record under the v4 schema; I06 X01's v1 subject is built from the v3 positive (the record without its W02a reference,
//! at I06 v1's version), and I06 X07's v2 subject is I06 v2's registered positive. Every count is asserted.

mod b1_support;
mod d2_support;
mod schema_support;

use std::collections::BTreeMap;

use b1_support::apply;
use d2_support::{field, list, ops, parse, text, with_member, I06_V2_VECTORS, I06_V3_VECTORS, V4_SCHEMA, V4_VECTORS};
use i05_protocol::json::{self, Value};
use planeon_observer::capture_check::Refusal;
use planeon_observer::capture_schema::{CaptureSchema, RecordSchema};
use planeon_observer::contracts;
use planeon_observer::i06_evidence::{check_evidence, fixture_flag, record_digest, EvidenceRefusal, W02A_PREFIX};
use planeon_observer::snapshot::Closure;
use schema_support::{localised, localised_in_branch};

struct Setup {
    vectors: Value,
    positives: Vec<Value>,
    evidence: Value,
    inventory: Value,
    schema: RecordSchema,
    v4_schema: Value,
    closure: Closure,
}

fn setup() -> Setup {
    let vectors = parse(I06_V3_VECTORS);
    let positives = list(&parse(V4_VECTORS), "positive").to_vec();
    let evidence = field(&vectors, "evidencePositive").clone();
    let inventory = json::parse(std::str::from_utf8(contracts::WRITER_INVENTORY).expect("UTF-8")).expect("the inventory");
    let schema = CaptureSchema::embedded().expect("the embedded schema").1;
    Setup { vectors, positives, evidence, inventory, schema, v4_schema: parse(V4_SCHEMA),
            closure: Closure::embedded().expect("the embedded closure") }
}

/// I06 v3's `bound(row)`: the native-profile v4 positive (`w02aPositive`, default 0) with the row's `backendOps`.
fn bound<'a>(setup: &'a Setup, row: &Value) -> (Value, &'a Value, &'a Value) {
    let number = row.get("w02aPositive").map_or(0, |_| d2_support::index(row, "w02aPositive"));
    let positive = &setup.positives[number];
    (apply(field(positive, "record"), ops(row, "backendOps")), field(positive, "profile"), field(positive, "endpoints"))
}

/// The v3 positive re-bound by digest to `record`.
fn rebound(evidence: &Value, record: &Value) -> Value {
    let reference = with_member(field(evidence, "w02aRecord"), "qualificationDigest",
                                Value::str(&record_digest(record).expect("a canonical record")));
    with_member(evidence, "w02aRecord", reference)
}

/// One evidence verdict: `None` when accepted, otherwise the refusal as the vectors spell it (a W02a schema refusal is
/// checked localised on the bound record and returned in the vectors' form).
fn evidence_verdict(setup: &Setup, value: &Value, record: &Value, profile: &Value, endpoints: &Value, fixture: bool,
                    expected: Option<&str>, in_branch: &mut Vec<String>) -> Option<String> {
    match check_evidence(value, &setup.inventory, record, profile, endpoints, &setup.schema, fixture) {
        Ok(accepted) => {
            assert_eq!(accepted.fixture(), fixture);
            assert_eq!(Some(accepted.record_digest().to_string()), record_digest(record));
            assert_eq!(Some(accepted.evidence_digest().to_string()), record_digest(value));
            None
        }
        Err(EvidenceRefusal::W02a(Refusal::Schema)) => {
            let wanted = expected.expect("a schema refusal the vector expects");
            let rest = wanted.strip_prefix(W02A_PREFIX).and_then(|rest| rest.strip_prefix("schema ")).expect("an SC00 schema refusal");
            let (path, keyword) = rest.rsplit_once(' ').expect("schema <path> <keyword>");
            if !localised(&setup.v4_schema, "record", record, path, keyword) {
                assert!(localised_in_branch(&setup.v4_schema, "record", record, path, keyword), "{wanted} not localised");
                in_branch.push(wanted.to_string());
            }
            Some(wanted.to_string())
        }
        Err(refusal) => Some(refusal.text().unwrap_or_else(|| panic!("a refusal without text: {refusal:?}"))),
    }
}

fn evidence_result(setup: &Setup, row: &Value, expected: Option<&str>, in_branch: &mut Vec<String>) -> Option<String> {
    let (record, profile, endpoints) = bound(setup, row);
    let fixture = match fixture_flag(field(row, "testFixture")) {
        Ok(fixture) => fixture,
        Err(refusal) => return refusal.text(),
    };
    let value = apply(&rebound(&setup.evidence, &record), ops(row, "ops"));
    let before = in_branch.len();
    let verdict = evidence_verdict(setup, &value, &record, profile, endpoints, fixture, expected, in_branch);
    if in_branch.len() > before {
        in_branch.truncate(before);
        in_branch.push(text(row, "id").to_string());
    }
    verdict
}

fn snapshot_result(setup: &Setup, row: &Value) -> Option<String> {
    let snapshot = apply(field(&setup.vectors, "snapshotPositive"), ops(row, "ops"));
    let namespace = row.get("namespace").and_then(Value::as_str).unwrap_or_else(|| text(&setup.vectors, "qualificationNamespace"));
    setup.closure.check(&snapshot, namespace).err().map(|refusal| refusal.text().to_string())
}

#[test]
fn the_i06_v3_replay_makes_151_checks() {
    let setup = setup();
    let namespace = text(&setup.vectors, "qualificationNamespace");
    assert_eq!(namespace, "unit-namespace");
    let (record, profile, endpoints) = {
        let positive = &setup.positives[0];
        (field(positive, "record"), field(positive, "profile"), field(positive, "endpoints"))
    };
    // The positive is bound to native-profile v4 positive 0.
    assert_eq!(text(field(&setup.evidence, "w02aRecord"), "qualificationDigest"), record_digest(record).expect("digest"));
    let mut checks = 0usize;
    let mut in_branch: Vec<String> = Vec::new();
    assert_eq!(evidence_verdict(&setup, &setup.evidence, record, profile, endpoints, true, None, &mut in_branch), None);
    assert_eq!(evidence_verdict(&setup, &setup.evidence, record, profile, endpoints, false, None, &mut in_branch).as_deref(),
               Some("SC00 a test-only W02a backend qualifies only in an explicit fixture call"));
    assert_eq!(setup.closure.check(field(&setup.vectors, "snapshotPositive"), namespace).err().map(|refusal| refusal.text().to_string()), None);
    checks += 3;

    for row in list(&setup.vectors, "evidenceAccepted") {
        assert_eq!(field(row, "testFixture").as_bool(), Some(true));
        assert_eq!(evidence_result(&setup, row, None, &mut in_branch), None, "accepted {}", text(row, "id"));
        checks += 1;
    }
    for row in list(&setup.vectors, "snapshotAccepted") {
        assert_eq!(snapshot_result(&setup, row), None, "accepted snapshot {}", text(row, "id"));
        checks += 1;
    }
    let mut texts: BTreeMap<String, usize> = BTreeMap::new();
    let mut wrapped_schema = 0usize;
    for row in list(&setup.vectors, "evidenceNegative") {
        let refusal = text(row, "refusal");
        assert_eq!(evidence_result(&setup, row, Some(refusal), &mut in_branch).as_deref(), Some(refusal), "evidence {}", text(row, "id"));
        if refusal.starts_with(&format!("{W02A_PREFIX}schema ")) {
            wrapped_schema += 1;
        }
        *texts.entry(refusal.to_string()).or_default() += 1;
        checks += 1;
    }
    assert_eq!(list(&setup.vectors, "evidenceNegative").len(), 91);
    assert_eq!(wrapped_schema, 9, "the nine SC00-wrapped schema refusals, each localised");
    for row in list(&setup.vectors, "snapshotNegative") {
        let refusal = text(row, "refusal");
        assert_eq!(snapshot_result(&setup, row).as_deref(), Some(refusal), "snapshot {}", text(row, "id"));
        checks += 1;
    }
    assert_eq!(checks, 3 + 7 + 5 + 91 + 38);

    // Cross-version, the v3 halves (the v1 halves are I06 v1's, outside R10).
    let v2_positive = field(&parse(I06_V2_VECTORS), "evidencePositive").clone();
    let mut cross = 0usize;
    for row in list(&setup.vectors, "crossVersion") {
        let id = text(row, "id");
        let expected = field(row, "v3Result").as_str();
        let found = if text(row, "subject") == "snapshot" {
            snapshot_result(&setup, row)
        } else {
            let (bound_record, bound_profile, bound_endpoints) = bound(&setup, row);
            let mine = rebound(&setup.evidence, &bound_record);
            let subject = match text(row, "v3Subject") {
                "v3" => mine,
                "v2" => v2_positive.clone(),
                // I06 v1's positive is unregistered: its v1 shape built from the v3 positive.
                "v1" => {
                    let mut object = mine.as_object().expect("an object").clone();
                    object.remove(&i05_protocol::json::JStr::new("w02aRecord"));
                    with_member(&Value::Object(object), "schemaVersion", Value::str("planeon.internal.i06-distribution-evidence/v1"))
                }
                other => panic!("an unknown subject {other}"),
            };
            let production = field(row, "production").as_bool().expect("a production flag");
            let value = apply(&subject, ops(row, "ops"));
            let before = in_branch.len();
            let verdict = evidence_verdict(&setup, &value, &bound_record, bound_profile, bound_endpoints, !production, expected,
                                           &mut in_branch);
            if in_branch.len() > before {
                in_branch.truncate(before);
                in_branch.push(id.to_string());
            }
            verdict
        };
        assert_eq!(found.as_deref(), expected, "cross-version {id}");
        cross += 1;
    }
    assert_eq!(cross, 7);
    checks += cross;
    // The SC00-wrapped schema refusals localised only in the backend profile's one-branch oneOf (MODEL_DEFINED R145).
    assert_eq!(in_branch, IN_BRANCH.map(str::to_string), "the oneOf-branch localisations");
    assert_eq!(checks, 151);
}

/// The cases whose SC00-wrapped schema refusal is localised only in the backend profile's `oneOf` branch.
const IN_BRANCH: [&str; 8] = ["E60", "E61", "E70", "E71", "G09", "G10", "X03", "X04"];

#[test]
fn a_non_boolean_fixture_flag_refuses_and_a_boolean_passes() {
    for value in [Value::int(1), Value::Null, Value::str("true"), Value::Array(Vec::new())] {
        assert_eq!(fixture_flag(&value), Err(EvidenceRefusal::Rule("SC00 fixture flag must be a boolean")));
    }
    assert_eq!(fixture_flag(&Value::Bool(true)), Ok(true));
    assert_eq!(fixture_flag(&Value::Bool(false)), Ok(false));
}
