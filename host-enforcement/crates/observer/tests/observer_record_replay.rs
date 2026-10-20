//! HE-004D2 DESIGN-D2 sections 5 and 11, phase A (MODEL_DEFINED R139, R145): the replay of native-profile v4's record
//! family through `record_check::check_record`: 196 negatives (127 pinned model texts, 69 best-match schema refusals each
//! localised by the shared rule), 11 accepted cases, and the cross-version cases X05-X08 and X15 (the v4 positives'
//! records under the vendored v3 schema, each `mustInclude` pair localised) and, from phase B, X01-X04 (the v3 vectors'
//! positive records under v4, which edge record v7 registers; the model's own replay reads them, D2-2): 216 checks.
//! Every count is asserted.

mod b1_support;
mod d2_support;
mod schema_support;

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use d2_support::{field, list, parse, positive_records, record_case, text, V3_SCHEMA, V3_VECTORS, V4_SCHEMA, V4_VECTORS};
use i05_protocol::json::Value;
use planeon_observer::capture_check::Refusal;
use planeon_observer::capture_schema::{CaptureSchema, RecordSchema};
use planeon_observer::record_check::check_record;
use schema_support::{localised, localised_in_branch, variant_validator};

fn record_schema() -> RecordSchema {
    CaptureSchema::embedded().expect("the embedded schema loads").1
}

#[test]
fn the_record_family_replay_makes_216_checks() {
    let vectors = parse(V4_VECTORS);
    let v4_schema = parse(V4_SCHEMA);
    let schema = record_schema();
    let positives = list(&vectors, "positive");
    let mut checks = 0usize;
    let mut model_texts: BTreeMap<String, usize> = BTreeMap::new();
    let mut schema_texts: BTreeMap<String, usize> = BTreeMap::new();
    let mut accepted = 0usize;
    let mut in_branch: BTreeSet<String> = BTreeSet::new();

    // Every positive's record is accepted on its own (not counted: the positives are checked whole by the qualification
    // replay).
    for (number, positive) in positives.iter().enumerate() {
        let verdict = check_record(field(positive, "record"), field(positive, "profile"), field(positive, "endpoints"), &schema);
        assert!(verdict.is_ok(), "positive {number}: {:?}", verdict.err());
    }

    for group in ["negative", "accepted"] {
        for row in list(&vectors, group) {
            if text(row, "target") != "record" {
                continue;
            }
            let id = text(row, "id");
            let (record, profile, endpoints) = record_case(positives, row);
            let verdict = check_record(&record, &profile, &endpoints, &schema).map(|_| ());
            if group == "accepted" {
                assert_eq!(verdict, Ok(()), "accepted {id}");
                accepted += 1;
            } else {
                let refusal = text(row, "refusal");
                if let Some(rest) = refusal.strip_prefix("schema ") {
                    let (path, keyword) = rest.rsplit_once(' ').expect("schema <path> <keyword>");
                    assert_eq!(verdict, Err(Refusal::Schema), "negative {id}: {refusal}");
                    if !localised(&v4_schema, "record", &record, path, keyword) {
                        assert!(localised_in_branch(&v4_schema, "record", &record, path, keyword), "negative {id}: {refusal} not localised");
                        in_branch.insert(id.to_string());
                    }
                    *schema_texts.entry(refusal.to_string()).or_default() += 1;
                } else {
                    assert_eq!(verdict, Err(Refusal::Model(refusal_static(refusal))), "negative {id}");
                    // Every model refusal but the v4 identity (checked before the shape step) meets a schema-valid record.
                    assert_eq!(schema.is_valid(&record), refusal != "not a v4 record", "negative {id}: the shape step's place");
                    *model_texts.entry(refusal.to_string()).or_default() += 1;
                }
            }
            checks += 1;
        }
    }
    assert_eq!((model_texts.len(), model_texts.values().sum::<usize>()), (44, 127), "Appendix A.1");
    assert_eq!((schema_texts.len(), schema_texts.values().sum::<usize>()), (56, 69), "Appendix A.2");
    assert_eq!(model_texts.get("enrolled boot entry outside the closed kernel parameters"), Some(&41));
    assert_eq!(model_texts.get("maintenance boot entry outside the closed kernel parameters"), Some(&5));
    assert_eq!(accepted, 11);
    // The refusals localised only inside the backend profile's one-branch oneOf (DESIGN-D2 section 11's fallback list).
    assert_eq!(in_branch.iter().map(String::as_str).collect::<Vec<_>>(), IN_BRANCH, "the oneOf-branch localisations");
    assert_eq!(checks, 207);

    // Cross-version X05-X08 and X15: each v4 positive's record under the vendored v3 schema, every mustInclude pair
    // localised; X01-X04: the v3 vectors' positive record of that index under check_record, with the v4 positive's
    // profile and endpoints (the model's `histories[2][index]`).
    let v3 = parse(V3_SCHEMA);
    let v3_record = variant_validator(&v3, "record");
    let v3_records = positive_records(V3_VECTORS);
    let mut cross = BTreeSet::new();
    for row in list(&vectors, "crossVersion") {
        let id = text(row, "id");
        match text(row, "kind") {
            "V4_RECORD_UNDER_V3" => {
                let record = field(&positives[d2_support::index(row, "index")], "record");
                assert!(!v3_record.is_valid(record), "{id}: a v4 record is invalid under v3");
                let pairs = list(row, "mustInclude");
                assert_eq!(pairs.len(), 2, "{id}");
                for pair in pairs {
                    let pair = pair.as_array().expect("a pair");
                    let (path, keyword) = (pair[0].as_str().expect("a path"), pair[1].as_str().expect("a keyword"));
                    assert!(localised(&v3, "record", record, path, keyword), "{id} {path} {keyword}");
                }
                cross.insert(id.to_string());
            }
            "V3_RECORD_UNDER_V4" => {
                assert_eq!(text(row, "expect"), "not a v4 record");
                let positive = &positives[d2_support::index(row, "index")];
                let old = &v3_records[d2_support::index(row, "index")];
                let verdict = check_record(old, field(positive, "profile"), field(positive, "endpoints"), &schema).map(|_| ());
                assert_eq!(verdict, Err(Refusal::Model("not a v4 record")), "{id}");
                cross.insert(id.to_string());
            }
            _ => {}
        }
    }
    assert_eq!(cross.iter().map(String::as_str).collect::<Vec<_>>(), ["X01", "X02", "X03", "X04", "X05", "X06", "X07", "X08",
                                                                       "X15"]);
    checks += cross.len();
    assert_eq!(checks, 216);
}

#[test]
fn a_value_that_is_not_a_v4_record_refuses_first() {
    let vectors = parse(V4_VECTORS);
    let schema = record_schema();
    let positive = &list(&vectors, "positive")[0];
    let (profile, endpoints) = (field(positive, "profile"), field(positive, "endpoints"));
    let record = field(positive, "record");
    let other = d2_support::with_member(record, "schemaVersion", Value::str("planeon.internal.native-qualification/v3"));
    for value in [Value::Null, Value::Array(Vec::new()), Value::str("record"), other] {
        assert_eq!(check_record(&value, profile, endpoints, &schema).map(|_| ()), Err(Refusal::Model("not a v4 record")));
    }
    // The accepted record carries the canonical digest of the record (the configuration's pin form).
    let accepted = check_record(record, profile, endpoints, &schema).expect("positive 0");
    assert_eq!(accepted.record().digest(), d2_support::canonical_digest(record));
    assert!(i05_protocol::json::py_eq(accepted.record().value(), record));
}

/// The record negatives whose refusal is localised only in the backend profile's `oneOf` branch (MODEL_DEFINED R145).
const IN_BRANCH: [&str; 4] = ["R58", "R59", "V25", "V28"];

/// The pinned texts as `'static` strings (the refusal type holds static text), shortest first: the vector's text is
/// matched against this closed list, so an unknown text fails the replay.
fn refusal_static(found: &str) -> &'static str {
    const PINNED: [&str; 44] = [
        "not a v4 record",
        "artifact custody",
        "backend API identity",
        "broker network grant",
        "unowned planeon code",
        "worker network grant",
        "gate endpoints differ",
        "duplicate cgroup inode",
        "server endpoints differ",
        "observer endpoints differ",
        "more than one node identity",
        "lifecycle subjects share code",
        "role executables share content",
        "backend cgroup outside cgroupfs",
        "duplicate signed endpoint tuple",
        "code shared across owner classes",
        "backend components share a cgroup",
        "seal marker does not bind this boot",
        "program pin outside the sealed layout",
        "program shared between hooks or roles",
        "backend components share an executable",
        "role executable equal to an interpreter",
        "backend component inside the planeon slice",
        "role closure lists another role's executable",
        "native-only role closure lists an interpreter",
        "enrolled boot entry without lockdown=integrity",
        "loopback apiserver endpoint must stay internal",
        "backend cgroup nested in another backend cgroup",
        "profile resource labels differ from the binding",
        "interpreter type outside the interpreted closures",
        "static native role closure is its executable alone",
        "CAP_NET_BIND_SERVICE only for a signed port below 1024",
        "enrolled and maintenance boot entries indistinguishable",
        "enrolled boot entry outside the closed kernel parameters",
        "backend components differ from the implementation profile",
        "maintenance boot entry names the maintenance target twice",
        "maintenance boot entry outside the closed kernel parameters",
        "entrypoint file label differs from the role's entrypoint type",
        "maintenance boot entry does not select the maintenance target",
        "backend executable label differs from the component's exec type",
        "interpreter closure file outside the dedicated interpreter type",
        "entrypoint type labels a file other than its subject's executable",
        "EFFECT_GATE holds no capability and its signed I04 port is 1024 or above",
        "maintenance boot entry differs from the enrolled entry beyond the maintenance unit",
    ];
    PINNED.iter().copied().find(|text| *text == found).unwrap_or_else(|| panic!("an unlisted pinned text: {found}"))
}
