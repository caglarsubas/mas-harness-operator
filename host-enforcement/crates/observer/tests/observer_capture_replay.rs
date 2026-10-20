//! HE-004D1 DESIGN-D1 sections 6.3 and 15.2 (owner decision Q-HE4D1-11 (a); MODEL_DEFINED R122, R130), moved onto
//! native-profile v5 by HE-004D2's unit B1 (DESIGN-D2 section 4.4; Amendment A2): the replay of native-profile v5's
//! capture-family vectors through the R10 port: 247 negatives (each the pinned model text, or a schema-step refusal
//! localised by B1's walk, extended to resolve conditionals, now in `schema_support`), 7 accepted cases, the 70 positive
//! captures, and the six cross-version cases (X09-X11: native-profile v4's positive captures under the v5 checks; X12-X14:
//! the v5 positives' captures under the vendored v4 schema, each `mustInclude` pair localised): 330 checks. The
//! differential (the 148 schema refusals refused at the schema step, the other 106 and every positive capture and record
//! valid) and every count are asserted. The vectors and the v4 schema come in through `include_str!`.

mod b1_support;
mod schema_support;

use std::collections::BTreeMap;

use b1_support::apply;
use i05_protocol::json::{self, Value};
use planeon_observer::capture_check::{check_backend_capture, check_capture, check_lifecycle_capture, CheckedRecord, Refusal};
use planeon_observer::capture_schema::{rewrite_conditionals, CaptureSchema};
use planeon_observer::enrolled::{record_form, Enrolled, RecordBytes};
use planeon_observer::kernel_text;
use schema_support::localised;

const VECTORS: &str = include_str!("../../../contracts/native-profile-v5/vectors.json");
const V4_VECTORS: &str = include_str!("../../../contracts/native-profile-v4/vectors.json");
const V4_SCHEMA: &str = include_str!("../../../contracts/native-profile-v4/qualification.schema.json");
const V5_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v5/qualification.schema.json");

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or_else(|| panic!("missing {key}"))
}

fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    field(value, key).as_array().unwrap_or_else(|| panic!("{key} is not a list"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key).as_str().unwrap_or_else(|| panic!("{key} is not text"))
}

struct Setup {
    vectors: Value,
    schema: CaptureSchema,
    records: Vec<CheckedRecord>,
}

fn setup() -> Setup {
    let vectors = json::parse(VECTORS).expect("the vectors parse");
    let (schema, record_schema) = CaptureSchema::embedded().expect("the embedded schema");
    let now = kernel_text::utc_seconds("2026-09-08T00:00:00Z");
    let records = list(&vectors, "positive")
        .iter()
        .map(|positive| {
            let record = field(positive, "record");
            assert!(record_schema.is_valid(record), "a positive record is valid");
            let bytes = json::canonical(record).expect("canonical");
            let value = record_form(&bytes).expect("canonical form");
            let pin = i05_protocol::sha256::prefixed(&bytes);
            Enrolled::new(RecordBytes { bytes, value, pin }, &record_schema, now).expect("a positive enrolls").record
        })
        .collect();
    Setup { vectors, schema, records }
}

/// One capture-family case's verdict and the value it judged.
fn judge(setup: &Setup, row: &Value) -> (Result<(), Refusal>, Value, &'static str) {
    let index = field(row, "positive").as_int().and_then(|int| int.to_u64()).expect("a positive index") as usize;
    let positive = &list(&setup.vectors, "positive")[index];
    let record = &setup.records[index];
    let ops = list(row, "ops");
    match text(row, "target") {
        "capture" => {
            let role = text(row, "role");
            let base = list(positive, "captures").iter().find(|capture| text(capture, "role") == role).expect("the role");
            let capture = apply(base, ops);
            (check_capture(record, &capture, role, &setup.schema), capture, "capture")
        }
        "lifecycle" => {
            let capture = apply(field(positive, "lifecycle"), ops);
            (check_lifecycle_capture(record, &capture, &setup.schema), capture, "lifecycleCapture")
        }
        "backend" => {
            let component = text(row, "component");
            let base = list(positive, "backendCaptures").iter().find(|capture| text(capture, "component") == component)
                .expect("the component");
            let capture = apply(base, ops);
            (check_backend_capture(record, &capture, &setup.schema), capture, "backendCapture")
        }
        other => panic!("not a capture family: {other}"),
    }
}

// ------------------------------------------------------------------------------------------------ the replay

#[test]
fn the_capture_family_replay_makes_330_checks() {
    let setup = setup();
    let v5_schema = json::parse(std::str::from_utf8(V5_SCHEMA).expect("ASCII")).expect("the v5 schema parses");
    let mut checks = 0usize;
    let mut families: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut keywords: BTreeMap<String, usize> = BTreeMap::new();
    let mut schema_by_family: BTreeMap<String, usize> = BTreeMap::new();
    let mut roles: BTreeMap<String, usize> = BTreeMap::new();
    let (mut model_texts, mut passed_schema) = (std::collections::BTreeSet::new(), 0usize);
    for group in ["negative", "accepted"] {
        for row in list(&setup.vectors, group) {
            let target = text(row, "target");
            if !["capture", "lifecycle", "backend"].contains(&target) {
                continue;
            }
            *families.entry((group.to_string(), target.to_string())).or_default() += 1;
            let id = text(row, "id");
            let (verdict, value, variant) = judge(&setup, row);
            if group == "accepted" {
                assert_eq!(verdict, Ok(()), "accepted {id}");
                passed_schema += 1;
            } else {
                let refusal = text(row, "refusal");
                if target == "capture" {
                    *roles.entry(text(row, "role").to_string()).or_default() += 1;
                }
                if let Some(rest) = refusal.strip_prefix("schema ") {
                    let (path, keyword) = rest.rsplit_once(' ').expect("schema <path> <keyword>");
                    assert_eq!(verdict, Err(Refusal::Schema), "negative {id}: {refusal}");
                    assert!(localised(&v5_schema, variant, &value, path, keyword), "negative {id}: {refusal} not localised");
                    *keywords.entry(keyword.to_string()).or_default() += 1;
                    *schema_by_family.entry(target.to_string()).or_default() += 1;
                } else {
                    assert!(matches!(verdict, Err(Refusal::Model(found)) if found == refusal), "negative {id}: {verdict:?}");
                    model_texts.insert(refusal.to_string());
                    passed_schema += 1;
                    let valid = match variant {
                        "capture" => setup.schema.capture_valid(&value),
                        "lifecycleCapture" => setup.schema.lifecycle_valid(&value),
                        _ => setup.schema.backend_valid(&value),
                    };
                    assert!(valid, "negative {id}: a model refusal's value passes the rewritten schema");
                }
            }
            checks += 1;
        }
    }
    let count = |kind: &str, target: &str| families.get(&(kind.to_string(), target.to_string())).copied().unwrap_or(0);
    assert_eq!((count("negative", "capture"), count("negative", "lifecycle"), count("negative", "backend")), (211, 29, 7));
    assert_eq!((count("accepted", "capture"), count("accepted", "lifecycle"), count("accepted", "backend")), (5, 2, 0));
    assert_eq!(keywords.values().sum::<usize>(), 148);
    let keyword = |name: &str| keywords.get(name).copied().unwrap_or(0);
    assert_eq!((keyword("additionalProperties"), keyword("not"), keyword("required"), keyword("const"), keyword("uniqueItems")),
               (102, 31, 11, 3, 1));
    let family = |name: &str| schema_by_family.get(name).copied().unwrap_or(0);
    assert_eq!((family("capture"), family("lifecycle"), family("backend")), (134, 10, 4));
    let role = |name: &str| roles.get(name).copied().unwrap_or(0);
    assert_eq!((role("OBSERVER"), role("SERVER"), role("WORKER"), role("BROKER"), role("EFFECT_GATE")), (81, 51, 32, 28, 19));
    assert_eq!(passed_schema, 106, "99 model-message negatives and 7 accepted pass the schema step");
    assert_eq!(model_texts.len(), 35, "the 35 distinct pinned capture-family messages");
    assert_eq!(checks, 254);

    // The 70 positive captures, each checked individually.
    for (index, positive) in list(&setup.vectors, "positive").iter().enumerate() {
        let record = &setup.records[index];
        for capture in list(positive, "captures") {
            assert!(setup.schema.capture_valid(capture));
            assert_eq!(check_capture(record, capture, text(capture, "role"), &setup.schema), Ok(()), "positive {index}");
            checks += 1;
        }
        let lifecycle = field(positive, "lifecycle");
        assert!(setup.schema.lifecycle_valid(lifecycle));
        assert_eq!(check_lifecycle_capture(record, lifecycle, &setup.schema), Ok(()), "positive {index} lifecycle");
        checks += 1;
        for capture in list(positive, "backendCaptures") {
            assert!(setup.schema.backend_valid(capture));
            assert_eq!(check_backend_capture(record, capture, &setup.schema), Ok(()), "positive {index} backend");
            checks += 1;
        }
    }
    assert_eq!(checks, 324);

    // Cross-version: X09-X11 (native-profile v4's positive captures under the v5 checks) and X12-X14 (the v5 positives'
    // captures under the vendored v4 schema).
    let v4_vectors = json::parse(V4_VECTORS).expect("the v4 vectors parse");
    let v4 = json::parse(V4_SCHEMA).expect("the v4 schema parses");
    let mut cross = 0usize;
    for row in list(&setup.vectors, "crossVersion") {
        let index = field(row, "index").as_int().and_then(|int| int.to_u64()).expect("index") as usize;
        let positive = &list(&setup.vectors, "positive")[index];
        let old = &list(&v4_vectors, "positive")[index];
        let record = &setup.records[index];
        let (value, variant) = match text(row, "kind") {
            "V4_CAPTURE_UNDER_V5" => {
                let value = &list(old, "captures")[0];
                assert_eq!(check_capture(record, value, "SERVER", &setup.schema), Err(Refusal::Model("not a v5 capture")));
                assert_eq!(text(row, "expect"), "not a v5 capture");
                cross += 1;
                continue;
            }
            "V4_LIFECYCLE_UNDER_V5" => {
                assert_eq!(check_lifecycle_capture(record, field(old, "lifecycle"), &setup.schema),
                           Err(Refusal::Model("not a v5 lifecycle capture")));
                assert_eq!(text(row, "expect"), "not a v5 lifecycle capture");
                cross += 1;
                continue;
            }
            "V4_BACKEND_CAPTURE_UNDER_V5" => {
                assert_eq!(check_backend_capture(record, &list(old, "backendCaptures")[0], &setup.schema),
                           Err(Refusal::Model("not a v5 backend capture")));
                assert_eq!(text(row, "expect"), "not a v5 backend capture");
                cross += 1;
                continue;
            }
            "V5_CAPTURE_UNDER_V4" => (list(positive, "captures")[0].clone(), "capture"),
            "V5_LIFECYCLE_UNDER_V4" => (field(positive, "lifecycle").clone(), "lifecycleCapture"),
            "V5_BACKEND_CAPTURE_UNDER_V4" => (list(positive, "backendCaptures")[0].clone(), "backendCapture"),
            other => panic!("an unknown cross-version kind {other}"),
        };
        let (loadable, _) = rewrite_conditionals(&v4).expect("the v4 schema rewrites");
        let validator = schema_support::variant_validator(&loadable, variant);
        assert!(!validator.is_valid(&value), "{} is invalid under v4", text(row, "id"));
        let pairs = list(row, "mustInclude");
        assert_eq!(pairs.len(), 2, "{}: the version const and the dropped required fields", text(row, "id"));
        for pair in pairs {
            let pair = pair.as_array().expect("a pair");
            let (path, keyword) = (pair[0].as_str().expect("path"), pair[1].as_str().expect("keyword"));
            assert!(localised(&v4, variant, &value, path, keyword), "{} {path} {keyword}", text(row, "id"));
        }
        cross += 1;
    }
    assert_eq!(cross, 6);
    checks += cross;
    assert_eq!(checks, 330);
}
