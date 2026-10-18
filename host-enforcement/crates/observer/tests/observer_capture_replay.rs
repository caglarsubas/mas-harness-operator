//! HE-004D1 DESIGN-D1 sections 6.3 and 15.2 (owner decision Q-HE4D1-11 (a); MODEL_DEFINED R122, R130): the replay of
//! native-profile v4's capture-family vectors through the R10 port: 229 negatives (each the pinned model text, or a
//! schema-step refusal localised by B1's walk, extended to resolve conditionals), 7 accepted cases, the 70 positive
//! captures, and the six cross-version cases (X09-X11: R10-built v3-shaped values; X12-X14: the positives' captures under
//! the vendored v3 schema, each `mustInclude` pair localised): 312 checks. The differential of section 6.3 item 4 (the
//! 125 schema refusals refused at the schema step, the other 111 and every positive capture and record valid) and every
//! count are asserted. The vectors and the v3 schema come in through `include_str!`.

mod b1_support;

use std::collections::BTreeMap;

use b1_support::apply;
use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::schema::Schema;
use planeon_observer::capture_check::{check_backend_capture, check_capture, check_lifecycle_capture, CheckedRecord, Refusal};
use planeon_observer::capture_schema::{rewrite_conditionals, CaptureSchema};
use planeon_observer::enrolled::{record_form, Enrolled, RecordBytes};
use planeon_observer::kernel_text;

const VECTORS: &str = include_str!("../../../contracts/native-profile-v4/vectors.json");
const V3_SCHEMA: &str = include_str!("../../../contracts/native-profile-v3/qualification.schema.json");
const V4_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v4/qualification.schema.json");

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

// ------------------------------------------------------------------------------------------------ localisation

#[derive(Clone, Debug)]
enum Step {
    Key(String),
    Index(usize),
}

/// jsonschema's `json_path`: `$`, then `.key` or `[index]` per element.
fn steps(path: &str) -> Vec<Step> {
    let rest = path.strip_prefix('$').expect("a JSON path starts with $");
    let bytes = rest.as_bytes();
    let (mut found, mut at) = (Vec::new(), 0);
    while at < bytes.len() {
        if bytes[at] == b'.' {
            let end = rest[at + 1..].find(['.', '[']).map_or(rest.len(), |offset| at + 1 + offset);
            found.push(Step::Key(rest[at + 1..end].to_string()));
            at = end;
        } else {
            let end = rest[at..].find(']').expect("a closing bracket") + at;
            found.push(Step::Index(rest[at + 1..end].parse().expect("an index")));
            at = end + 1;
        }
    }
    found
}

/// A one-off schema: `members` with the `$defs` of the walked schema.
fn one_off(members: Vec<(String, Value)>, defs: &Value) -> Schema {
    let mut root = Object::new();
    for (key, member) in members {
        root.insert(JStr::new(&key), member);
    }
    root.insert(JStr::new("$defs"), defs.clone());
    Schema::from_value(&Value::Object(root)).expect("a one-off schema loads")
}

fn members_of(node: &Value) -> Vec<(String, Value)> {
    node.as_object()
        .map(|object| object.iter().map(|(key, member)| (key.as_str().unwrap_or("").to_string(), member.clone())).collect())
        .unwrap_or_default()
}

/// The schema nodes that apply at one instance location: the node, what its `$ref` names, every `allOf` member, and
/// the branch of a conditional its `if` selects (evaluated with i05-protocol on a one-off schema of the `if`, whose
/// `$defs` are the loadable rewritten ones, `loadable`).
fn applicable<'a>(node: &'a Value, defs: &'a Value, loadable: &Value, instance: &Value, out: &mut Vec<&'a Value>) {
    if node.as_object().is_none() {
        return;
    }
    out.push(node);
    if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
        let name = reference.strip_prefix("#/$defs/").expect("a local reference");
        applicable(field(defs, name), defs, loadable, instance, out);
    }
    for member in node.get("allOf").and_then(Value::as_array).unwrap_or_default() {
        applicable(member, defs, loadable, instance, out);
    }
    if let Some(condition) = node.get("if") {
        let holds = one_off(members_of(condition), loadable).is_valid(instance);
        let branch = if holds { node.get("then") } else { node.get("else") };
        if let Some(branch) = branch {
            applicable(branch, defs, loadable, instance, out);
        }
    }
}

/// The nodes reached at the end of `path` from `node`, following `properties`, a schema-valued
/// `additionalProperties` and `items`.
fn reach<'a>(node: &'a Value, defs: &'a Value, loadable: &Value, instance: &Value, path: &[Step], out: &mut Vec<&'a Value>) {
    let mut here = Vec::new();
    applicable(node, defs, loadable, instance, &mut here);
    let Some((first, rest)) = path.split_first() else {
        out.extend(here);
        return;
    };
    for candidate in here {
        match first {
            Step::Key(key) => {
                let Some(sub) = instance.get(key) else { continue };
                match candidate.get("properties").and_then(|properties| properties.get(key)) {
                    Some(child) => reach(child, defs, loadable, sub, rest, out),
                    None => {
                        if let Some(extra) = candidate.get("additionalProperties").filter(|extra| extra.as_object().is_some()) {
                            reach(extra, defs, loadable, sub, rest, out);
                        }
                    }
                }
            }
            Step::Index(index) => {
                let Some(sub) = instance.as_array().and_then(|items| items.get(*index)) else { continue };
                if let Some(items) = candidate.get("items") {
                    reach(items, defs, loadable, sub, rest, out);
                }
            }
        }
    }
}

/// The value at `path` in `instance`.
fn locate<'a>(instance: &'a Value, path: &[Step]) -> &'a Value {
    path.iter().fold(instance, |node, step| match step {
        Step::Key(key) => field(node, key),
        Step::Index(index) => &node.as_array().expect("an array")[*index],
    })
}

/// B1's localisation rule, extended: walking the original schema, among the nodes at the path's end one holding
/// `keyword` refuses the sub-instance as a one-keyword schema built from that node (`additionalProperties` with the
/// node's `properties` names). One-off schemas carry the rewritten `$defs`, which i05-protocol loads.
fn localised(schema_root: &Value, variant: &str, instance: &Value, path: &str, keyword: &str) -> bool {
    let defs = field(schema_root, "$defs");
    let (rewritten, _) = rewrite_conditionals(schema_root).expect("the schema rewrites");
    let loadable = field(&rewritten, "$defs");
    let path = steps(path);
    let mut ends = Vec::new();
    reach(field(defs, variant), defs, loadable, instance, &path, &mut ends);
    let sub = locate(instance, &path);
    ends.iter().filter(|node| node.get(keyword).is_some()).any(|node| {
        let mut members = vec![(keyword.to_string(), field(node, keyword).clone())];
        if keyword == "additionalProperties" {
            let mut names = Object::new();
            for (name, _) in node.get("properties").and_then(Value::as_object).map(|object| object.iter().collect::<Vec<_>>())
                .unwrap_or_default()
            {
                names.insert(name.clone(), Value::Bool(true));
            }
            members.push(("properties".to_string(), Value::Object(names)));
        }
        !one_off(members, loadable).is_valid(sub)
    })
}

// ------------------------------------------------------------------------------------------------ the replay

#[test]
fn the_capture_family_replay_makes_312_checks() {
    let setup = setup();
    let v4_schema = json::parse(std::str::from_utf8(V4_SCHEMA).expect("ASCII")).expect("the v4 schema parses");
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
                    assert!(localised(&v4_schema, variant, &value, path, keyword), "negative {id}: {refusal} not localised");
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
    assert_eq!((count("negative", "capture"), count("negative", "lifecycle"), count("negative", "backend")), (199, 25, 5));
    assert_eq!((count("accepted", "capture"), count("accepted", "lifecycle"), count("accepted", "backend")), (5, 2, 0));
    assert_eq!(keywords.values().sum::<usize>(), 125);
    let keyword = |name: &str| keywords.get(name).copied().unwrap_or(0);
    assert_eq!((keyword("additionalProperties"), keyword("not"), keyword("required"), keyword("const"), keyword("uniqueItems")),
               (79, 31, 11, 3, 1));
    let family = |name: &str| schema_by_family.get(name).copied().unwrap_or(0);
    assert_eq!((family("capture"), family("lifecycle"), family("backend")), (119, 4, 2));
    let role = |name: &str| roles.get(name).copied().unwrap_or(0);
    assert_eq!((role("OBSERVER"), role("SERVER"), role("WORKER"), role("BROKER"), role("EFFECT_GATE")), (78, 48, 30, 26, 17));
    assert_eq!(passed_schema, 111, "104 model-message negatives and 7 accepted pass the schema step");
    assert_eq!(model_texts.len(), 37, "the 37 distinct pinned capture-family messages");
    assert_eq!(checks, 236);

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
    assert_eq!(checks, 306);

    // Cross-version: X09-X11 (R10-built v3-shaped values) and X12-X14 (v4 values under the vendored v3 schema).
    let v3 = json::parse(V3_SCHEMA).expect("the v3 schema parses");
    let mut cross = 0usize;
    for row in list(&setup.vectors, "crossVersion") {
        let index = field(row, "index").as_int().and_then(|int| int.to_u64()).expect("index") as usize;
        let positive = &list(&setup.vectors, "positive")[index];
        let record = &setup.records[index];
        let with_version = |value: &Value, version: &str| {
            let mut value = value.clone();
            if let Value::Object(object) = &mut value {
                object.insert(JStr::new("schemaVersion"), Value::str(version));
            }
            value
        };
        let server = &list(positive, "captures")[0];
        let lifecycle = field(positive, "lifecycle");
        let backend = &list(positive, "backendCaptures")[0];
        let (value, variant) = match text(row, "kind") {
            "V3_CAPTURE_UNDER_V4" => {
                let value = with_version(server, "planeon.internal.native-qualification-capture/v3");
                assert_eq!(check_capture(record, &value, "SERVER", &setup.schema), Err(Refusal::Model("not a v4 capture")));
                assert_eq!(text(row, "expect"), "not a v4 capture");
                cross += 1;
                continue;
            }
            "V3_LIFECYCLE_UNDER_V4" => {
                let value = with_version(lifecycle, "planeon.internal.native-qualification-lifecycle/v3");
                assert_eq!(check_lifecycle_capture(record, &value, &setup.schema), Err(Refusal::Model("not a v4 lifecycle capture")));
                assert_eq!(text(row, "expect"), "not a v4 lifecycle capture");
                cross += 1;
                continue;
            }
            "V3_BACKEND_CAPTURE_UNDER_V4" => {
                let value = with_version(backend, "planeon.internal.native-qualification-backend/v3");
                assert_eq!(check_backend_capture(record, &value, &setup.schema), Err(Refusal::Model("not a v4 backend capture")));
                assert_eq!(text(row, "expect"), "not a v4 backend capture");
                cross += 1;
                continue;
            }
            "V4_CAPTURE_UNDER_V3" => (server.clone(), "capture"),
            "V4_LIFECYCLE_UNDER_V3" => (lifecycle.clone(), "lifecycleCapture"),
            "V4_BACKEND_CAPTURE_UNDER_V3" => (backend.clone(), "backendCapture"),
            _ => continue,
        };
        let mut root = Object::new();
        root.insert(JStr::new("$ref"), Value::str(&format!("#/$defs/{variant}")));
        root.insert(JStr::new("$defs"), field(&v3, "$defs").clone());
        let validator = Schema::from_value(&Value::Object(root)).expect("the v3 schema loads unchanged");
        assert!(!validator.is_valid(&value), "{} is invalid under v3", text(row, "id"));
        for pair in list(row, "mustInclude") {
            let pair = pair.as_array().expect("a pair");
            let (path, keyword) = (pair[0].as_str().expect("path"), pair[1].as_str().expect("keyword"));
            assert!(localised(&v3, variant, &value, path, keyword), "{} {path} {keyword}", text(row, "id"));
        }
        cross += 1;
    }
    assert_eq!(cross, 6);
    checks += cross;
    assert_eq!(checks, 312);
}
