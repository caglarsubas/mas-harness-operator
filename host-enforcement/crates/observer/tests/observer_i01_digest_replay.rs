//! HE-004-I01B1, its first part (DESIGN-I01B rev 3 section 2 and DESIGN-I01B1 rev 2; owner decision Q-HE4I1-2 and the
//! monitor's Q-I01B-26 (a)): the I01 digest contract's vectors (`contracts/i01-digests-v1/vectors.json`, edge record
//! v10's row 70) replayed against `i01_digest`, each vector's own expectations compared one by one.
//!
//! - The four vendored files are edge record v10's rows 69-72 (each sha256 and size). `definitions.json` is the
//!   contract the vectors pin (their `contract.canonicalSha256`), and `i01_digest`'s refusal texts are its
//!   `refusalTexts`, all 90.
//! - The design's counts: 16 helper vectors (canonical bytes, digests, the exactness bounds) and 152 vectors. Each
//!   vector is built as the model builds it (its fixtures, then its operations), and B1's list inputs are made from its
//!   lists, each list as the apiserver serves it under its closed-set request.
//! - Compared: every projection's digest and, where the vector pins them, its identity, document, canonical bytes and
//!   resourceVersion, or its refusal text; every enforcement digest and its pinned document, or its refusal; every
//!   digest relation (`same`, `differs`) between two compared values; the definitions pin.
//! - Deferred to HE-004-I01B1's second part, each counted and asserted here: what needs the A2 render
//!   (`admissionPolicy` and `admissionFenceDigest` once their sealed values pass: the render handed in records that it
//!   was asked and renders nothing), the capture gate verdicts (69, with the vectors' ms values as the ages), the
//!   answer refusal lists (12), the relations over a deferred value (5) and the complete I01 positive (5 checks).
//! - One vector's lists never reach a digest: RB-17 deletes a ClusterRole's name, and B1's `Inputs::new` refuses the
//!   lists (ItemShape, ClusterRoles item 1) before either RBAC value is derived. The vector pins the producer's text,
//!   "rbac: malformed metadata", which the observer cannot reach; the replay asserts the earlier refusal for both of
//!   its checks.
//!
//! Of the model's 320 checks (16 helper checks, the definitions pin, 120 projection, 46 enforcement, 69 gate, 12 answer
//! and 51 relation checks, and the complete positive's 5), 208 are compared here, 110 are deferred and 2 are refused
//! earlier by B1's inputs.

mod b1_support;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use b1_support::apply;
use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::sha256;
use planeon_observer::i01_digest::{self, DigestKey, DigestSnapshot, EnforcementValue, ProjectionValue, Rendered,
                                   SealedAdmission, B1_MALFORMED, CLOSURE_VERSION, SCHEMA_VERSION};
use planeon_observer::inputs::{InputError, Inputs, ListBody, ListInput, Resource};
use planeon_observer::snapshot::Closure;

const DEFINITIONS: &[u8] = include_bytes!("../../../contracts/i01-digests-v1/definitions.json");
const VECTORS: &[u8] = include_bytes!("../../../contracts/i01-digests-v1/vectors.json");
const README: &[u8] = include_bytes!("../../../contracts/i01-digests-v1/README.md");
const PROXY_VECTORS: &[u8] = include_bytes!("../../../contracts/i01-v1/proxy-contract-vectors.json");
/// Edge record v10's rows 69-72: each vendored file's bytes, sha256 and size.
const ROWS: [(&str, &[u8], &str, usize); 4] = [
    ("i01-digests-v1/definitions.json", DEFINITIONS, "086692065cfc9da101f770fa39c50af2e2650a169595526e9860fc805478c2aa",
     35_940),
    ("i01-digests-v1/vectors.json", VECTORS, "bd9f04bd04fcccc584bcab341ec649bcead567fe349c57e30958eaaf2ea64f84",
     468_843),
    ("i01-digests-v1/README.md", README, "e393dd11c75f527829bb6522c5643cb593b6dc67e2788f5e280ce9de0f4166ae", 46_944),
    ("i01-v1/proxy-contract-vectors.json", PROXY_VECTORS,
     "edf32ddf992e06e8786fd331affdb4d2ecd5538ca874d52c37439386793a8eb7", 12_799),
];
/// The design's counts (DESIGN-I01B rev 3 section 1): 152 vectors and 16 helper vectors.
const VECTOR_COUNT: usize = 152;
const HELPER_COUNT: usize = 16;
/// The complete I01 positive's checks (the model's `_check_complete`), all deferred.
const COMPLETE_CHECKS: usize = 5;
/// The contract's eleven snapshot lists and B1's closed-set entry for each.
const LISTS: [(&str, Resource); 11] = [
    ("namespaces", Resource::Namespaces),
    ("resourceQuotas", Resource::ResourceQuotas),
    ("limitRanges", Resource::LimitRanges),
    ("serviceAccounts", Resource::ServiceAccounts),
    ("networkPolicies", Resource::NetworkPolicies),
    ("roles", Resource::Roles),
    ("roleBindings", Resource::RoleBindings),
    ("clusterRoles", Resource::ClusterRoles),
    ("clusterRoleBindings", Resource::ClusterRoleBindings),
    ("validatingAdmissionPolicies", Resource::ValidatingAdmissionPolicies),
    ("validatingAdmissionPolicyBindings", Resource::ValidatingAdmissionPolicyBindings),
];
/// The model's closed forms, sorted: the vectors document, a vector, an expectation, the complete positive.
const VECTOR_MEMBERS: [&str; 9] = ["complete", "contract", "evidenceClass", "fixtures", "helpers", "nativeAcceptance",
                                   "schemaVersion", "sources", "vectors"];
const ROW_MEMBERS: [&str; 7] = ["binding", "capture", "case", "expect", "id", "ops", "snapshot"];
const EXPECT_MEMBERS: [&str; 6] = ["differs", "enforcement", "gates", "observation", "projections", "same"];
const COMPLETE_MEMBERS: [&str; 10] = ["binding", "capture", "case", "now", "observation", "previous", "profile",
                                      "replaced", "request", "snapshot"];

fn parse(raw: &[u8]) -> Value {
    json::parse(std::str::from_utf8(raw).expect("the vendored file is UTF-8")).expect("the vendored JSON parses")
}

fn member<'a>(value: &'a Value, name: &str) -> &'a Value {
    value.get(name).unwrap_or_else(|| panic!("{name} is missing"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    member(value, name).as_str().unwrap_or_else(|| panic!("{name} is not text"))
}

fn array<'a>(value: &'a Value, name: &str) -> &'a [Value] {
    member(value, name).as_array().unwrap_or_else(|| panic!("{name} is not an array"))
}

fn object(value: &Value) -> &Object {
    value.as_object().expect("an object")
}

/// An object's member names in document order.
fn names_in_order(value: &Value) -> Vec<&str> {
    object(value).iter().map(|(name, _)| name.as_str().expect("a text member name")).collect()
}

/// An object's member names, sorted.
fn names(value: &Value) -> Vec<&str> {
    let mut names = names_in_order(value);
    names.sort_unstable();
    names
}

fn hex(data: &[u8]) -> String {
    sha256::hex(&sha256::digest(data))
}

/// Lowercase hexadecimal text as bytes.
fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "hex text of whole bytes");
    (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digits")).collect()
}

/// A helper vector's input: `{"$fill": n}` stands for a string of n `a` characters (the model's `_expand`).
fn expand(value: &Value) -> Value {
    match value {
        Value::Object(members) => {
            if let (1, Some(Value::Int(count))) = (members.len(), members.get("$fill")) {
                let count = usize::try_from(count.to_u64().expect("a fill count")).expect("a fill count");
                return Value::str(&"a".repeat(count));
            }
            let mut out = Object::new();
            for (name, member) in members.iter() {
                out.insert(name.clone(), expand(member));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(expand).collect()),
        other => other.clone(),
    }
}

/// The helper vectors, as the model replays them: canonical bytes as hex, SHA-256 of hex bytes, `projection_digest`,
/// and the exactness rule under resourceQuota's texts. Each vector's id is recorded; the number replayed.
fn replay_helpers(vectors: &Value, ids: &mut Vec<String>) -> usize {
    let helpers = array(vectors, "helpers");
    for row in helpers {
        assert_eq!(names(row), ["case", "expect", "function", "id", "input"], "a closed helper vector");
        let id = text(row, "id");
        ids.push(id.to_string());
        let input = expand(member(row, "input"));
        let got = match text(row, "function") {
            "canonical" => Value::str(&sha256::hex(&json::canonical(&input).expect("canonical bytes"))),
            "digest" => Value::str(&hex(&unhex(input.as_str().expect("hex text")))),
            "projection_digest" => Value::str(&i01_digest::projection_digest(&input).expect("a digest")),
            "bound" => match i01_digest::exact(DigestKey::ResourceQuota, &input) {
                Ok(()) => Value::Null,
                Err(refusal) => Value::str(refusal),
            },
            other => panic!("helper vector {id}: no helper function {other}"),
        };
        assert!(json::json_eq(&got, member(row, "expect")), "helper vector {id}: {got:?}");
    }
    helpers.len()
}

/// A vector's inputs as the model builds them: the named snapshot fixture with the enrolled record, the named binding
/// and capture, then the vector's operations applied in order.
fn combined(fixtures: &Value, row: &Value) -> Value {
    let mut snapshot = member(member(fixtures, "snapshots"), text(row, "snapshot")).clone();
    match &mut snapshot {
        Value::Object(members) => members.insert(JStr::new("record"), member(fixtures, "record").clone()),
        _ => panic!("a snapshot fixture is an object"),
    }
    let mut members = Object::new();
    members.insert(JStr::new("snapshot"), snapshot);
    members.insert(JStr::new("binding"), member(member(fixtures, "bindings"), text(row, "binding")).clone());
    members.insert(JStr::new("capture"), member(member(fixtures, "captures"), text(row, "capture")).clone());
    apply(&Value::Object(members), array(row, "ops"))
}

/// B1's list inputs for a snapshot's lists: each list as the apiserver serves it (its list kind and apiVersion, a
/// complete list's metadata, the items), paired with its closed-set request.
fn list_inputs(lists: &Value) -> Vec<ListInput> {
    assert!(names(lists).iter().all(|name| LISTS.iter().any(|(list, _)| list == name)), "only the contract's lists");
    LISTS
        .iter()
        .filter_map(|&(name, resource)| {
            let items = lists.get(name)?;
            let (kind, api_version) = resource.list_kind();
            let mut list = Object::new();
            list.insert(JStr::new("kind"), Value::str(&kind));
            list.insert(JStr::new("apiVersion"), Value::str(&api_version));
            list.insert(JStr::new("metadata"), Value::Object(Object::new()));
            list.insert(JStr::new("items"), items.clone());
            Some(ListInput { spec: resource.spec(), body: ListBody::Served(Value::Object(list)) })
        })
        .collect()
}

/// An expectation's member of keyed values (`projections`, `enforcement`, `gates`, `same`, `differs`): each key's
/// name, the contract key and the value.
fn keyed<'a>(expect: &'a Value, kind: &str) -> Vec<(&'a str, DigestKey, &'a Value)> {
    let Some(found) = expect.get(kind) else {
        return Vec::new();
    };
    object(found)
        .iter()
        .map(|(name, want)| {
            let name = name.as_str().expect("a text key");
            (name, DigestKey::of_name(name).unwrap_or_else(|| panic!("{name} is not a contract key")), want)
        })
        .collect()
}

/// A refusal compared with the expectation, which must be exactly `{"refusal": <text>}`.
fn compare_refusal(at: &str, want: &Value, refusal: &str) {
    assert_eq!(want.get("refusal").and_then(Value::as_str), Some(refusal), "{at}: refusal");
    assert_eq!(object(want).len(), 1, "{at}: a refusal is the expectation's one member");
}

/// A projection compared with the vector's expectation (the model's checks): its refusal, or its digest and every
/// pinned identity, document, canonical text and resourceVersion. The digest, when there is one.
fn compare_projection(at: &str, want: &Value, outcome: Result<ProjectionValue, &'static str>) -> Option<String> {
    let value = match outcome {
        Ok(value) => value,
        Err(refusal) => {
            compare_refusal(at, want, refusal);
            return None;
        }
    };
    assert!(want.get("refusal").is_none(), "{at}: derived, but the vector refuses with {:?}", want.get("refusal"));
    let digest = text(&value.identity, "projectionDigest").to_string();
    assert_eq!(text(want, "digest"), digest, "{at}: digest");
    if let Some(identity) = want.get("identity") {
        assert!(json::json_eq(identity, &value.identity), "{at}: identity {:?}", value.identity);
    }
    if let Some(document) = want.get("document") {
        assert!(json::json_eq(document, &value.document), "{at}: document {:?}", value.document);
    }
    if let Some(canonical) = want.get("canonical") {
        let bytes = json::canonical(&value.document).expect("a canonical document");
        assert_eq!(canonical.as_str(), std::str::from_utf8(&bytes).ok(), "{at}: canonical");
    }
    if let Some(version) = want.get("resourceVersion") {
        assert!(json::json_eq(version, &value.resource_version), "{at}: resourceVersion {:?}", value.resource_version);
    }
    Some(digest)
}

/// An enforcement digest compared with the vector's expectation: its refusal, or its digest and any pinned document.
fn compare_enforcement(at: &str, want: &Value, outcome: Result<EnforcementValue, &'static str>) -> Option<String> {
    let value = match outcome {
        Ok(value) => value,
        Err(refusal) => {
            compare_refusal(at, want, refusal);
            return None;
        }
    };
    assert!(want.get("refusal").is_none(), "{at}: derived, but the vector refuses with {:?}", want.get("refusal"));
    assert_eq!(text(want, "digest"), value.digest, "{at}: digest");
    if let Some(document) = want.get("document") {
        assert!(value.document.as_ref().is_some_and(|ours| json::json_eq(document, ours)), "{at}: document {:?}",
                value.document);
    }
    Some(value.digest)
}

/// The replay's counts: the checks compared, those deferred to the second part, and those B1's inputs refuse earlier.
#[derive(Debug, Default)]
struct Tally {
    projections: usize,
    enforcements: usize,
    relations: usize,
    render_projections: usize,
    render_enforcements: usize,
    gates: usize,
    answers: usize,
    deferred_relations: usize,
    b1_inputs: usize,
}

#[test]
fn the_vendored_files_are_edge_record_v10s_rows() {
    for (name, bytes, digest, size) in ROWS {
        assert_eq!((hex(bytes), bytes.len()), (digest.to_string(), size), "contracts/{name}");
    }
}

#[test]
fn definitions_are_the_pinned_contract() {
    let definitions = parse(DEFINITIONS);
    assert_eq!(text(&definitions, "schemaVersion"), SCHEMA_VERSION);
    // Every refusal text, written out in i01_digest, is the contract's, and every pinned one is written there.
    let pinned: Vec<&str> =
        array(&definitions, "refusalTexts").iter().map(|item| item.as_str().expect("a text")).collect();
    assert_eq!(pinned.len(), 90);
    assert_eq!(i01_digest::refusal_texts(), pinned);
    for &(field, refusal) in B1_MALFORMED.iter() {
        assert_eq!(refusal, format!("rbac: malformed {field}"));
        assert!(pinned.contains(&refusal), "{refusal}");
    }
    // The keys, in the contract's order, and each projection's fixed apiVersion and kind.
    let projections = member(&definitions, "projections");
    let digests = member(&definitions, "enforcementDigests");
    assert_eq!(names_in_order(projections), DigestKey::POLICIES.map(DigestKey::name));
    assert_eq!(names_in_order(digests), DigestKey::DIGESTS.map(DigestKey::name));
    for key in DigestKey::POLICIES {
        let identity = member(member(projections, key.name()), "identity");
        assert_eq!(key.api_version_and_kind(), Some((text(identity, "apiVersion"), text(identity, "kind"))), "{key:?}");
    }
    for key in DigestKey::POLICIES.into_iter().chain(DigestKey::DIGESTS) {
        assert_eq!(DigestKey::of_name(key.name()), Some(key));
        let entry = member(if DigestKey::POLICIES.contains(&key) { projections } else { digests }, key.name());
        for refusal in array(entry, "refusals") {
            let refusal = refusal.as_str().expect("a text");
            assert!(pinned.contains(&refusal), "{key:?}: {refusal}");
        }
    }
    for key in DigestKey::DIGESTS {
        assert_eq!(key.api_version_and_kind(), None);
    }
    let gated: Vec<&str> =
        array(member(&definitions, "captureGate"), "gated").iter().map(|item| item.as_str().expect("a text")).collect();
    assert_eq!(gated, DigestKey::GATED.map(DigestKey::name));
    assert_eq!(text(member(member(digests, "rbacClosureDigest"), "document"), "schemaVersion"), CLOSURE_VERSION);
}

#[test]
fn every_contract_vector_replays() {
    let vectors = parse(VECTORS);
    assert_eq!(names(&vectors), VECTOR_MEMBERS);
    assert_eq!(text(&vectors, "schemaVersion"), "planeon.internal.policy-observation-digests-vectors/v1");
    assert_eq!(text(&vectors, "evidenceClass"), "UNIT_VERIFICATION_ONLY");
    assert_eq!(member(&vectors, "nativeAcceptance").as_bool(), Some(false));
    let mut ids = Vec::new();
    assert_eq!(replay_helpers(&vectors, &mut ids), HELPER_COUNT);
    // The definitions pin, after the helpers, as the model checks it.
    let contract = member(&vectors, "contract");
    assert_eq!(names(contract), ["canonicalSha256", "path"]);
    assert_eq!(text(contract, "path"), "architecture/policy-observation-digests/definitions.json");
    assert_eq!(text(contract, "canonicalSha256"), hex(&json::canonical(&parse(DEFINITIONS)).expect("canonical bytes")));
    let fixtures = member(&vectors, "fixtures");
    assert_eq!(names(fixtures), ["bindings", "captures", "record", "snapshots"]);
    let closure = Closure::embedded().expect("the embedded closure reads");
    // The A2 render is the second part's: asked, it records that and renders nothing, and the value is deferred.
    let asked = Cell::new(false);
    let render = |_: &SealedAdmission| -> Option<Rendered> {
        asked.set(true);
        None
    };
    let mut tally = Tally::default();
    let mut digests: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut pending: BTreeSet<(String, String)> = BTreeSet::new();
    let rows = array(&vectors, "vectors");
    assert_eq!(rows.len(), VECTOR_COUNT);
    for row in rows {
        assert_eq!(names(row), ROW_MEMBERS, "a closed vector");
        let id = text(row, "id");
        ids.push(id.to_string());
        let expect = member(row, "expect");
        let expected = names(expect);
        assert!(!expected.is_empty() && expected.iter().all(|name| EXPECT_MEMBERS.contains(name)),
                "vector {id}: a closed expectation");
        let inputs = combined(fixtures, row);
        let snapshot = member(&inputs, "snapshot");
        let binding = member(&inputs, "binding");
        let projections = keyed(expect, "projections");
        let enforcements = keyed(expect, "enforcement");
        match Inputs::new(list_inputs(member(snapshot, "lists"))) {
            Err(error) => {
                // B1's inputs refuse the lists before any digest is derived.
                assert_eq!((id, error), ("RB-17", InputError::ItemShape(Resource::ClusterRoles, 1)), "vector {id}");
                for (name, key, want) in projections.iter().chain(enforcements.iter()) {
                    assert!(matches!(key, DigestKey::Rbac | DigestKey::RbacClosureDigest), "vector {id}: {name}");
                    compare_refusal(&format!("vector {id} {name}"), want, "rbac: malformed metadata");
                    pending.insert((id.to_string(), name.to_string()));
                    tally.b1_inputs += 1;
                }
            }
            Ok(lists) => {
                let view = DigestSnapshot {
                    inputs: &lists,
                    resource_version: snapshot.get("resourceVersion"),
                    configuration: snapshot.get("configuration"),
                    adm4_loaded_hash: snapshot.get("adm4LoadedHash"),
                    record: snapshot.get("record"),
                };
                for (name, key, want) in &projections {
                    asked.set(false);
                    let outcome = i01_digest::projection(*key, &view, binding, &render);
                    if asked.get() {
                        pending.insert((id.to_string(), name.to_string()));
                        tally.render_projections += 1;
                        continue;
                    }
                    if let Some(digest) = compare_projection(&format!("vector {id} {name}"), want, outcome) {
                        digests.insert((id.to_string(), name.to_string()), digest);
                    }
                    tally.projections += 1;
                }
                for (name, key, want) in &enforcements {
                    asked.set(false);
                    let outcome = i01_digest::enforcement(*key, &view, &closure, &render);
                    if asked.get() {
                        pending.insert((id.to_string(), name.to_string()));
                        tally.render_enforcements += 1;
                        continue;
                    }
                    if let Some(digest) = compare_enforcement(&format!("vector {id} {name}"), want, outcome) {
                        digests.insert((id.to_string(), name.to_string()), digest);
                    }
                    tally.enforcements += 1;
                }
            }
        }
        // The capture gate's verdicts and the answers are the second part's: each counted, its form checked.
        for (name, key, want) in keyed(expect, "gates") {
            assert!(DigestKey::GATED.contains(&key), "vector {id}: {name} is not a gated value");
            assert!(want.is_null() || want.as_str().is_some_and(|refusal| refusal.starts_with(name)),
                    "vector {id}: gate {name}");
            tally.gates += 1;
        }
        if let Some(answer) = expect.get("observation") {
            assert!(answer.as_array().is_some_and(|refusals| refusals.iter().all(|item| item.as_str().is_some())),
                    "vector {id}: an answer's refusal list");
            tally.answers += 1;
        }
        for relation in ["same", "differs"] {
            for (name, _, other) in keyed(expect, relation) {
                let other = other.as_str().expect("a vector id");
                let here = (id.to_string(), name.to_string());
                let there = (other.to_string(), name.to_string());
                match (digests.get(&here), digests.get(&there)) {
                    (Some(ours), Some(theirs)) => {
                        assert_eq!(ours == theirs, relation == "same", "vector {id}: {relation} {name} as {other}");
                        tally.relations += 1;
                    }
                    _ => {
                        assert!(pending.contains(&here) || pending.contains(&there),
                                "vector {id}: {relation} {name} as {other} has no value to compare");
                        tally.deferred_relations += 1;
                    }
                }
            }
        }
    }
    // The complete I01 positive (the gate, the render and the answer together) is the second part's.
    let complete = member(&vectors, "complete");
    assert_eq!(names(complete), COMPLETE_MEMBERS, "the closed complete positive");
    assert_eq!((text(complete, "snapshot"), text(complete, "capture")), ("closure", "passing"));
    assert_eq!(ids.len(), HELPER_COUNT + VECTOR_COUNT);
    assert_eq!(ids.iter().collect::<BTreeSet<_>>().len(), ids.len(), "unique vector ids");
    // The counts: 105 of 120 projection checks, 40 of 46 enforcement checks and 46 of 51 relations compared.
    assert_eq!((tally.projections, tally.enforcements, tally.relations), (105, 40, 46), "{tally:?}");
    let deferred_counts =
        (tally.render_projections, tally.render_enforcements, tally.gates, tally.answers, tally.deferred_relations);
    assert_eq!(deferred_counts, (14, 5, 69, 12, 5), "{tally:?}");
    assert_eq!(tally.b1_inputs, 2, "{tally:?}");
    let compared = HELPER_COUNT + 1 + tally.projections + tally.enforcements + tally.relations;
    let deferred = tally.render_projections + tally.render_enforcements + tally.gates + tally.answers
        + tally.deferred_relations + COMPLETE_CHECKS;
    assert_eq!((compared, deferred, tally.b1_inputs), (208, 110, 2));
    assert_eq!(compared + deferred + tally.b1_inputs, 320);
}
