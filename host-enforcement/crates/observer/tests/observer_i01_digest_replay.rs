//! HE-004-I01B1 (DESIGN-I01B rev 3 section 2 and DESIGN-I01B1 rev 2; owner decision Q-HE4I1-2 and the monitor's
//! Q-I01B-26 (a), MON-I01B1-A (a) and MON-I01B1-B (a)), moved to the I01 digest contract v2 by HE-004-I01B4
//! (DESIGN-I01B4 rev 2 section 4.1; the monitor's Q-I01B4-2 and Q-I01B4-5; I4D-1, I4D-8): the contract v2's vectors
//! (`contracts/i01-digests-v2/vectors.json`, edge record v11's row 74) replayed against `i01_digest`, with
//! `i01_admission_render`'s admission v4 render handed in and `i01_gate`'s capture gate, each vector's own expectations
//! compared one by one. v1's replay is retired; v1's files stay held and pinned (Q-I01B4-2).
//!
//! - The four vendored files are edge record v11's rows 73-75 and 79 (each sha256 and size). `definitions.json` is the
//!   contract the vectors pin (their `contract.canonicalSha256`), and `i01_digest`'s refusal texts are its
//!   `refusalTexts`, all 90.
//! - The design's counts: 16 helper vectors (canonical bytes, digests, the exactness bounds) and 152 vectors. Each
//!   vector is built as the model builds it (its fixtures, then its operations), and B1's list inputs are made from its
//!   lists, each list as the apiserver serves it under its closed-set request.
//! - Compared: every projection's digest and, where the vector pins them, its identity, document, canonical bytes and
//!   resourceVersion, or its refusal text; every enforcement digest and its pinned document, or its refusal; every
//!   digest relation (`same`, `differs`) between two compared values; the definitions pin. The A2 render is
//!   `i01_admission_render::render`, handed in as `i01_digest`'s render argument (MON-I01B1-B (a)).
//! - The capture gate's verdicts (69): the vector's capture data as `i01_gate`'s plain data, the latest completed set
//!   with the vectors' ms values as the ages (a negative monotonic age is `scheduled_after_now`). R10's capture view is
//!   typed, so capture data of another shape (the contract's malformed capture data) has no R10 form: the replay's
//!   adapter checks the model's data shape and refuses such data as the key's malformed input before the gate.
//! - The answer refusal lists (12) and the complete I01 positive (6 checks, over the `qual` snapshot: v1's five and
//!   the sealed-namespace equality), as the model's `observed` and `check_observation_digests` compose them: every
//!   value derived with the render, the three gated values gated at the answer, each compared with the signed binding
//!   (the projection's identity without its resourceVersion, the digest with `enforcementPins`), the texts once each,
//!   in key order. The comparison is the test's, the model's composition over the port's values; HE-004-I01B3's answer
//!   logic is not built here.
//! - One vector's lists never reach a digest: RB-17 deletes a ClusterRole's name, and B1's `Inputs::new` refuses the
//!   lists (ItemShape, ClusterRoles item 1) before either RBAC value is derived. The vector pins the producer's text,
//!   "rbac: malformed metadata", which the observer cannot reach; the replay asserts the earlier refusal for both of
//!   its checks (MON-I01B1-A (a), R10-defined behaviour recorded in MODEL_DEFINED; unchanged in v2).
//! - R10-defined, outside the 321: profile v2's positive (row 79) is the complete positive's profile in every member
//!   but exactly ten, the profile members the positive's `replaced` list re-derives (the seven `policy.*Digest` and
//!   the three preexisting references' `observedDigest`). That gives row 79 its one reader.
//! - Not run in R10 (the contract v2's README section 11, MON-I01S-C2-1-WORDING): the profile-schema load
//!   (`_profile_schema`), profile v2's `validate` and `precondition`, and the frozen-model file pins (`_frozen`'s
//!   FROZEN_MODELS loop, `scripts/proxy_profile_v2.py` included), since models are pinned, not copied. Also not
//!   mirrored, as under v1: the model's uncounted FROZEN_INPUTS digest loop and I06 identity check (R10 embeds those
//!   bytes, G-D2-2) and its DESIGN_TEXTS coverage check; the v2 layer test's W1 assertions (VPO, profile v2 validate
//!   and precondition, P10) are harness-side (HO README section 10). `tools/gate.py`'s G-I01B4-1 holds the absence.
//!
//! Of the model's 323 checks (16 helper checks, the definitions pin, 120 projection, 46 enforcement, 69 gate, 12 answer
//! and 51 relation checks, and the complete positive's 8), R10's replay counts 321, the complete positive's 6 among
//! them (16 + 1 + 298 + 6): 319 are compared here and 2 are refused earlier by B1's inputs.

mod b1_support;

use std::collections::{BTreeMap, BTreeSet};

use b1_support::apply;
use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::sha256;
use planeon_observer::i01_admission_render;
use planeon_observer::i01_digest::{self, DigestKey, DigestSnapshot, EnforcementValue, ProjectionValue, B1_MALFORMED,
                                   CLOSURE_VERSION, SCHEMA_VERSION};
use planeon_observer::i01_gate::{self, LatestSet};
use planeon_observer::inputs::{InputError, Inputs, ListBody, ListInput, Resource};
use planeon_observer::snapshot::Closure;

const DEFINITIONS: &[u8] = include_bytes!("../../../contracts/i01-digests-v2/definitions.json");
const VECTORS: &[u8] = include_bytes!("../../../contracts/i01-digests-v2/vectors.json");
const README: &[u8] = include_bytes!("../../../contracts/i01-digests-v2/README.md");
const PROXY_VECTORS: &[u8] = include_bytes!("../../../contracts/i01-v2/proxy-profile-v2-vectors.json");
/// Edge record v11's rows 73-75 and 79: each vendored file's bytes, sha256 and size.
const ROWS: [(&str, &[u8], &str, usize); 4] = [
    ("i01-digests-v2/definitions.json", DEFINITIONS, "fef08fddfb94e06eeff5bc4bdaf37246f9142fd072dd6427f629350c8d5cb2f2",
     36_135),
    ("i01-digests-v2/vectors.json", VECTORS, "68eab4709431f73ce6f977aad7e5a087dccf9b5635c4ce04b8c08387bdce2594",
     602_663),
    ("i01-digests-v2/README.md", README, "fbb28445c5ec35bbf65bec5d852bd94de8b7c4acf8d2c239ee234e00c10d6090", 60_473),
    // Row 79's file, named once in this source, by its include literal above (G-I01B4-1 (b)).
    ("i01-v2/, row 79", PROXY_VECTORS, "011a650bcd2a11f2eaeba531693f3e7ee9c30c1f6ede2d5ecf87919f206affcc", 62_297),
];
/// The design's counts (DESIGN-I01B rev 3 section 1, unchanged in v2): 152 vectors and 16 helper vectors.
const VECTOR_COUNT: usize = 152;
const HELPER_COUNT: usize = 16;
/// The complete I01 positive's checks R10 runs, six of the model's eight `_check_complete` checks: the answer refuses
/// nothing, the observed projections, the observed enforcement, `profileDigest`, `bindingDigest` with the profile's
/// digests and references, and the snapshot's qualification namespace is the sealed namespace. Profile v2's
/// `validate` and `precondition` stay harness-side.
const COMPLETE_CHECKS: usize = 6;
/// The sealed namespace (the v2 model's `SEALED_NAMESPACE`, harness-onion `scripts/policy_observation_digests_v2.py:63`;
/// the render replay ties it to admission v4's `sealed.namespace`).
const SEALED_NAMESPACE: &str = "planeon-qual";
/// The vectors' pin of the definitions (`contract.canonicalSha256`), and the complete positive's profile digest and
/// binding digest.
const DEFINITIONS_PIN: &str = "5f170f308ed32b7d10859c1d2f919d47eebd813c2f2588cff7cccbac8c653d7b";
const PROFILE_DIGEST: &str = "sha256:c212b038a751ec4bf874bee6e18ceb721cd1050b475da5b1aa5fa763377e3761";
const BINDING_DIGEST: &str = "sha256:6e745318b14b5c5e3139516bd581405cb9627303e804a15067888eff45e77b94";
/// The ten members in which profile v2's positive (row 79) differs from the complete positive's profile, sorted:
/// those the positive's `replaced` list names for the profile (`REPLACED_PROFILE`).
const ROW_79_DIFFERS: [&str; 10] = [
    "capacityEntries.preexistingResourceRefs[0].observedDigest",
    "capacityEntries.preexistingResourceRefs[1].observedDigest",
    "capacityEntries.preexistingResourceRefs[2].observedDigest",
    "policy.admissionPolicyDigest",
    "policy.limitRangeDigest",
    "policy.mutationBrokerDigest",
    "policy.networkPolicyDigest",
    "policy.rbacDigest",
    "policy.resourceQuotaDigest",
    "policy.serviceAccountDigest",
];
const REPLACED_PROFILE: [&str; 2] =
    ["profile.policy.*Digest", "profile.capacityEntries.preexistingResourceRefs[*].observedDigest"];
/// The capture verdicts' data shape (`definitions.json` `captureGate.dataShape`), each member list sorted, and the
/// largest count it admits (2^53 - 1).
const CAPTURE_MEMBERS: [&str; 2] = ["answer", "sets"];
const SET_MEMBERS: [&str; 4] = ["completed", "scheduledMonotonicMs", "slots", "startedWallMs"];
const ANSWER_MEMBERS: [&str; 2] = ["monotonicMs", "wallMs"];
const MAX_COUNT: i64 = (1 << 53) - 1;
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

/// The paths (`a.b[0].c`, members sorted) at which two values differ: a leaf whose values differ, and an array whose
/// lengths differ, at its own path; a member held on one side only as its path and ` (one side)`.
fn differences(left: &Value, right: &Value, at: &str, out: &mut Vec<String>) {
    match (left, right) {
        (Value::Object(ours), Value::Object(theirs)) => {
            let mut keys: Vec<&str> =
                ours.iter().chain(theirs.iter()).map(|(name, _)| name.as_str().expect("a text member name")).collect();
            keys.sort_unstable();
            keys.dedup();
            for key in keys {
                let path = if at.is_empty() { key.to_string() } else { format!("{at}.{key}") };
                match (ours.get(key), theirs.get(key)) {
                    (Some(one), Some(other)) => differences(one, other, &path, out),
                    _ => out.push(format!("{path} (one side)")),
                }
            }
        }
        (Value::Array(ours), Value::Array(theirs)) if ours.len() == theirs.len() => {
            for (index, (one, other)) in ours.iter().zip(theirs).enumerate() {
                differences(one, other, &format!("{at}[{index}]"), out);
            }
        }
        _ => {
            if !json::json_eq(left, right) {
                out.push(at.to_string());
            }
        }
    }
}

/// Lowercase hexadecimal text as bytes.
fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "hex text of whole bytes");
    (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digits")).collect()
}

/// Expands a helper vector's input (the model's `_expand`): an object that is exactly `{"$fill": n}` becomes a text of
/// n letters `a`; arrays and other objects are expanded member by member.
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

/// A snapshot's values as `i01_digest` reads them, over B1's checked lists.
fn view<'a>(lists: &'a Inputs, snapshot: &'a Value) -> DigestSnapshot<'a> {
    DigestSnapshot {
        inputs: lists,
        resource_version: snapshot.get("resourceVersion"),
        configuration: snapshot.get("configuration"),
        adm4_loaded_hash: snapshot.get("adm4LoadedHash"),
        record: snapshot.get("record"),
    }
}

/// The latest completed capture set as `i01_gate`'s plain data, owned.
struct Latest {
    slots: Vec<(String, bool)>,
    scheduled_after_now: bool,
    mono_age_ms: u64,
    wall_age_ms: i64,
}

/// Whether a value is an object holding exactly these member names (sorted).
fn closed(value: &Value, members: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        let mut held: Vec<&[u8]> = object.iter().map(|(name, _)| name.as_bytes()).collect();
        held.sort_unstable();
        held == members.iter().map(|member| member.as_bytes()).collect::<Vec<&[u8]>>()
    })
}

/// The data shape's count: an integer in 0..2^53 - 1.
fn count(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_int).and_then(|int| int.to_i64()).filter(|number| (0..=MAX_COUNT).contains(number))
}

/// The vector's capture verdicts as the gate's plain data (the contract's `captureGate.dataShape`, the model's
/// `_capture`): `None` for data of another shape; otherwise the latest completed set (the last entry whose `completed`
/// is true), if any, with each slot taken when it is `TAKEN`, and its two ages at the answer from the vectors' ms
/// values (the answer's monotonic reading minus the set's own scheduled start, `scheduled_after_now` when that is
/// negative; the answer's wall reading minus the set's start).
fn latest_set(capture: &Value) -> Option<Option<Latest>> {
    if !closed(capture, &CAPTURE_MEMBERS) {
        return None;
    }
    let sets = capture.get("sets").and_then(Value::as_array)?;
    for set in sets {
        let slots = set.get("slots").and_then(Value::as_object);
        let shaped = closed(set, &SET_MEMBERS)
            && count(set.get("scheduledMonotonicMs")).is_some()
            && count(set.get("startedWallMs")).is_some()
            && set.get("completed").and_then(Value::as_bool).is_some()
            && slots.is_some_and(|slots| slots.iter().all(|(_, state)| matches!(state, Value::Str(_))));
        if !shaped {
            return None;
        }
    }
    let answer = capture.get("answer").filter(|answer| closed(answer, &ANSWER_MEMBERS))?;
    let (monotonic, wall) = (count(answer.get("monotonicMs"))?, count(answer.get("wallMs"))?);
    let Some(latest) = sets.iter().rev().find(|set| set.get("completed").and_then(Value::as_bool) == Some(true)) else {
        return Some(None);
    };
    let slots = latest.get("slots").and_then(Value::as_object)?;
    let mono = monotonic - count(latest.get("scheduledMonotonicMs"))?;
    Some(Some(Latest {
        // A slot name without a text form cannot be one of R10's slot names, so it is left out (never taken).
        slots: slots
            .iter()
            .filter_map(|(name, state)| Some((name.as_str()?.to_string(), state.as_str() == Some("TAKEN"))))
            .collect(),
        scheduled_after_now: mono < 0,
        mono_age_ms: u64::try_from(mono).unwrap_or(0),
        wall_age_ms: wall - count(latest.get("startedWallMs"))?,
    }))
}

/// The capture gate for one gated value at the vector's answer: the capture data as plain data, then `i01_gate`
/// (capture data of another shape is the key's malformed input, the adapter's refusal).
fn gate(key: DigestKey, capture: &Value, record: &Value) -> Result<(), &'static str> {
    let latest = latest_set(capture).ok_or(key.malformed())?;
    let set = latest.as_ref().map(|data| LatestSet {
        slots: &data.slots,
        scheduled_after_now: data.scheduled_after_now,
        mono_age_ms: data.mono_age_ms,
        wall_age_ms: data.wall_age_ms,
    });
    i01_gate::capture_gate(key, set.as_ref(), record)
}

/// Every value of one answer (the model's `observed`): each projection and digest derived at the snapshot, the A2
/// render handed in, and each of the three gated values gated at the answer, or its first refusal.
#[allow(clippy::type_complexity)]
fn observed(view: &DigestSnapshot<'_>, binding: &Value, capture: &Value, closure: &Closure)
            -> (Vec<(DigestKey, Result<ProjectionValue, &'static str>)>,
                Vec<(DigestKey, Result<String, &'static str>)>) {
    let null = Value::Null;
    let record = view.record.unwrap_or(&null);
    let projections = DigestKey::POLICIES
        .into_iter()
        .map(|key| {
            let outcome = i01_digest::projection(key, view, binding, &i01_admission_render::render).and_then(|value| {
                if DigestKey::GATED.contains(&key) {
                    gate(key, capture, record)?;
                }
                Ok(value)
            });
            (key, outcome)
        })
        .collect();
    let digests = DigestKey::DIGESTS
        .into_iter()
        .map(|key| {
            let outcome = i01_digest::enforcement(key, view, closure, &i01_admission_render::render).and_then(|value| {
                if DigestKey::GATED.contains(&key) {
                    gate(key, capture, record)?;
                }
                Ok(value.digest)
            });
            (key, outcome)
        })
        .collect();
    (projections, digests)
}

/// The answer's refusal list (the model's `check_observation_digests`): each value's refusal, or "<key>: differs from
/// the signed value" when its identity (without resourceVersion) or digest is not the signed binding's (`projections`,
/// `enforcementPins`), each text once, in key order.
fn check_observation(view: &DigestSnapshot<'_>, binding: &Value, capture: &Value, closure: &Closure)
                     -> Vec<&'static str> {
    let (projections, digests) = observed(view, binding, capture, closure);
    let signed = binding.get("projections").and_then(Value::as_object);
    let pins = binding.get("enforcementPins").and_then(Value::as_object);
    let mut errors: Vec<&'static str> = Vec::new();
    let mut add = |text: &'static str| {
        if !errors.contains(&text) {
            errors.push(text);
        }
    };
    for (key, outcome) in &projections {
        match outcome {
            Err(refusal) => add(*refusal),
            Ok(value) => {
                let expected = signed.and_then(|signed| signed.get(key.name()));
                if !expected.is_some_and(|expected| json::py_eq(&value.identity, expected)) {
                    add(key.differs());
                }
            }
        }
    }
    for (key, outcome) in &digests {
        match outcome {
            Err(refusal) => add(*refusal),
            Ok(digest) => {
                let pinned = pins.and_then(|pins| pins.get(key.name()));
                if !pinned.is_some_and(|pinned| pinned.as_str() == Some(digest.as_str())) {
                    add(key.differs());
                }
            }
        }
    }
    errors
}

/// A refusal as the model's `observed` writes it.
fn refusal_value(text: &str) -> Value {
    let mut members = Object::new();
    members.insert(JStr::new("refusal"), Value::str(text));
    Value::Object(members)
}

/// The replay's counts: the checks compared, and those B1's inputs refuse earlier.
#[derive(Debug, Default)]
struct Tally {
    projections: usize,
    enforcements: usize,
    relations: usize,
    gates: usize,
    answers: usize,
    b1_inputs: usize,
}

#[test]
fn the_vendored_files_are_edge_record_v11s_rows_73_to_75_and_79() {
    for (name, bytes, digest, size) in ROWS {
        assert_eq!((hex(bytes), bytes.len()), (digest.to_string(), size), "contracts/{name}");
    }
}

/// R10-defined, outside the 321 (DESIGN-I01B4 rev 2 section 4.1): row 79's positive is the complete positive's profile
/// in every member but exactly the ten its `replaced` list names for the profile, each present on both sides and
/// differing.
#[test]
fn row_79s_positive_is_the_complete_positives_profile_but_ten_members() {
    let vectors = parse(VECTORS);
    let complete = member(&vectors, "complete");
    let row_79 = parse(PROXY_VECTORS);
    let mut differing = Vec::new();
    differences(member(complete, "profile"), member(&row_79, "positive"), "", &mut differing);
    assert_eq!(differing, ROW_79_DIFFERS);
    let replaced: Vec<&str> = array(complete, "replaced").iter().map(|item| item.as_str().expect("a text")).collect();
    let profile_entries: Vec<&str> = replaced.iter().copied().filter(|entry| entry.starts_with("profile.")).collect();
    assert_eq!(profile_entries, REPLACED_PROFILE);
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
    assert_eq!(text(&vectors, "schemaVersion"), "planeon.internal.policy-observation-digests-vectors/v2");
    assert_eq!(text(&vectors, "evidenceClass"), "UNIT_VERIFICATION_ONLY");
    assert_eq!(member(&vectors, "nativeAcceptance").as_bool(), Some(false));
    let mut ids = Vec::new();
    assert_eq!(replay_helpers(&vectors, &mut ids), HELPER_COUNT);
    // The definitions pin, after the helpers, as the model checks it.
    let contract = member(&vectors, "contract");
    assert_eq!(names(contract), ["canonicalSha256", "path"]);
    assert_eq!(text(contract, "path"), "architecture/policy-observation-digests-v2/definitions.json");
    assert_eq!(text(contract, "canonicalSha256"), hex(&json::canonical(&parse(DEFINITIONS)).expect("canonical bytes")));
    assert_eq!(text(contract, "canonicalSha256"), DEFINITIONS_PIN);
    let fixtures = member(&vectors, "fixtures");
    assert_eq!(names(fixtures), ["bindings", "captures", "record", "snapshots"]);
    let closure = Closure::embedded().expect("the embedded closure reads");
    let mut tally = Tally::default();
    let mut digests: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut refused_earlier: BTreeSet<(String, String)> = BTreeSet::new();
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
        let capture = member(&inputs, "capture");
        let projections = keyed(expect, "projections");
        let enforcements = keyed(expect, "enforcement");
        let lists = Inputs::new(list_inputs(member(snapshot, "lists")));
        match &lists {
            Err(error) => {
                // B1's inputs refuse the lists before any digest is derived (MON-I01B1-A (a)).
                assert_eq!((id, error), ("RB-17", &InputError::ItemShape(Resource::ClusterRoles, 1)), "vector {id}");
                for (name, key, want) in projections.iter().chain(enforcements.iter()) {
                    assert!(matches!(key, DigestKey::Rbac | DigestKey::RbacClosureDigest), "vector {id}: {name}");
                    compare_refusal(&format!("vector {id} {name}"), want, "rbac: malformed metadata");
                    refused_earlier.insert((id.to_string(), name.to_string()));
                    tally.b1_inputs += 1;
                }
            }
            Ok(lists) => {
                let digest_view = view(lists, snapshot);
                for (name, key, want) in &projections {
                    let outcome = i01_digest::projection(*key, &digest_view, binding, &i01_admission_render::render);
                    if let Some(digest) = compare_projection(&format!("vector {id} {name}"), want, outcome) {
                        digests.insert((id.to_string(), name.to_string()), digest);
                    }
                    tally.projections += 1;
                }
                for (name, key, want) in &enforcements {
                    let outcome = i01_digest::enforcement(*key, &digest_view, &closure, &i01_admission_render::render);
                    if let Some(digest) = compare_enforcement(&format!("vector {id} {name}"), want, outcome) {
                        digests.insert((id.to_string(), name.to_string()), digest);
                    }
                    tally.enforcements += 1;
                }
            }
        }
        // The capture gate's verdicts, with the vector's capture data and the snapshot's record.
        let null = Value::Null;
        let record = snapshot.get("record").unwrap_or(&null);
        for (name, key, want) in keyed(expect, "gates") {
            assert!(DigestKey::GATED.contains(&key), "vector {id}: {name} is not a gated value");
            match gate(key, capture, record) {
                Ok(()) => assert!(want.is_null(), "vector {id}: gate {name} passes, the vector refuses with {want:?}"),
                Err(refusal) => assert_eq!(want.as_str(), Some(refusal), "vector {id}: gate {name}"),
            }
            tally.gates += 1;
        }
        // The answer's refusal list: each value is derived, gated where the contract gates it, then held to the signed
        // binding.
        if let Some(answer) = expect.get("observation") {
            let Ok(lists) = &lists else {
                panic!("vector {id}: an answer over lists B1 refuses");
            };
            let want: Vec<&str> =
                array(expect, "observation").iter().map(|item| item.as_str().expect("a text")).collect();
            assert!(answer.as_array().is_some());
            let got = check_observation(&view(lists, snapshot), binding, capture, &closure);
            assert_eq!(got, want, "vector {id}: answer");
            tally.answers += 1;
        }
        for relation in ["same", "differs"] {
            for (name, _, other) in keyed(expect, relation) {
                let other = other.as_str().expect("a vector id");
                let here = (id.to_string(), name.to_string());
                let there = (other.to_string(), name.to_string());
                assert!(!refused_earlier.contains(&here) && !refused_earlier.contains(&there),
                        "vector {id}: {relation} {name} as {other} over a value B1's inputs refuse");
                match (digests.get(&here), digests.get(&there)) {
                    (Some(ours), Some(theirs)) => {
                        assert_eq!(ours == theirs, relation == "same", "vector {id}: {relation} {name} as {other}");
                        tally.relations += 1;
                    }
                    _ => panic!("vector {id}: {relation} {name} as {other} has no value to compare"),
                }
            }
        }
    }
    assert_eq!(ids.len(), HELPER_COUNT + VECTOR_COUNT);
    assert_eq!(ids.iter().collect::<BTreeSet<_>>().len(), ids.len(), "unique vector ids");
    let complete = replay_complete(&vectors, &closure);
    // The counts (Q-I01B4-5): 119 of 120 projection checks and 45 of 46 enforcement checks (RB-17's two refused
    // earlier), every gate, answer and relation check, and the complete positive's six.
    assert_eq!((tally.projections, tally.enforcements, tally.relations), (119, 45, 51), "{tally:?}");
    assert_eq!((tally.gates, tally.answers, complete), (69, 12, 6), "{tally:?}");
    assert_eq!(complete, COMPLETE_CHECKS);
    assert_eq!(tally.b1_inputs, 2, "{tally:?}");
    let compared = HELPER_COUNT + 1 + tally.projections + tally.enforcements + tally.gates + tally.answers
        + tally.relations + complete;
    assert_eq!((compared, tally.b1_inputs), (319, 2));
    // 16 helper checks + the definitions pin + 298 vector checks (120 + 46 + 69 + 12 + 51) + the complete positive's 6.
    assert_eq!(compared + tally.b1_inputs, 321);
    assert_eq!(compared + tally.b1_inputs, HELPER_COUNT + 1 + (120 + 46 + 69 + 12 + 51) + COMPLETE_CHECKS);
}

/// The complete I01 positive (the model's `_check_complete`, six of its eight checks): PV's binding, request and
/// observation with profile v2's positive, re-derived for the sealed namespace, with the values the model derives from
/// the `qual` snapshot, the record and the passing capture. The answer over the fixture refuses nothing; its observed
/// projections (each identity with its resourceVersion) and enforcement (each digest, with `policyGeneration` the
/// observation's generation) are the observation's; `profileDigest` is the profile's digest; `bindingDigest`, the
/// profile's seven policy digests and its three preexisting references agree with the binding; and the snapshot's
/// qualification namespace is the sealed namespace. Profile v2's `validate` and `precondition` are not run in R10. The
/// number of checks R10 runs.
fn replay_complete(vectors: &Value, closure: &Closure) -> usize {
    let complete = member(vectors, "complete");
    assert_eq!(names(complete), COMPLETE_MEMBERS, "the closed complete positive");
    assert_eq!((text(complete, "snapshot"), text(complete, "capture")), ("qual", "passing"));
    let fixtures = member(vectors, "fixtures");
    let mut snapshot = member(member(fixtures, "snapshots"), text(complete, "snapshot")).clone();
    match &mut snapshot {
        Value::Object(members) => members.insert(JStr::new("record"), member(fixtures, "record").clone()),
        _ => panic!("a snapshot fixture is an object"),
    }
    let capture = member(member(fixtures, "captures"), text(complete, "capture"));
    let (binding, request) = (member(complete, "binding"), member(complete, "request"));
    let (observation, profile) = (member(complete, "observation"), member(complete, "profile"));
    let lists = Inputs::new(list_inputs(member(&snapshot, "lists"))).expect("the qual snapshot's lists");
    let digest_view = view(&lists, &snapshot);
    // 1. The answer refuses nothing.
    let answer = check_observation(&digest_view, binding, capture, closure);
    assert_eq!(answer, Vec::<&str>::new(), "complete positive: the answer");
    // 2 and 3. The observed values are the observation's.
    let (projections, enforcement) = observed(&digest_view, binding, capture, closure);
    let mut observed_projections = Object::new();
    for (key, outcome) in projections {
        let value = match outcome {
            Ok(value) => {
                let mut identity = value.identity.as_object().cloned().expect("an identity object");
                identity.insert(JStr::new("resourceVersion"), value.resource_version.clone());
                Value::Object(identity)
            }
            Err(refusal) => refusal_value(refusal),
        };
        observed_projections.insert(JStr::new(key.name()), value);
    }
    assert!(json::py_eq(&Value::Object(observed_projections), member(observation, "projections")),
            "complete positive: observed projections");
    let mut observed_enforcement = Object::new();
    for (key, outcome) in enforcement {
        observed_enforcement.insert(JStr::new(key.name()), match outcome {
            Ok(digest) => Value::str(&digest),
            Err(refusal) => refusal_value(refusal),
        });
    }
    observed_enforcement.insert(JStr::new("policyGeneration"), member(observation, "generation").clone());
    assert!(json::py_eq(&Value::Object(observed_enforcement), member(observation, "enforcement")),
            "complete positive: observed enforcement");
    // 4. The binding's profileDigest is the profile's digest.
    let digest_of = |value: &Value| sha256::prefixed(&json::canonical(value).expect("canonical bytes"));
    assert_eq!(text(binding, "profileDigest"), digest_of(profile), "complete positive: profileDigest");
    assert_eq!(text(binding, "profileDigest"), PROFILE_DIGEST);
    // 5. bindingDigest, the profile's policy digests and its preexisting references agree with the binding.
    let bound = digest_of(binding);
    assert_eq!(bound, BINDING_DIGEST);
    assert_eq!((text(request, "bindingDigest"), text(observation, "bindingDigest")), (bound.as_str(), bound.as_str()),
               "complete positive: bindingDigest");
    let signed = member(binding, "projections");
    let policy = member(profile, "policy");
    for key in DigestKey::POLICIES {
        assert_eq!(text(policy, &format!("{}Digest", key.name())), text(member(signed, key.name()), "projectionDigest"),
                   "complete positive: profile digest {}", key.name());
    }
    let references = array(member(profile, "capacityEntries"), "preexistingResourceRefs");
    for (key, kind) in [(DigestKey::ResourceQuota, "ResourceQuota"), (DigestKey::LimitRange, "LimitRange"),
                        (DigestKey::ServiceAccount, "ServiceAccount")] {
        let found: Vec<&Value> = references.iter().filter(|reference| text(reference, "kind") == kind).collect();
        let entry = member(signed, key.name());
        assert!(found.len() == 1
                && text(found[0], "observedDigest") == text(entry, "projectionDigest")
                && text(found[0], "uid") == text(entry, "uid"),
                "complete positive: reference {}", key.name());
    }
    // 6. The snapshot's qualification namespace is the sealed namespace (the v2 model's SEALED_NAMESPACE).
    assert_eq!(text(member(&snapshot, "configuration"), "qualificationNamespace"), SEALED_NAMESPACE,
               "complete positive: sealed namespace");
    COMPLETE_CHECKS
}
