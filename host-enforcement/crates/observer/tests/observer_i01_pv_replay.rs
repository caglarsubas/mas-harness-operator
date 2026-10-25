//! HE-004-I01A2, unit U7 of HE-004-I01a (DESIGN-I01A sections 7, 8 and 15; owner decisions Q-HE4I1-10 (a), Q-I01A-1
//! and Q-U7-1..3 (a); MODEL_DEFINED's HE-004-I01A2 section): the I01 wire's vectors (`PV`, edge record v9's row 68)
//! replayed against R10's request checks.
//!
//! - The vendored files are edge record v9's bytes (rows 67 and 68: each sha256 and size), and the vendored schema's
//!   request definition (`CS`, `$defs.request`) is the one `i01_request` implements: its seven members, the two
//!   constants, the three text forms and the `sequence` range.
//! - `PV`'s request cases, the positive's request and its five request negatives, run at unit level, so that each
//!   negative's own refusal is seen: framing and the schema (`frame`, `request_schema`), a fresh session's chain
//!   (`Chain::check`; the positive has no previous observation), and the binding gate (`binding_gate`) with a test
//!   binding. The test binding is built from the positive's binding document: the SHA-256 of i05-protocol's canonical
//!   encoding of that document, which must be the `bindingDigest` the positive's request names (the evidence that R10's
//!   canonical form is the one `PV` was written with), and the scope's `runNonce`.
//! - HE-004-I01B2 (DESIGN-I01B2 section 8, I2D-6): the test binding is `I01Binding::from_config` over the positive's
//!   binding document, the one constructor `serve` calls on the configuration's checked member; its digest and nonce
//!   are read through the getters, and the request negatives are refused against that one binding.
//! - Negative 1 (another operation) refuses at the schema; negatives 2 and 3 (another `runNonce`, another
//!   `bindingDigest`) pass framing, the schema and the chain and refuse only at the gate; negatives 4 and 5
//!   (sequence 2, a previous digest other than zero) refuse at the chain. The positive passes every check.
//! - R10's own framing negatives (DESIGN-I01A section 15) were all built by HE-004-I01A: `observer_i01_request`
//!   (size, bytes, strict JSON, depth, floats, integers, decoded text, the non-canonical encodings, extra and missing
//!   members), `observer_i01_wait` (a datagram over 16,384 bytes cut short, other ancillary data, a passed
//!   descriptor) and `observer_i01_service` (each receive outcome closing the session). None is new here; the last
//!   test applies the framing rules to `PV`'s positive request in other encodings than its canonical one.
//!
//! Not replayed: `PV`'s 17 observation negatives and 5 binding negatives. Those cases also read the proxy profile,
//! `architecture/proxy-contract-inputs/vectors.json`, which edge record v9 did not register (its replay-scope note;
//! edge record v10's row 72 registered it for HE-004-I01B1); the observation side is I01b's.
//!
//! HE-004-I01B1 (DESIGN-I01B rev 3 section 8.1; the monitor's R-B1-13 (a)) adds those 22 cases' table as data
//! (`PV_CASES`): each case's label, the VPO rule it breaks, its checker (an R10 check, or HE-008's profile-side one)
//! and the packet that replays it. A test holds its labels to `PV`'s negatives 6-27, each once. No row is replayed in
//! HE-004-I01B1.
//!
//! HE-004-I01B4, W3 (DESIGN-I01B4 rev 2 section 4.3; the monitor's Q-I01B4-4 and Q-I01B4D-1 (a); I4D-3, I4D-4, I4D-13):
//! - The source is S1's complete triple, the one profile v2 wire triple that exists: `complete` inside the I01 digest
//!   contract v2's vectors (`contracts/i01-digests-v2/vectors.json`, edge record v11's row 74, pinned by its sha256 and
//!   size). Its `now`, `previous` (null), scope window, nonces and challenge are `PV`'s.
//! - The derivation rule (R10-defined, MODEL_DEFINED R181): for each of `PV`'s negatives 6-27, the derived case is the
//!   triple's binding or observation with exactly that negative's one change, its `value` at its `path`; nothing is
//!   recomputed, as `PV`'s own negatives are its positive with one change. The label stays `PV`'s, and the rule label,
//!   checker and packet stay `PV_CASES`' row (the rule column is a label, not a VPO result).
//! - Checked here, structure only: the derived cases are exactly `PV_CASES`' 22 labels, in order; each path exists in
//!   the triple's document; each value differs from the triple's value there; each derived document equals the
//!   triple's but at that one path. That each derived case still breaks the same VPO rule, and only it, is not shown
//!   (harness-onion's VPO proof, not chosen). No derived case is run against a checker here: none exists yet.
//! - The request side (Q-I01B4D-1 (a)): the triple's request equals `PV`'s positive request but at `bindingDigest`; it
//!   passes framing, the schema, a fresh chain and `binding_gate` with the test binding built from the triple's
//!   binding; and `PV`'s five request negatives, applied to the triple by the same rule, each with a value other than
//!   the triple's, refuse at their own steps.
//! - Carried: W3's derived cases (R181): negative-27 is replayed against the load-time check (status 13) in
//!   HE-004-I01B2, and the 18 rows whose packet is HE-004-I01B3 against their checkers in HE-004-I01B3, each as the
//!   derived case on S1's v2 triple (row 74), with the derivation rule unchanged; each packet's design section states
//!   it and whether PV's v1 cases are also replayed. Cases 18, 23 and 24 (packet `-`, checker HE-008's profile-side
//!   one) are replayed in no R10 packet. HE-004-I01B2 replayed negative-27 (Q-I01B2D-3 (a)): PV's own case and W3's
//!   derived case on S1's triple, each as a v3 document refused at the namespace check, status 13
//!   (`observer_config_v3`); the 18 HE-004-I01B3 rows stay carried.
//!
//! HE-004-I01B3 (DESIGN-I01B3 rev 4 section 7; the monitor's Q-I01B3-3 (a); I3D-5), the carried replay done: each of
//! the 18 rows whose packet is HE-004-I01B3 runs as W3's derived case on S1's triple, the derivation rule unchanged,
//! against its checker (`I01B3_ROWS`), and refuses with its expected text:
//! - rows 6-13, 17 and 19-21: `i01_answer::self_check` over the derived observation, with the triple's request,
//!   binding and `now` and `previous` null (VPO's label, or VPO's generic text for the shape rows 19 and 20);
//! - rows 14-16 and 22: `self_check`'s text, and for 15, 16 and 22 the snapshot comparison's half, the changed value
//!   applied to the binding's corresponding member (`projections.<key>.<member>`, `enforcementPins.<digest>`) and
//!   `i01_answer::refusals` over the `qual` snapshot giving exactly the contract's differs text; the namespace has no
//!   differs text, so row 14's half is `self_check`'s only;
//! - row 25: `self_check` with the derived binding ("observed namespace"); row 26: `refusals` with the derived binding
//!   ("serviceAccount: differs from the signed value").
//!
//! PV's v1 cases are also replayed for the document-level rows (6-13, 17, 19-21), each on PV's own positive, with the
//! same checker and text. They are not replayed for the snapshot-comparison rows (14-16, 22, 25, 26), whose v1
//! positive has no snapshot fixture. Cases 18, 23 and 24 stay HE-008's.

use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::sha256;
use planeon_observer::i01_answer::{self, CaptureFacts, ENFORCEMENT_PROOF_TEXT, FRESHNESS_WINDOW_TEXT,
                                   INVALID_OBSERVATION_TEXT, OBSERVED_IDENTITY_TEXT, OBSERVED_NAMESPACE_TEXT,
                                   QUOTA_HEADROOM_TEXT, RESPONSE_SUBSTITUTION_TEXT, STALE_OR_FUTURE_TEXT};
use planeon_observer::i01_request::{binding_gate, check_request, frame, request_schema, Chain, I01Binding, I01Request,
                                    RequestRefusal, MAX_INTEGER, MEMBERS, OBSERVE_POLICY, REQUEST_SCHEMA, ZERO_DIGEST};
use planeon_observer::inputs::{Inputs, ListBody, ListInput, Resource};
use planeon_observer::kernel_text::utc_seconds;
use planeon_observer::snapshot::Closure;

const PV: &str = include_str!("../../../contracts/i01-v1/vectors.json");
const CS: &str = include_str!("../../../contracts/i01-v1/channel.schema.json");
/// Edge record v9's rows 67 and 68: the schema's and the vectors' sha256 and size.
const CS_PIN: (&str, usize) = ("fb69b77201d9b6275a19667a5f5770537f382ddb11309095733628c8430bdc0e", 41_771);
const PV_PIN: (&str, usize) = ("1bfb46776636f800e38ab6a8f94a0989aa38513fb4a28ef18e61e732a115c124", 14_486);
/// HE-004-I01B4 (W3): the I01 digest contract v2's vectors, S1's complete triple's file (edge record v11's row 74:
/// its sha256 and size), and the triple's request `bindingDigest`, the canonical digest of its binding.
const DIGEST_VECTORS: &[u8] = include_bytes!("../../../contracts/i01-digests-v2/vectors.json");
const ROW_74_PIN: (&str, usize) = ("68eab4709431f73ce6f977aad7e5a087dccf9b5635c4ce04b8c08387bdce2594", 602_663);
const TRIPLE_BINDING_DIGEST: &str = "sha256:6e745318b14b5c5e3139516bd581405cb9627303e804a15067888eff45e77b94";
/// `PV`'s five request negatives, in file order.
const REQUEST_NEGATIVES: [&str; 5] = ["negative-1-request-operation", "negative-2-request-runNonce",
                                      "negative-3-request-bindingDigest", "negative-4-request-sequence",
                                      "negative-5-request-previousObservationDigest"];
/// The chain's refusal of a session's first request.
const FIRST: RequestRefusal = RequestRefusal::Chain("a session's first request is sequence 1 after the zero digest");
/// DESIGN-I01B rev 3 section 8.1 (R-B1-13 (a)): `PV`'s 22 binding and observation negatives, each as (case, VPO rule,
/// checker, packet). A case HE-008 holds profile-side is replayed by no R10 packet ("-"). In cases 23-27 the mutated
/// binding also changes its digest, so a request naming the positive's digest fails the gate; that is not counted as
/// the case's checker.
const PV_CASES: [(&str, &str, &str, &str); 22] = [
    ("negative-6-observation-challenge", "response substitution", "R10: i01_answer's self-check", "HE-004-I01B3"),
    ("negative-7-observation-runNonce", "response substitution", "R10: i01_answer's self-check", "HE-004-I01B3"),
    ("negative-8-observation-bindingDigest", "response substitution", "R10: i01_answer's self-check", "HE-004-I01B3"),
    ("negative-9-observation-sequence", "response substitution", "R10: i01_answer's self-check", "HE-004-I01B3"),
    ("negative-10-observation-previousObservationDigest", "response substitution", "R10: i01_answer's self-check",
     "HE-004-I01B3"),
    ("negative-11-observation-observedAt", "stale or future", "R10: self-check window", "HE-004-I01B3"),
    ("negative-12-observation-expiresAt", "stale or future", "R10: self-check window", "HE-004-I01B3"),
    ("negative-13-observation-expiresAt", "freshness window", "R10: self-check window", "HE-004-I01B3"),
    ("negative-14-observation-namespace.uid", "observed namespace", "R10: snapshot comparison and self-check",
     "HE-004-I01B3"),
    ("negative-15-observation-projections.resourceQuota.projectionDigest", "observed identity or digest",
     "R10: snapshot comparison and self-check", "HE-004-I01B3"),
    ("negative-16-observation-projections.rbac.uid", "observed identity or digest",
     "R10: snapshot comparison and self-check", "HE-004-I01B3"),
    ("negative-17-observation-quota.used.configMaps", "used <= hard", "R10: self-check", "HE-004-I01B3"),
    ("negative-18-observation-quota.hard.configMaps", "requested <= hard - used", "HE-008, profile-side", "-"),
    ("negative-19-observation-quota.used.cpuMillis", "shape", "R10: self-check shape", "HE-004-I01B3"),
    ("negative-20-observation-quota.hard.cpuMillis", "shape", "R10: self-check shape", "HE-004-I01B3"),
    ("negative-21-observation-enforcement.policyGeneration", "enforcement proof mismatch", "R10: self-check",
     "HE-004-I01B3"),
    ("negative-22-observation-enforcement.hostPreflightDigest", "enforcement proof mismatch",
     "R10: self-check, and the snapshot comparison", "HE-004-I01B3"),
    ("negative-23-binding-scope.tenantId", "profile scope", "HE-008, profile-side", "-"),
    ("negative-24-binding-profileDigest", "profile digest", "HE-008, profile-side", "-"),
    ("negative-25-binding-namespace.uid", "namespace binding",
     "R10: the snapshot comparison; HE-008 holds the profile-side half", "HE-004-I01B3"),
    ("negative-26-binding-projections.serviceAccount.uid", "policy identity",
     "R10: the snapshot comparison; HE-008 holds the profile-side half", "HE-004-I01B3"),
    ("negative-27-binding-scope.namespace", "namespace binding", "R10: load-time check (status 13)", "HE-004-I01B2"),
];
/// HE-004-I01B3 (DESIGN-I01B3 rev 4 section 7; Q-I01B3-3 (a); I3D-5): the 18 rows' checkers and expected texts, each as
/// (case, `self_check`'s text, `refusals`' text). `self_check` checks the observation's half (VPO's label, or VPO's
/// generic text for the shape rows) and row 25's derived binding; `refusals` checks the snapshot comparison's half,
/// the changed value applied to the binding's corresponding member, and row 26's derived binding. The namespace has no
/// differs text, so row 14 is `self_check`'s only.
const I01B3_ROWS: [(&str, Option<&str>, Option<&str>); 18] = [
    ("negative-6-observation-challenge", Some(RESPONSE_SUBSTITUTION_TEXT), None),
    ("negative-7-observation-runNonce", Some(RESPONSE_SUBSTITUTION_TEXT), None),
    ("negative-8-observation-bindingDigest", Some(RESPONSE_SUBSTITUTION_TEXT), None),
    ("negative-9-observation-sequence", Some(RESPONSE_SUBSTITUTION_TEXT), None),
    ("negative-10-observation-previousObservationDigest", Some(RESPONSE_SUBSTITUTION_TEXT), None),
    ("negative-11-observation-observedAt", Some(STALE_OR_FUTURE_TEXT), None),
    ("negative-12-observation-expiresAt", Some(STALE_OR_FUTURE_TEXT), None),
    ("negative-13-observation-expiresAt", Some(FRESHNESS_WINDOW_TEXT), None),
    ("negative-14-observation-namespace.uid", Some(OBSERVED_NAMESPACE_TEXT), None),
    ("negative-15-observation-projections.resourceQuota.projectionDigest", Some(OBSERVED_IDENTITY_TEXT),
     Some("resourceQuota: differs from the signed value")),
    ("negative-16-observation-projections.rbac.uid", Some(OBSERVED_IDENTITY_TEXT),
     Some("rbac: differs from the signed value")),
    ("negative-17-observation-quota.used.configMaps", Some(QUOTA_HEADROOM_TEXT), None),
    ("negative-19-observation-quota.used.cpuMillis", Some(INVALID_OBSERVATION_TEXT), None),
    ("negative-20-observation-quota.hard.cpuMillis", Some(INVALID_OBSERVATION_TEXT), None),
    ("negative-21-observation-enforcement.policyGeneration", Some(ENFORCEMENT_PROOF_TEXT), None),
    ("negative-22-observation-enforcement.hostPreflightDigest", Some(ENFORCEMENT_PROOF_TEXT),
     Some("hostPreflightDigest: differs from the signed value")),
    ("negative-25-binding-namespace.uid", Some(OBSERVED_NAMESPACE_TEXT), None),
    ("negative-26-binding-projections.serviceAccount.uid", None, Some("serviceAccount: differs from the signed value")),
];
/// The contract's eleven snapshot lists and B1's closed-set entry for each (the `qual` snapshot's list inputs).
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

fn parse(text: &str) -> Value {
    json::parse(text).expect("the vendored JSON parses")
}

fn member<'a>(value: &'a Value, name: &str) -> &'a Value {
    value.get(name).unwrap_or_else(|| panic!("{name} is missing"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    member(value, name).as_str().unwrap_or_else(|| panic!("{name} is not text"))
}

fn integer(value: &Value, name: &str) -> u64 {
    member(value, name).as_int().and_then(|int| int.to_u64()).unwrap_or_else(|| panic!("{name} is not a count"))
}

fn texts<'a>(value: &'a Value, name: &str) -> Vec<&'a str> {
    let items = member(value, name).as_array().unwrap_or_else(|| panic!("{name} is not an array"));
    items.iter().map(|item| item.as_str().expect("a text item")).collect()
}

fn canonical(value: &Value) -> Vec<u8> {
    json::canonical(value).expect("a canonical encoding")
}

fn hex(data: &[u8]) -> String {
    sha256::hex(&sha256::digest(data))
}

fn vectors() -> Value {
    parse(PV)
}

fn positive(vectors: &Value) -> &Value {
    member(vectors, "positive")
}

/// A member of an object, by name, for writing.
fn member_mut<'a>(node: &'a mut Value, name: &JStr) -> &'a mut Value {
    match node {
        Value::Object(object) => object.get_key_mut(name).expect("the path's member exists"),
        _ => panic!("PV's paths name object members"),
    }
}

/// A copy of `document` with the member at `path` (object member names) replaced by `new`.
fn with_value(document: &Value, path: &[Value], new: &Value) -> Value {
    let name = |step: &Value| match step {
        Value::Str(name) => name.clone(),
        _ => panic!("PV's paths name object members"),
    };
    let mut copy = document.clone();
    let (last, parents) = path.split_last().expect("a non-empty path");
    let mut node = &mut copy;
    for step in parents {
        node = member_mut(node, &name(step));
    }
    match node {
        Value::Object(object) => {
            let last = name(last);
            assert!(object.contains_key(&last), "a negative replaces an existing member");
            object.insert(last, new.clone());
        }
        _ => panic!("PV's paths name object members"),
    }
    copy
}

/// The test binding: HE-008's binding as the gate compares it, `I01Binding::from_config` over `PV`'s positive binding
/// document (HE-004-I01B2: the one constructor, which `serve` calls on the configuration's checked member).
#[cfg(test)]
fn test_binding(positive: &Value) -> I01Binding {
    I01Binding::from_config(member(positive, "binding")).expect("the positive's binding has a digest and a nonce")
}

/// `PV`'s request negatives, each with its request: the positive's with the negative's one change.
fn request_negatives(vectors: &Value) -> Vec<(String, Value)> {
    request_negatives_on(vectors, member(positive(vectors), "request"))
}

/// `PV`'s request negatives applied to `request` (`PV`'s positive request, or HE-004-I01B4's triple's): each with
/// `request` changed in the negative's one member.
fn request_negatives_on(vectors: &Value, request: &Value) -> Vec<(String, Value)> {
    let cases = member(vectors, "negative").as_array().expect("the negatives are an array");
    cases.iter()
         .filter(|case| text(case, "document") == "request")
         .map(|case| {
             let path = member(case, "path").as_array().expect("a path");
             (text(case, "label").to_string(), with_value(request, path, member(case, "value")))
         })
         .collect()
}

/// The value at `path` (object member names) in `document`, if every step names a member.
fn value_at<'a>(document: &'a Value, path: &[Value]) -> Option<&'a Value> {
    path.iter().try_fold(document, |node, step| node.get(step.as_str()?))
}

/// HE-004-I01B4 (W3): row 74's file, and S1's complete triple in it.
fn digest_vectors() -> Value {
    parse(std::str::from_utf8(DIGEST_VECTORS).expect("the vendored file is UTF-8"))
}

fn triple(vectors: &Value) -> &Value {
    member(vectors, "complete")
}

/// One of W3's derived cases: `PV`'s label, document, path and value, and the derived document.
struct Derived<'a> {
    label: &'a str,
    document: &'a str,
    path: &'a [Value],
    value: &'a Value,
    derived: Value,
}

/// W3's derivation rule (R10-defined, MODEL_DEFINED R181): each of `PV`'s negatives 6-27 (`document` observation or
/// binding) applied to the triple, its one change, `value` at `path`, in the triple's `document`. Nothing is
/// recomputed.
fn derived_cases<'a>(vectors: &'a Value, triple: &Value) -> Vec<Derived<'a>> {
    let cases = member(vectors, "negative").as_array().expect("the negatives are an array");
    cases.iter()
         .filter(|case| ["observation", "binding"].contains(&text(case, "document")))
         .map(|case| {
             let (document, path) = (text(case, "document"), member(case, "path").as_array().expect("a path"));
             let value = member(case, "value");
             Derived { label: text(case, "label"), document, path, value,
                       derived: with_value(member(triple, document), path, value) }
         })
         .collect()
}

/// Each request negative's own refusal: the request rule it breaks.
fn expected(label: &str) -> RequestRefusal {
    match label {
        "negative-1-request-operation" => RequestRefusal::Schema("another operation"),
        "negative-2-request-runNonce" | "negative-3-request-bindingDigest" => RequestRefusal::Binding,
        "negative-4-request-sequence" | "negative-5-request-previousObservationDigest" => FIRST,
        other => panic!("{other} is not one of PV's request negatives"),
    }
}

#[test]
fn the_vendored_files_are_edge_v9_s_and_the_case_counts_hold() {
    assert_eq!((hex(CS.as_bytes()), CS.len()), (CS_PIN.0.to_string(), CS_PIN.1));
    assert_eq!((hex(PV.as_bytes()), PV.len()), (PV_PIN.0.to_string(), PV_PIN.1));
    let vectors = vectors();
    assert_eq!(text(&vectors, "evidenceClass"), "UNIT_VERIFICATION_ONLY");
    assert_eq!(member(&vectors, "nativeAcceptance").as_bool(), Some(false));
    let positive = positive(&vectors);
    for name in ["binding", "request", "observation"] {
        assert!(member(positive, name).as_object().is_some(), "{name}");
    }
    assert!(member(positive, "previous").is_null(), "the positive's request is a session's first");
    // 27 negatives: 5 on the request (replayed), 17 on the observation and 5 on the binding (not replayed).
    let cases = member(&vectors, "negative").as_array().expect("the negatives are an array");
    let count = |document: &str| cases.iter().filter(|case| text(case, "document") == document).count();
    assert_eq!((cases.len(), count("request"), count("observation"), count("binding")), (27, 5, 17, 5));
    // Each request negative changes one member of the request.
    let labels: Vec<&str> = cases.iter().filter(|case| text(case, "document") == "request")
                                 .map(|case| text(case, "label")).collect();
    assert_eq!(labels, REQUEST_NEGATIVES);
    for case in cases.iter().filter(|case| text(case, "document") == "request") {
        let path = texts(case, "path");
        assert!(path.len() == 1 && MEMBERS.contains(&path[0]), "{path:?}");
    }
}

#[test]
fn the_pv_case_table_names_pv_s_negatives_6_to_27_each_once() {
    // DESIGN-I01B rev 3 section 8.1: the labels are exactly PV's binding and observation negatives, in file order, each
    // once; the request negatives (1-5, replayed above) are not in it.
    let vectors = vectors();
    let cases = member(&vectors, "negative").as_array().expect("the negatives are an array");
    let labels: Vec<&str> = cases.iter().map(|case| text(case, "label")).collect();
    assert_eq!(labels.len(), 27);
    let table: Vec<&str> = PV_CASES.iter().map(|&(label, _, _, _)| label).collect();
    assert_eq!(table, labels[5..]);
    let mut once = table.clone();
    once.sort_unstable();
    once.dedup();
    assert_eq!(once.len(), 22);
    for (number, label) in table.iter().enumerate() {
        assert!(label.starts_with(&format!("negative-{}-", number + 6)), "{label}");
    }
    for label in REQUEST_NEGATIVES {
        assert!(!table.contains(&label), "{label}");
    }
    for case in &cases[5..] {
        assert!(["observation", "binding"].contains(&text(case, "document")), "{}", text(case, "label"));
    }
    // Each row names its rule, its checker and its packet; none is replayed in HE-004-I01B1.
    for (label, rule, checker, packet) in PV_CASES {
        assert!(!rule.is_empty() && (checker.starts_with("R10: ") || checker.starts_with("HE-008")), "{label}");
        assert!(["HE-004-I01B2", "HE-004-I01B3", "-"].contains(&packet), "{label}");
        assert_eq!(packet == "-", checker.starts_with("HE-008"), "{label}");
    }
    let count = |packet: &str| PV_CASES.iter().filter(|row| row.3 == packet).count();
    assert_eq!((count("HE-004-I01B2"), count("HE-004-I01B3"), count("-")), (1, 18, 3));
}

#[test]
fn the_schema_s_request_definition_is_the_one_i01_request_implements() {
    let schema = parse(CS);
    let request = member(member(&schema, "$defs"), "request");
    assert_eq!(text(request, "type"), "object");
    assert_eq!(member(request, "additionalProperties").as_bool(), Some(false));
    let mut required = texts(request, "required");
    required.sort_unstable();
    assert_eq!(required, MEMBERS);
    let properties = member(request, "properties");
    let mut named: Vec<&str> = properties.as_object().expect("the properties are an object").iter()
                                         .map(|(name, _)| name.as_str().expect("a text name")).collect();
    named.sort_unstable();
    assert_eq!(named, MEMBERS);
    assert_eq!(text(member(properties, "schemaVersion"), "const"), REQUEST_SCHEMA);
    assert_eq!(text(member(properties, "operation"), "const"), OBSERVE_POLICY);
    // The text forms `i01_request` checks: a sha256 digest, a run nonce of 1 to 63 characters, 64 hexadecimal digits.
    for (name, pattern, longest) in [("bindingDigest", "^sha256:[0-9a-f]{64}$", 71),
                                     ("previousObservationDigest", "^sha256:[0-9a-f]{64}$", 71),
                                     ("runNonce", "^[a-z0-9][a-z0-9.-]{0,62}$", 63),
                                     ("challenge", "^[0-9a-f]{64}$", 64)] {
        let property = member(properties, name);
        assert_eq!((text(property, "type"), text(property, "pattern")), ("string", pattern), "{name}");
        assert_eq!((integer(property, "minLength"), integer(property, "maxLength")), (1, longest), "{name}");
    }
    let sequence = member(properties, "sequence");
    assert_eq!(text(sequence, "type"), "integer");
    assert_eq!((integer(sequence, "minimum"), integer(sequence, "maximum")), (1, MAX_INTEGER));
    assert_eq!(ZERO_DIGEST, format!("sha256:{}", "0".repeat(64)));
}

#[test]
fn pv_s_positive_request_passes_every_check_with_the_test_binding() {
    let vectors = vectors();
    let positive = positive(&vectors);
    let request = member(positive, "request");
    // The positive's request names the digest of the binding document's canonical encoding, and the scope's nonce.
    let bound = test_binding(positive);
    assert_eq!(bound.signed_digest(), text(request, "bindingDigest"));
    assert_eq!(bound.signed_nonce(), text(request, "runNonce"));
    assert_eq!(bound.signed_digest(), sha256::prefixed(&canonical(member(positive, "binding"))));
    let bytes = canonical(request);
    let framed = frame(&bytes, false).expect("the positive's request frames");
    let checked = request_schema(&framed).expect("the positive's request has the schema's form");
    assert_eq!(checked, I01Request { binding_digest: text(request, "bindingDigest").to_string(),
                                     run_nonce: text(request, "runNonce").to_string(),
                                     challenge: text(request, "challenge").to_string(),
                                     sequence: integer(request, "sequence"),
                                     previous_digest: text(request, "previousObservationDigest").to_string() });
    assert_eq!((checked.sequence, checked.previous_digest.as_str()), (1, ZERO_DIGEST));
    assert_eq!(Chain::default().check(&checked), Ok(()));
    assert_eq!(binding_gate(&checked, Some(&bound)), Ok(()));
    assert_eq!(check_request(&bytes, false, &mut Chain::default(), Some(&bound)), Ok(checked));
    // I01a's case: no binding exists, so even the positive closes at the gate.
    assert_eq!(check_request(&bytes, false, &mut Chain::default(), None), Err(RequestRefusal::Binding));
}

/// One request negative refuses at its own step (the rule `expected` names), with `bound` the positive's test binding.
fn refuses_at_its_own_step(label: &str, request: &Value, bound: &I01Binding) {
    let refusal = expected(label);
    let bytes = canonical(request);
    // Every request negative is well framed: it changes one member's value.
    let framed = frame(&bytes, false).unwrap_or_else(|error| panic!("{label} frames: {error:?}"));
    let schema = request_schema(&framed);
    match refusal {
        RequestRefusal::Schema(_) => assert_eq!(schema, Err(refusal), "{label}"),
        RequestRefusal::Chain(_) => {
            let checked = schema.unwrap_or_else(|error| panic!("{label} has the schema's form: {error:?}"));
            assert_eq!(Chain::default().check(&checked), Err(refusal), "{label}");
            // Its binding members are the positive's, so the gate alone would pass it.
            assert_eq!(binding_gate(&checked, Some(bound)), Ok(()), "{label}");
        }
        RequestRefusal::Binding => {
            let checked = schema.unwrap_or_else(|error| panic!("{label} has the schema's form: {error:?}"));
            assert_eq!(Chain::default().check(&checked), Ok(()), "{label}");
            assert_eq!(binding_gate(&checked, Some(bound)), Err(refusal), "{label}");
            // The changed member is the refusal's cause (HE-004-I01B2: refused against the one from_config binding,
            // no second binding built): exactly one of the request's two binding members differs from the binding's.
            let differs = (checked.binding_digest != bound.signed_digest(), checked.run_nonce != bound.signed_nonce());
            assert!(differs == (true, false) || differs == (false, true), "{label}: {differs:?}");
        }
        other => panic!("{label}: no request negative refuses at {other:?}"),
    }
    // The whole check, in its order, with the test binding and without one (I01a's case): the same refusal.
    assert_eq!(check_request(&bytes, false, &mut Chain::default(), Some(bound)), Err(refusal), "{label}");
    assert_eq!(check_request(&bytes, false, &mut Chain::default(), None), Err(refusal), "{label}");
}

#[test]
fn each_request_negative_refuses_at_its_own_step() {
    let vectors = vectors();
    let bound = test_binding(positive(&vectors));
    let negatives = request_negatives(&vectors);
    assert_eq!(negatives.len(), REQUEST_NEGATIVES.len());
    for (label, request) in &negatives {
        refuses_at_its_own_step(label, request, &bound);
    }
}

#[test]
fn w3_s_derived_cases_are_pv_cases_22_rows_on_s1_s_triple() {
    // HE-004-I01B4, W3 (DESIGN-I01B4 rev 2 section 4.3): structure only, no checker.
    assert_eq!((hex(DIGEST_VECTORS), DIGEST_VECTORS.len()), (ROW_74_PIN.0.to_string(), ROW_74_PIN.1));
    let (vectors, digests) = (vectors(), digest_vectors());
    let (positive, triple) = (positive(&vectors), triple(&digests));
    // The triple's now, previous, scope window, nonces and challenge are PV's.
    assert!(json::json_eq(member(triple, "now"), member(positive, "now")));
    assert!(member(triple, "previous").is_null() && member(positive, "previous").is_null());
    let (scope, pv_scope) = (member(member(triple, "binding"), "scope"), member(member(positive, "binding"), "scope"));
    for name in ["validFrom", "expiresAt", "runNonce", "capacityNonce"] {
        assert_eq!(text(scope, name), text(pv_scope, name), "scope.{name}");
    }
    assert_eq!(text(member(triple, "request"), "challenge"), text(member(positive, "request"), "challenge"));
    assert_eq!(text(member(triple, "observation"), "challenge"), text(member(positive, "observation"), "challenge"));
    let cases = derived_cases(&vectors, triple);
    let labels: Vec<&str> = cases.iter().map(|case| case.label).collect();
    let table: Vec<&str> = PV_CASES.iter().map(|&(label, _, _, _)| label).collect();
    assert_eq!(labels, table);
    for case in &cases {
        let label = case.label;
        let original = member(triple, case.document);
        // The path exists in the triple's document, and the negative's value differs from the triple's there.
        let held = value_at(original, case.path).unwrap_or_else(|| panic!("{label}: the path is in the triple"));
        assert!(!json::json_eq(held, case.value), "{label}: the value differs from the triple's");
        // The derived document holds the value there, and equals the triple's document but at that one path.
        assert!(value_at(&case.derived, case.path).is_some_and(|got| json::json_eq(got, case.value)), "{label}");
        assert!(!json::json_eq(&case.derived, original), "{label}");
        assert!(json::json_eq(&with_value(&case.derived, case.path, held), original), "{label}: one change only");
    }
    let count = |document: &str| cases.iter().filter(|case| case.document == document).count();
    assert_eq!((cases.len(), count("observation"), count("binding")), (22, 17, 5));
}

#[test]
fn s1_s_triple_request_passes_and_pv_s_request_negatives_refuse_on_it() {
    // HE-004-I01B4, the request side (Q-I01B4D-1 (a), with I4D-4's two assertions).
    let (vectors, digests) = (vectors(), digest_vectors());
    let triple = triple(&digests);
    let (request, pv_request) = (member(triple, "request"), member(member(&vectors, "positive"), "request"));
    // (1) The triple's request is PV's positive request but at bindingDigest.
    let differing: Vec<&str> = request.as_object().expect("the request is an object").iter()
        .map(|(name, _)| name.as_str().expect("a text name"))
        .filter(|name| !pv_request.get(name).is_some_and(|theirs| json::json_eq(member(request, name), theirs)))
        .collect();
    assert_eq!(differing, ["bindingDigest"]);
    assert_eq!(request.as_object().map(|object| object.len()), pv_request.as_object().map(|object| object.len()));
    // Framing, the schema, a fresh chain and binding_gate, with the test binding built from the triple's binding (its
    // canonical digest is the request's bindingDigest, and the scope's runNonce).
    let bound = test_binding(triple);
    assert_eq!((bound.signed_digest(), bound.signed_nonce()), (TRIPLE_BINDING_DIGEST, text(request, "runNonce")));
    assert_eq!(text(request, "bindingDigest"), TRIPLE_BINDING_DIGEST);
    let bytes = canonical(request);
    let checked = request_schema(&frame(&bytes, false).expect("the triple's request frames"))
        .expect("the triple's request has the schema's form");
    assert_eq!((checked.sequence, checked.previous_digest.as_str()), (1, ZERO_DIGEST));
    assert_eq!(Chain::default().check(&checked), Ok(()));
    assert_eq!(binding_gate(&checked, Some(&bound)), Ok(()));
    assert_eq!(check_request(&bytes, false, &mut Chain::default(), Some(&bound)), Ok(checked));
    // PV's binding does not name the triple's request.
    assert_eq!(check_request(&bytes, false, &mut Chain::default(), Some(&test_binding(member(&vectors, "positive")))),
               Err(RequestRefusal::Binding));
    // PV's five request negatives, applied to the triple by the same rule: (2) each value differs from the triple's,
    // and each refuses at its own step.
    let negatives = request_negatives_on(&vectors, request);
    let labels: Vec<&str> = negatives.iter().map(|(label, _)| label.as_str()).collect();
    assert_eq!(labels, REQUEST_NEGATIVES);
    let cases = member(&vectors, "negative").as_array().expect("the negatives are an array");
    for case in cases.iter().filter(|case| text(case, "document") == "request") {
        let path = member(case, "path").as_array().expect("a path");
        let held = value_at(request, path).expect("the path is in the triple's request");
        assert!(!json::json_eq(held, member(case, "value")), "{}: the value differs", text(case, "label"));
    }
    for (label, negative) in &negatives {
        refuses_at_its_own_step(label, negative, &bound);
    }
}

#[test]
fn the_positive_request_in_other_encodings_refuses_at_framing() {
    let vectors = vectors();
    let request = member(positive(&vectors), "request");
    let bound = test_binding(positive(&vectors));
    let encoded = String::from_utf8(canonical(request)).expect("UTF-8");
    // The members in the vectors file's order (schemaVersion first), compactly: not sorted, so not canonical.
    let object = request.as_object().expect("the request is an object");
    let in_order: Vec<String> = object.iter()
        .map(|(name, value)| format!("{}:{}", String::from_utf8(canonical(&Value::Str(name.clone()))).expect("UTF-8"),
                                     String::from_utf8(canonical(value)).expect("UTF-8")))
        .collect();
    let in_order = format!("{{{}}}", in_order.join(","));
    assert_ne!(in_order, encoded, "the file's order is not the sorted one");
    for form in [in_order.clone(), in_order.replace("\":", "\": "), encoded.replace(",\"", ", \""),
                 encoded.replace("\":", "\": "), format!(" {encoded}")] {
        assert_eq!(check_request(form.as_bytes(), false, &mut Chain::default(), Some(&bound)),
                   Err(RequestRefusal::Canonical), "{form}");
    }
    // A line end (the vectors file's own layout) is not printable ASCII.
    for form in [format!("{encoded}\n"), encoded.replacen(",\"", ",\n  \"", 1)] {
        assert_eq!(check_request(form.as_bytes(), false, &mut Chain::default(), Some(&bound)),
                   Err(RequestRefusal::Bytes), "{form}");
    }
    assert!(check_request(encoded.as_bytes(), false, &mut Chain::default(), Some(&bound)).is_ok());
}

/// A row's packet in `PV_CASES`.
fn packet(label: &str) -> &'static str {
    PV_CASES.iter().find(|row| row.0 == label).map(|row| row.3).unwrap_or_else(|| panic!("{label} is not a PV case"))
}

/// Whether a row's R10 checker is the self-check alone (a document-level row), not the snapshot comparison.
fn document_level(label: &str) -> bool {
    PV_CASES.iter().any(|row| row.0 == label && row.3 == "HE-004-I01B3" && !row.2.contains("snapshot comparison"))
}

/// B1's list inputs for a snapshot's lists, each as the apiserver serves it under its closed-set request.
fn list_inputs(lists: &Value) -> Vec<ListInput> {
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

/// The `passing` capture as `CaptureFacts`: its one completed set, every slot taken, its two ages at the answer.
fn passing(capture: &Value) -> CaptureFacts {
    let set = member(capture, "sets").as_array().and_then(|sets| sets.first()).expect("one set");
    let answer = member(capture, "answer");
    let count = |value: &Value, name: &str| member(value, name).as_int().and_then(|int| int.to_i64()).expect("a count");
    let slots = member(set, "slots").as_object().expect("the slots").iter()
        .map(|(slot, state)| (slot.as_str().expect("a slot name").to_string(), state.as_str() == Some("TAKEN")))
        .collect();
    CaptureFacts {
        completed: true,
        expired: false,
        scheduled_after_now: false,
        slots,
        mono_age_ms: u64::try_from(count(answer, "monotonicMs") - count(set, "scheduledMonotonicMs")).expect("an age"),
        wall_age_ms: count(answer, "wallMs") - count(set, "startedWallMs"),
        record_digest: String::new(),
    }
}

/// The snapshot comparison (HE-004-I01B3): `i01_answer::derive` over the triple's `qual` snapshot, the enrolled record
/// and I06's closure with `binding`, then `refusals` with the `passing` capture; the answer list.
fn refused_by_the_snapshot(digests: &Value, binding: &Value) -> Vec<&'static str> {
    let fixtures = member(digests, "fixtures");
    let complete = member(digests, "complete");
    let snapshot = member(member(fixtures, "snapshots"), text(complete, "snapshot"));
    let lists = Inputs::new(list_inputs(member(snapshot, "lists"))).expect("the qual snapshot's lists");
    let closure = Closure::embedded().expect("the embedded closure reads");
    let derived = i01_answer::derive(&lists, member(snapshot, "resourceVersion"), member(snapshot, "configuration"),
                                     member(snapshot, "adm4LoadedHash"), member(fixtures, "record"), &closure, binding,
                                     &Value::Null, "", 0, u64::MAX)
        .unwrap_or_else(|refusal| panic!("the qual snapshot's derivations are built: {refusal}"));
    i01_answer::refusals(&derived, &passing(member(member(fixtures, "captures"), text(complete, "capture"))))
}

/// The binding member an observation path's value is compared with: a projection's member in `projections`, an
/// enforcement digest in `enforcementPins`.
fn binding_path(path: &[Value]) -> Vec<Value> {
    let mut steps = path.to_vec();
    if steps.first().and_then(Value::as_str) == Some("enforcement") {
        steps[0] = Value::str("enforcementPins");
    }
    steps
}

#[test]
fn w3_s_18_rows_refuse_at_their_checkers() {
    // HE-004-I01B3 (Q-I01B3-3 (a); I3D-5): each row as W3's derived case on S1's triple, against its checker.
    let (vectors, digests) = (vectors(), digest_vectors());
    let triple = triple(&digests);
    let request = request_schema(member(triple, "request")).expect("the triple's request has the schema's form");
    let now = utc_seconds(text(triple, "now")).expect("the triple's now");
    let (binding, observation) = (member(triple, "binding"), member(triple, "observation"));
    // The triple itself passes both checkers.
    assert!(member(triple, "previous").is_null());
    assert_eq!(i01_answer::self_check(observation, &request, binding, now, None), Ok(()));
    assert_eq!(refused_by_the_snapshot(&digests, binding), Vec::<&str>::new());
    let cases = derived_cases(&vectors, triple);
    let rows: Vec<&Derived> = cases.iter().filter(|case| packet(case.label) == "HE-004-I01B3").collect();
    let labels: Vec<&str> = rows.iter().map(|case| case.label).collect();
    assert_eq!(labels, I01B3_ROWS.map(|row| row.0));
    let (mut by_self_check, mut by_refusals) = (0, 0);
    for (case, (label, self_checked, refused)) in rows.iter().zip(I01B3_ROWS) {
        let (checked, signed) = match case.document {
            "observation" => (&case.derived, binding),
            _ => (observation, &case.derived),
        };
        if let Some(want) = self_checked {
            assert_eq!(i01_answer::self_check(checked, &request, signed, now, None), Err(want), "{label}");
            by_self_check += 1;
        }
        if let Some(want) = refused {
            let changed = match case.document {
                "observation" => with_value(binding, &binding_path(case.path), case.value),
                _ => case.derived.clone(),
            };
            assert_eq!(refused_by_the_snapshot(&digests, &changed), [want], "{label}");
            by_refusals += 1;
        }
    }
    // 17 rows through self_check (all but 26), 4 through refusals (15, 16, 22 and 26).
    assert_eq!((by_self_check, by_refusals), (17, 4));
}

#[test]
fn pv_s_v1_document_rows_refuse_at_self_check() {
    // PV's own cases for the document-level rows (6-13, 17, 19-21), on PV's v1 positive; the snapshot-comparison rows
    // have no v1 snapshot fixture.
    let vectors = vectors();
    let positive = positive(&vectors);
    let request = request_schema(member(positive, "request")).expect("PV's request has the schema's form");
    let now = utc_seconds(text(positive, "now")).expect("PV's now");
    let (binding, observation) = (member(positive, "binding"), member(positive, "observation"));
    assert_eq!(i01_answer::self_check(observation, &request, binding, now, None), Ok(()));
    let cases = member(&vectors, "negative").as_array().expect("the negatives are an array");
    let mut replayed = 0;
    for (label, self_checked, _) in I01B3_ROWS {
        if !document_level(label) {
            continue;
        }
        let case = cases.iter().find(|case| text(case, "label") == label).expect("the row's PV case");
        assert_eq!(text(case, "document"), "observation", "{label}");
        let path = member(case, "path").as_array().expect("a path");
        let changed = with_value(observation, path, member(case, "value"));
        let want = self_checked.expect("a document-level row's self-check text");
        assert_eq!(i01_answer::self_check(&changed, &request, binding, now, None), Err(want), "{label}");
        replayed += 1;
    }
    assert_eq!(replayed, 12);
}
