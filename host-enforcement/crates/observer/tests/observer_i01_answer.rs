//! HE-004-I01B3 (DESIGN-I01B3 rev 4 sections 3 and 7; the owner's Q-I01B3-SPLIT and the monitor's Q-I01B3-1..13 and
//! Q-I01B3D-1..3): `i01_answer`'s unit tests, over the I01 digest contract v2's complete positive
//! (`contracts/i01-digests-v2/vectors.json`, edge record v11's row 74: the `qual` snapshot, the enrolled record, the
//! `passing` capture and S1's triple).
//! - `derive`: each `Err` case, the one way each input leaves `Derived` unbuildable, and the per-key results it keeps
//!   without comparing them (Q-I01B3D-1 (a)).
//! - The `CaptureFacts` mapping to the capture gate: no completed set, an expired view, the slots and the two ages.
//! - `refusals`: per key, in key order, the derivation's refusal, then the gate's, then the comparison; each text once.
//! - `answer`: the complete positive under Q-I01B3D-3 (a') [I3D-2; I3E-9], exactly two members replaced; each step's
//!   refusal in order (the binding in D-3's form, the answer list, the record digest, each window bound, the rollback,
//!   the observation rules, the bound); a sequence-2 request not refused by the chain rules [I3D-1], and I3E-8's three
//!   sequence-2 faults.
//! - `self_check`: DIB section 8.1's continuation cases with `previous` given [I3D-6]; VPO's rule order, the shape's
//!   generic text and the byte bound's label; VPC's `_time` reading (years 0001-9999).

use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::sha256;
use planeon_observer::i01_answer::{self, CaptureFacts, Derived, ANSWER_ROLLBACK_TEXT, ANSWER_WINDOW_TEXT, CHAIN_GAP_TEXT,
                                   CLOCK_ROLLBACK_TEXT, ENFORCEMENT_PROOF_TEXT, FRESHNESS_WINDOW_TEXT,
                                   INITIAL_CHAIN_TEXT, INVALID_OBSERVATION_TEXT, OBSERVATION_BYTES_TEXT,
                                   OBSERVED_IDENTITY_TEXT, OBSERVED_NAMESPACE_TEXT, QUOTA_HEADROOM_TEXT,
                                   RECORD_DIGEST_TEXT, REQUEST_BINDING_TEXT, RESPONSE_SUBSTITUTION_TEXT, RESTART_TEXT,
                                   STALE_OR_FUTURE_TEXT};
use planeon_observer::i01_digest::{DigestKey, BROKER_ROW_INCOMPLETE};
use planeon_observer::i01_request::{request_schema, I01Request, ZERO_DIGEST};
use planeon_observer::inputs::{Inputs, ListBody, ListInput, Resource};
use planeon_observer::kernel_text::utc_seconds;
use planeon_observer::snapshot::Closure;

const VECTORS: &[u8] = include_bytes!("../../../contracts/i01-digests-v2/vectors.json");
/// The triple's binding digest: `sha256:` and the hex SHA-256 of the binding's canonical bytes.
const BINDING_DIGEST: &str = "sha256:6e745318b14b5c5e3139516bd581405cb9627303e804a15067888eff45e77b94";
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
/// The three gated keys' texts, in key order.
const NOT_PASSED: [&str; 3] = ["mutationBroker: broker capture not passed",
                               "networkEnforcementDigest: agent capture not passed",
                               "hostPreflightDigest: capture set not passed"];
const TOO_OLD: [&str; 3] = ["mutationBroker: capture set too old", "networkEnforcementDigest: capture set too old",
                            "hostPreflightDigest: capture set too old"];

fn parse(raw: &[u8]) -> Value {
    json::parse(std::str::from_utf8(raw).expect("the vendored file is UTF-8")).expect("the vendored JSON parses")
}

fn member<'a>(value: &'a Value, name: &str) -> &'a Value {
    value.get(name).unwrap_or_else(|| panic!("{name} is missing"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    member(value, name).as_str().unwrap_or_else(|| panic!("{name} is not text"))
}

/// The object at `path` (member names), for writing.
fn at_mut<'a>(value: &'a mut Value, path: &[&str]) -> &'a mut Object {
    let mut node = value;
    for step in path {
        node = match node {
            Value::Object(object) => {
                object.get_key_mut(&JStr::new(step)).unwrap_or_else(|| panic!("{step} is missing"))
            }
            _ => panic!("{step}: not an object member"),
        };
    }
    match node {
        Value::Object(object) => object,
        _ => panic!("{path:?} is not an object"),
    }
}

/// `value` with the member `name` of the object at `path` set to `new`.
fn set(value: &mut Value, path: &[&str], name: &str, new: Value) {
    at_mut(value, path).insert(JStr::new(name), new);
}

/// `value` without the member `name` of the object at `path`.
fn remove(value: &mut Value, path: &[&str], name: &str) {
    assert!(at_mut(value, path).remove(&JStr::new(name)).is_some(), "{path:?}.{name} is removed");
}

/// The seconds of a canonical UTC text (1970 on).
fn seconds(text: &str) -> i64 {
    i64::try_from(utc_seconds(text).expect("a canonical UTC text")).expect("seconds")
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

/// The complete positive's inputs to `derive`, each a value a test may change: the `qual` snapshot (its lists, the
/// read's resourceVersion, the configuration and ADM-4's loaded hash), the enrolled record, the triple's binding, the
/// triple's observation's quota pair and generation, and a configuration window that does not bind.
struct Case {
    vectors: Value,
    snapshot: Value,
    record: Value,
    binding: Value,
    quota: Value,
    generation: String,
    not_before: u64,
    not_after: u64,
}

impl Case {
    fn complete() -> Case {
        let vectors = parse(VECTORS);
        let complete = member(&vectors, "complete");
        let fixtures = member(&vectors, "fixtures");
        let snapshot = member(member(fixtures, "snapshots"), text(complete, "snapshot")).clone();
        let record = member(fixtures, "record").clone();
        let binding = member(complete, "binding").clone();
        let observation = member(complete, "observation");
        let quota = member(observation, "quota").clone();
        let generation = text(observation, "generation").to_string();
        let not_before = utc_seconds("2026-09-08T00:00:00Z").expect("a canonical UTC text");
        let not_after = utc_seconds("2026-09-08T00:10:00Z").expect("a canonical UTC text");
        Case { vectors, snapshot, record, binding, quota, generation, not_before, not_after }
    }

    fn complete_member(&self, name: &str) -> &Value {
        member(member(&self.vectors, "complete"), name)
    }

    fn derive(&self) -> Result<Derived, &'static str> {
        let lists = Inputs::new(list_inputs(member(&self.snapshot, "lists"))).expect("the snapshot's lists");
        let closure = Closure::embedded().expect("the embedded closure reads");
        i01_answer::derive(&lists, member(&self.snapshot, "resourceVersion"), member(&self.snapshot, "configuration"),
                           member(&self.snapshot, "adm4LoadedHash"), &self.record, &closure, &self.binding,
                           &self.quota, &self.generation, self.not_before, self.not_after)
    }

    fn derived(&self) -> Derived {
        self.derive().unwrap_or_else(|refusal| panic!("the derivations are built: {refusal}"))
    }

    /// The `passing` capture as `CaptureFacts`: its one completed set, all slots taken, with its two ages at the
    /// answer; the record digest is the record's `sha256:` digest, the derived and signed `hostPreflightDigest`.
    fn passing(&self) -> CaptureFacts {
        let capture = member(member(member(&self.vectors, "fixtures"), "captures"), "passing");
        let sets = member(capture, "sets").as_array().expect("the sets");
        let set = sets.first().expect("one set");
        let answer = member(capture, "answer");
        let count = |value: &Value, name: &str| {
            member(value, name).as_int().and_then(|int| int.to_i64()).expect("a count")
        };
        let slots = member(set, "slots").as_object().expect("the slots").iter()
            .map(|(slot, state)| (slot.as_str().expect("a slot name").to_string(), state.as_str() == Some("TAKEN")))
            .collect();
        CaptureFacts {
            completed: true,
            expired: false,
            scheduled_after_now: false,
            slots,
            mono_age_ms: u64::try_from(count(answer, "monotonicMs") - count(set, "scheduledMonotonicMs"))
                .expect("an age"),
            wall_age_ms: count(answer, "wallMs") - count(set, "startedWallMs"),
            record_digest: sha256::prefixed(&json::canonical(&self.record).expect("canonical bytes")),
        }
    }

    /// The binding's `hostPreflightDigest` pin set to the record's digest, after a change to the record.
    fn repin(&mut self) {
        let digest = sha256::prefixed(&json::canonical(&self.record).expect("canonical bytes"));
        set(&mut self.binding, &["enforcementPins"], "hostPreflightDigest", Value::str(&digest));
    }

    /// The triple's request: sequence 1, the zero digest, the binding's digest and nonce.
    fn request(&self) -> I01Request {
        request_schema(self.complete_member("request")).expect("the triple's request has the schema's form")
    }

    /// The triple's request naming `derived`'s signed binding (after a change to the binding).
    fn request_for(&self, derived: &Derived) -> I01Request {
        I01Request { binding_digest: derived.bound_digest().to_string(), run_nonce: derived.bound_nonce().to_string(),
                     ..self.request() }
    }

    /// The triple's observation.
    fn observation(&self) -> Value {
        self.complete_member("observation").clone()
    }
}

/// The milliseconds of a canonical UTC text, the wall reading `answer` takes.
fn millis(text: &str) -> u64 {
    utc_seconds(text).expect("a canonical UTC text") * 1000
}

/// An observation parsed from `answer`'s bytes.
fn parsed(bytes: &[u8]) -> Value {
    parse(bytes)
}

/// `value` with its member `name` (at the top level or the object at `path`) set to `new`.
fn with(value: &Value, path: &[&str], name: &str, new: Value) -> Value {
    let mut copy = value.clone();
    set(&mut copy, path, name, new);
    copy
}

#[test]
fn derive_builds_the_complete_positives_derivations() {
    let case = Case::complete();
    let derived = case.derived();
    let observation = case.complete_member("observation");
    // Every projection and digest derived, in key order, each the observation's.
    let keys: Vec<DigestKey> = derived.policy_values().iter().map(|(key, _)| *key).collect();
    assert_eq!(keys, DigestKey::POLICIES);
    for (key, outcome) in derived.policy_values() {
        let value = outcome.as_ref().unwrap_or_else(|refusal| panic!("{key:?}: {refusal}"));
        let mut identity = value.identity.as_object().cloned().expect("an identity object");
        identity.insert(JStr::new("resourceVersion"), value.resource_version.clone());
        assert!(json::json_eq(&Value::Object(identity), member(member(observation, "projections"), key.name())),
                "{key:?}");
    }
    let keys: Vec<DigestKey> = derived.digest_values().iter().map(|(key, _)| *key).collect();
    assert_eq!(keys, DigestKey::DIGESTS);
    for (key, outcome) in derived.digest_values() {
        let value = outcome.as_ref().unwrap_or_else(|refusal| panic!("{key:?}: {refusal}"));
        assert_eq!(value.digest, text(member(observation, "enforcement"), key.name()), "{key:?}");
    }
    // The namespace member: the qual Namespace's name and uid, and the read's resourceVersion text.
    assert!(json::json_eq(derived.namespace_member(), member(observation, "namespace")));
    assert_eq!(text(derived.namespace_member(), "resourceVersion"), text(&case.snapshot, "resourceVersion"));
    // The signed binding, its digest and its nonce, computed as the binding gate's are (B3-6 (3)).
    assert!(json::json_eq(derived.binding_member(), &case.binding));
    assert_eq!(derived.bound_digest(), BINDING_DIGEST);
    assert_eq!(derived.bound_digest(), sha256::prefixed(&json::canonical(&case.binding).expect("canonical bytes")));
    assert_eq!(derived.bound_nonce(), text(member(&case.binding, "scope"), "runNonce"));
    // The record, its boot id, the quota pair, the generation and the three windows.
    assert!(json::json_eq(derived.enrolled_record(), &case.record));
    assert_eq!(derived.boot_id(), text(member(&case.record, "host"), "bootId"));
    assert!(json::json_eq(derived.quota_pair(), &case.quota));
    assert_eq!(derived.generation_hex(), case.generation);
    let scope = member(&case.binding, "scope");
    assert_eq!(derived.scope_window(), (seconds(text(scope, "validFrom")), seconds(text(scope, "expiresAt"))));
    let record_scope = member(&case.record, "scope");
    assert_eq!(derived.record_window(),
               (seconds(text(record_scope, "validFrom")), seconds(text(record_scope, "expiresAt"))));
    assert_eq!(derived.config_window(),
               (i64::try_from(case.not_before).expect("seconds"), i64::try_from(case.not_after).expect("seconds")));
}

#[test]
fn derive_keeps_each_per_key_refusal_and_compares_nothing() {
    // A changed signed value is not compared at derive time (Q-I01B3D-1 (a)): the derivations are the positive's.
    let positive = Case::complete().derived();
    let mut case = Case::complete();
    set(&mut case.binding, &["projections", "rbac"], "projectionDigest", Value::str("sha256:00"));
    set(&mut case.binding, &["enforcementPins"], "hostPreflightDigest", Value::str("sha256:11"));
    set(&mut case.binding, &["namespace"], "uid", Value::str("another-uid"));
    let derived = case.derived();
    for (ours, theirs) in derived.policy_values().iter().zip(positive.policy_values()) {
        let (ours, theirs) = (ours.1.as_ref().expect("derived"), theirs.1.as_ref().expect("derived"));
        assert!(json::json_eq(&ours.identity, &theirs.identity));
    }
    for (ours, theirs) in derived.digest_values().iter().zip(positive.digest_values()) {
        assert_eq!(ours.1.as_ref().expect("derived").digest, theirs.1.as_ref().expect("derived").digest);
    }
    // A key's own refusal is kept, not raised: the record's BROKER row removed, the binding's quota name changed.
    let mut case = Case::complete();
    remove(&mut case.record, &["roles"], "BROKER");
    set(&mut case.binding, &["projections", "resourceQuota"], "name", Value::str("another-quota"));
    let derived = case.derived();
    let outcome = |key: DigestKey| {
        derived.policy_values().iter().find(|(own, _)| *own == key).map(|(_, outcome)| outcome).expect("each key")
    };
    assert_eq!(outcome(DigestKey::MutationBroker).as_ref().err(), Some(&BROKER_ROW_INCOMPLETE));
    assert_eq!(outcome(DigestKey::ResourceQuota).as_ref().err(), Some(&"resourceQuota: name differs from the binding"));
    assert!(outcome(DigestKey::LimitRange).is_ok());
    assert_eq!(derived.policy_values().len() + derived.digest_values().len(), 11);
}

#[test]
fn derive_refuses_only_a_derived_it_cannot_build() {
    let refuses = |case: &Case, want: &str, what: &str| {
        assert_eq!(case.derive().err(), Some(want), "{what}");
    };
    // The binding's digest or nonce (B3-6 (3)): no scope, no runNonce, a runNonce not text, no canonical bytes.
    let mut case = Case::complete();
    remove(&mut case.binding, &[], "scope");
    refuses(&case, REQUEST_BINDING_TEXT, "no scope");
    let mut case = Case::complete();
    remove(&mut case.binding, &["scope"], "runNonce");
    refuses(&case, REQUEST_BINDING_TEXT, "no runNonce");
    let mut case = Case::complete();
    set(&mut case.binding, &["scope"], "runNonce", Value::int(7));
    refuses(&case, REQUEST_BINDING_TEXT, "a runNonce not text");
    let mut case = Case::complete();
    let surrogate = json::parse("\"\\ud800\"").expect("a lone surrogate");
    set(&mut case.binding, &["observer"], "note", surrogate);
    refuses(&case, REQUEST_BINDING_TEXT, "a binding without canonical bytes");
    // The binding's and the record's scope windows: missing or not canonical UTC text.
    for scope_of in ["binding", "record"] {
        for (name, value) in [("validFrom", None), ("expiresAt", None), ("validFrom", Some("2026-9-08T00:00:00Z")),
                              ("expiresAt", Some("2026-09-31T00:00:00Z")), ("validFrom", Some("2026-09-08 00:00:00Z")),
                              ("expiresAt", Some("0000-01-01T00:00:00Z")),
                              ("validFrom", Some("2026-09-08T24:00:00Z"))] {
            let mut case = Case::complete();
            let target = if scope_of == "binding" { &mut case.binding } else { &mut case.record };
            match value {
                None => remove(target, &["scope"], name),
                Some(value) => set(target, &["scope"], name, Value::str(value)),
            }
            refuses(&case, ANSWER_WINDOW_TEXT, &format!("{scope_of} scope.{name} {value:?}"));
        }
    }
    let mut case = Case::complete();
    remove(&mut case.record, &[], "scope");
    refuses(&case, ANSWER_WINDOW_TEXT, "a record without a scope");
    // The record's boot id.
    let mut case = Case::complete();
    remove(&mut case.record, &["host"], "bootId");
    refuses(&case, INVALID_OBSERVATION_TEXT, "no host.bootId");
    let mut case = Case::complete();
    set(&mut case.record, &["host"], "bootId", Value::Null);
    refuses(&case, INVALID_OBSERVATION_TEXT, "a host.bootId not text");
    let mut case = Case::complete();
    remove(&mut case.record, &[], "host");
    refuses(&case, INVALID_OBSERVATION_TEXT, "no host");
    // The namespace member: no qualification namespace, one naming no listed Namespace, a Namespace without a uid,
    // a resourceVersion not text.
    let mut case = Case::complete();
    remove(&mut case.snapshot, &["configuration"], "qualificationNamespace");
    refuses(&case, OBSERVED_NAMESPACE_TEXT, "no qualificationNamespace");
    let mut case = Case::complete();
    set(&mut case.snapshot, &["configuration"], "qualificationNamespace", Value::str("unlisted"));
    refuses(&case, OBSERVED_NAMESPACE_TEXT, "an unlisted namespace");
    let mut case = Case::complete();
    let namespaces = match member(member(&case.snapshot, "lists"), "namespaces") {
        Value::Array(items) => items.iter().map(|item| {
            let mut item = item.clone();
            if text(member(&item, "metadata"), "name") == "planeon-qual" {
                remove(&mut item, &["metadata"], "uid");
            }
            item
        }).collect(),
        _ => panic!("the namespaces list"),
    };
    set(&mut case.snapshot, &["lists"], "namespaces", Value::Array(namespaces));
    refuses(&case, OBSERVED_NAMESPACE_TEXT, "a Namespace without a uid");
    let mut case = Case::complete();
    set(&mut case.snapshot, &[], "resourceVersion", Value::int(100));
    refuses(&case, OBSERVED_NAMESPACE_TEXT, "a resourceVersion not text");
}

#[test]
fn derive_reads_utc_text_as_vpcs_time_does() {
    // VPC's `_time` (validate_proxy_contract.py:98-101): every canonical UTC text from year 0001 to 9999; before 1970
    // as negative seconds, read 2,000 years later and moved back.
    for (from, want) in [("1969-12-31T23:59:59Z", -1), ("1970-01-01T00:00:00Z", 0),
                         ("1900-03-01T00:00:00Z", -2_203_891_200), ("0001-01-01T00:00:00Z", -62_135_596_800),
                         ("1600-02-29T00:00:00Z", -11_670_998_400)] {
        let mut case = Case::complete();
        set(&mut case.binding, &["scope"], "validFrom", Value::str(from));
        assert_eq!(case.derived().scope_window().0, want, "{from}");
    }
    for from in ["0000-12-31T00:00:00Z", "1900-02-29T00:00:00Z", "+999-01-01T00:00:00Z", "1969-12-31T23:59:60Z"] {
        let mut case = Case::complete();
        set(&mut case.binding, &["scope"], "validFrom", Value::str(from));
        assert_eq!(case.derive().err(), Some(ANSWER_WINDOW_TEXT), "{from}");
    }
}

/// The complete positive's derivations with `facts` changed by `change`: the answer list.
fn listed(change: impl Fn(&mut CaptureFacts)) -> Vec<&'static str> {
    let case = Case::complete();
    let mut facts = case.passing();
    change(&mut facts);
    i01_answer::refusals(&case.derived(), &facts)
}

#[test]
fn capture_facts_map_to_the_capture_gate() {
    assert_eq!(listed(|_| ()), Vec::<&str>::new());
    // No completed set: None, each gated key's own text.
    assert_eq!(listed(|facts| facts.completed = false), NOT_PASSED);
    assert_eq!(listed(|facts| {
        facts.completed = false;
        facts.expired = true;
    }), NOT_PASSED);
    // An expired view: a set whose slots are all not taken, whatever the slots say.
    assert_eq!(listed(|facts| facts.expired = true), NOT_PASSED);
    // The slots: role/BROKER not taken refuses mutationBroker and hostPreflightDigest (whose five role slots hold it);
    // the agent's slot refuses networkEnforcementDigest and hostPreflightDigest; a slot listed twice must be taken
    // twice.
    let untake = |name: &'static str| move |facts: &mut CaptureFacts| {
        for slot in &mut facts.slots {
            if slot.0 == name {
                slot.1 = false;
            }
        }
    };
    assert_eq!(listed(untake("role/BROKER")), [NOT_PASSED[0], NOT_PASSED[2]]);
    assert_eq!(listed(untake("backend/NETWORK_POLICY_AGENT")), [NOT_PASSED[1], NOT_PASSED[2]]);
    assert_eq!(listed(untake("role/SERVER")), [NOT_PASSED[2]]);
    assert_eq!(listed(|facts| facts.slots.retain(|slot| slot.0 != "lifecycle")), [NOT_PASSED[2]]);
    assert_eq!(listed(|facts| facts.slots.push(("role/BROKER".to_string(), false))), [NOT_PASSED[0], NOT_PASSED[2]]);
    // The two ages, each within 0..=90,000 ms; a set scheduled after the answer is too old whatever its age.
    assert_eq!(listed(|facts| facts.mono_age_ms = 90_000), Vec::<&str>::new());
    assert_eq!(listed(|facts| facts.wall_age_ms = 90_000), Vec::<&str>::new());
    assert_eq!(listed(|facts| facts.wall_age_ms = 0), Vec::<&str>::new());
    assert_eq!(listed(|facts| facts.mono_age_ms = 90_001), TOO_OLD);
    assert_eq!(listed(|facts| facts.wall_age_ms = 90_001), TOO_OLD);
    assert_eq!(listed(|facts| facts.wall_age_ms = -1), TOO_OLD);
    assert_eq!(listed(|facts| facts.scheduled_after_now = true), TOO_OLD);
    // The record digest is no gate input (Q-CB-11 (a)); the answer compares it.
    assert_eq!(listed(|facts| facts.record_digest.clear()), Vec::<&str>::new());
}

#[test]
fn refusals_compose_derivation_then_gate_then_comparison_each_text_once() {
    let mut facts = Case::complete().passing();
    // The comparison: each key's identity without resourceVersion against the signed projection, each digest against
    // its pin, the texts in key order.
    let mut case = Case::complete();
    set(&mut case.binding, &["enforcementPins"], "hostPreflightDigest", Value::str("sha256:11"));
    set(&mut case.binding, &["projections", "limitRange"], "uid", Value::str("another-uid"));
    set(&mut case.binding, &["projections", "admissionPolicy"], "kind", Value::str("Another"));
    assert_eq!(i01_answer::refusals(&case.derived(), &facts),
               ["admissionPolicy: differs from the signed value", "limitRange: differs from the signed value",
                "hostPreflightDigest: differs from the signed value"]);
    // Python equality: an identity member added to the signed projection differs; null against null is equal.
    let mut case = Case::complete();
    set(&mut case.binding, &["projections", "rbac"], "resourceVersion", Value::str("100"));
    assert_eq!(i01_answer::refusals(&case.derived(), &facts), ["rbac: differs from the signed value"]);
    let mut case = Case::complete();
    remove(&mut case.binding, &["projections"], "admissionPolicy");
    assert_eq!(i01_answer::refusals(&case.derived(), &facts), ["admissionPolicy: differs from the signed value"]);
    // The gate comes before the comparison: mutationBroker differs and its gate fails, so the gate's text alone.
    let mut case = Case::complete();
    set(&mut case.binding, &["projections", "mutationBroker"], "uid", Value::str("another-uid"));
    assert_eq!(i01_answer::refusals(&case.derived(), &facts), ["mutationBroker: differs from the signed value"]);
    facts.scheduled_after_now = true;
    assert_eq!(i01_answer::refusals(&case.derived(), &facts), TOO_OLD);
    facts.scheduled_after_now = false;
    // The derivation comes first: the BROKER row removed and the projection's uid changed, the row's text alone;
    // a derivation refusal is not gated.
    remove(&mut case.record, &["roles"], "BROKER");
    let derived = case.derived();
    assert_eq!(i01_answer::refusals(&derived, &facts),
               [BROKER_ROW_INCOMPLETE, "hostPreflightDigest: differs from the signed value"]);
    facts.completed = false;
    assert_eq!(i01_answer::refusals(&derived, &facts), [BROKER_ROW_INCOMPLETE, NOT_PASSED[1], NOT_PASSED[2]]);
    // Each text once: no NetworkPolicy refuses networkPolicy and networkEnforcementDigest with one text.
    let facts = Case::complete().passing();
    let mut case = Case::complete();
    set(&mut case.snapshot, &["lists"], "networkPolicies", Value::Array(Vec::new()));
    assert_eq!(i01_answer::refusals(&case.derived(), &facts), ["networkPolicy: count is not one"]);
}

// ------------------------------------------------------------------------------------------- answer and self_check

/// The triple's observedAt, the wall reading of the complete positive's answer.
const OBSERVED_AT: &str = "2026-09-08T00:00:01Z";

/// `sha256:` and the hex SHA-256 of a value's canonical bytes.
fn digest_of(value: &Value) -> String {
    sha256::prefixed(&json::canonical(value).expect("canonical bytes"))
}

/// `answer` over `case`, its request naming the case's binding, at `wall`, after `last`.
fn answered(case: &Case, facts: &CaptureFacts, wall: &str, last: Option<u64>) -> Result<Vec<u8>, &'static str> {
    let derived = case.derived();
    i01_answer::answer(&derived, &case.request_for(&derived), facts, millis(wall), last)
}

#[test]
fn the_complete_positive_is_answered_as_the_triples_observation_but_two_members() {
    // Q-I01B3D-3 (a') [I3D-2; I3E-9]: derive and answer on the qual snapshot and the passing capture, with the triple's
    // request and generation, the triple's quota pair and a configuration window that does not bind (stated inputs),
    // and wall_ms the triple's observedAt.
    let case = Case::complete();
    let observation = case.observation();
    assert_eq!(text(&observation, "observedAt"), OBSERVED_AT);
    let bytes = i01_answer::answer(&case.derived(), &case.request(), &case.passing(), millis(OBSERVED_AT), None)
        .expect("the complete positive is answered");
    // Exactly two members replaced: observerBootId by the record's host.bootId (Q-I01B-10's source) and expiresAt by
    // observedAt + 5 s; every other member byte-equal, the namespace's resourceVersion the read's.
    let boot_id = member(member(&case.record, "host"), "bootId").clone();
    let mut expected = with(&observation, &[], "observerBootId", boot_id);
    set(&mut expected, &[], "expiresAt", Value::str("2026-09-08T00:00:06Z"));
    assert_eq!(String::from_utf8(bytes.clone()).expect("UTF-8"),
               String::from_utf8(json::canonical(&expected).expect("canonical bytes")).expect("UTF-8"));
    let answer = parsed(&bytes);
    let mut differing: Vec<&str> = observation.as_object().expect("an object").iter()
        .map(|(name, _)| name.as_str().expect("a text name"))
        .filter(|name| !json::json_eq(member(&answer, name), member(&observation, name)))
        .collect();
    differing.sort_unstable();
    assert_eq!(differing, ["expiresAt", "observerBootId"]);
    assert_eq!(answer.as_object().map(Object::len), Some(14));
    assert_eq!(text(member(&answer, "namespace"), "resourceVersion"), text(&case.snapshot, "resourceVersion"));
    // The public self_check passes on the answer, with the triple's now and previous null, as on the triple's own.
    let now = utc_seconds(text(member(&case.vectors, "complete"), "now")).expect("the triple's now");
    assert!(case.complete_member("previous").is_null());
    assert_eq!(i01_answer::self_check(&answer, &case.request(), &case.binding, now, None), Ok(()));
    assert_eq!(i01_answer::self_check(&observation, &case.request(), &case.binding, now, None), Ok(()));
}

#[test]
fn answer_refuses_at_each_step_in_order() {
    let case = Case::complete();
    let (derived, facts, request) = (case.derived(), case.passing(), case.request());
    let wall = millis(OBSERVED_AT);
    assert!(i01_answer::answer(&derived, &request, &facts, wall, None).is_ok());
    // 1. The binding [B3-6 (3)]: a request naming another nonce or digest (D-3's form), or a changed binding.
    for other in [I01Request { run_nonce: "other-nonce".to_string(), ..request.clone() },
                  I01Request { binding_digest: ZERO_DIGEST.to_string(), ..request.clone() }] {
        assert_eq!(i01_answer::answer(&derived, &other, &facts, wall, None), Err(REQUEST_BINDING_TEXT));
    }
    let mut changed = Case::complete();
    set(&mut changed.binding, &["scope"], "tenantId", Value::str("another-tenant"));
    assert_eq!(i01_answer::answer(&changed.derived(), &request, &facts, wall, None), Err(REQUEST_BINDING_TEXT));
    // 2. The answer list's first text.
    let late = CaptureFacts { completed: false, ..facts.clone() };
    assert_eq!(i01_answer::answer(&derived, &request, &late, wall, None), Err(NOT_PASSED[0]));
    let mut changed = Case::complete();
    set(&mut changed.binding, &["projections", "rbac"], "uid", Value::str("another-uid"));
    set(&mut changed.binding, &["projections", "limitRange"], "uid", Value::str("another-uid"));
    assert_eq!(answered(&changed, &facts, OBSERVED_AT, None), Err("limitRange: differs from the signed value"));
    // 3. The capture set's record digest: the derived and signed hostPreflightDigest.
    for digest in ["", ZERO_DIGEST] {
        let other = CaptureFacts { record_digest: digest.to_string(), ..facts.clone() };
        assert_eq!(i01_answer::answer(&derived, &request, &other, wall, None), Err(RECORD_DIGEST_TEXT));
    }
    // 4. The windows at one reading: each start, then each end of expiresAt's minimum.
    assert_eq!(i01_answer::answer(&derived, &request, &facts, millis("2026-09-07T23:59:59Z"), None),
               Err(ANSWER_WINDOW_TEXT));
    let expiry = |change: &dyn Fn(&mut Case)| -> Result<String, &'static str> {
        let mut case = Case::complete();
        change(&mut case);
        answered(&case, &case.passing(), OBSERVED_AT, None).map(|bytes| text(&parsed(&bytes), "expiresAt").to_string())
    };
    let at = |text: &str| Value::str(text);
    assert_eq!(expiry(&|_| ()), Ok("2026-09-08T00:00:06Z".to_string()));
    assert_eq!(expiry(&|case| set(&mut case.binding, &["scope"], "validFrom", at("2026-09-08T00:00:02Z"))),
               Err(ANSWER_WINDOW_TEXT));
    assert_eq!(expiry(&|case| {
        set(&mut case.record, &["scope"], "validFrom", at("2026-09-08T00:00:02Z"));
        case.repin();
    }), Err(ANSWER_WINDOW_TEXT));
    assert_eq!(expiry(&|case| case.not_before = millis("2026-09-08T00:00:02Z") / 1000), Err(ANSWER_WINDOW_TEXT));
    assert_eq!(expiry(&|case| set(&mut case.binding, &["scope"], "expiresAt", at("2026-09-08T00:00:03Z"))),
               Ok("2026-09-08T00:00:03Z".to_string()));
    assert_eq!(expiry(&|case| set(&mut case.binding, &["scope"], "expiresAt", at("2026-09-08T00:00:01Z"))),
               Err(ANSWER_WINDOW_TEXT));
    assert_eq!(expiry(&|case| {
        set(&mut case.record, &["scope"], "expiresAt", at("2026-09-08T00:00:05Z"));
        case.repin();
    }), Ok("2026-09-08T00:00:02Z".to_string()));
    assert_eq!(expiry(&|case| {
        set(&mut case.record, &["scope"], "expiresAt", at("2026-09-08T00:00:04Z"));
        case.repin();
    }), Err(ANSWER_WINDOW_TEXT));
    assert_eq!(expiry(&|case| case.not_after = millis("2026-09-08T00:00:04Z") / 1000),
               Ok("2026-09-08T00:00:04Z".to_string()));
    assert_eq!(expiry(&|case| case.not_after = millis("2026-09-08T00:00:01Z") / 1000), Err(ANSWER_WINDOW_TEXT));
    // 5. The rollback, in whole seconds [I3D-9 (b)].
    let now = wall / 1000;
    assert_eq!(i01_answer::answer(&derived, &request, &facts, wall, Some(now + 1)), Err(ANSWER_ROLLBACK_TEXT));
    assert!(i01_answer::answer(&derived, &request, &facts, wall, Some(now)).is_ok());
    assert!(i01_answer::answer(&derived, &request, &facts, wall + 999, Some(now)).is_ok());
    // 7. VPO's observation rules on the assembled members: the namespace is compared only here (I3D-5); used <= hard;
    // the shape (a negative count, a boot id not a UUID, a generation not 64 hex digits).
    let rules = |change: &dyn Fn(&mut Case)| -> Result<Vec<u8>, &'static str> {
        let mut case = Case::complete();
        change(&mut case);
        answered(&case, &case.passing(), OBSERVED_AT, None)
    };
    assert_eq!(rules(&|case| set(&mut case.binding, &["namespace"], "uid", at("another-namespace-uid"))),
               Err(OBSERVED_NAMESPACE_TEXT));
    assert_eq!(rules(&|case| set(&mut case.quota, &["used"], "pods", Value::int(2))), Err(QUOTA_HEADROOM_TEXT));
    assert_eq!(rules(&|case| set(&mut case.quota, &["used"], "pods", Value::int(-1))), Err(INVALID_OBSERVATION_TEXT));
    assert_eq!(rules(&|case| {
        set(&mut case.record, &["host"], "bootId", at("not-a-uuid"));
        case.repin();
    }), Err(INVALID_OBSERVATION_TEXT));
    assert_eq!(rules(&|case| case.generation = "b".repeat(63)), Err(INVALID_OBSERVATION_TEXT));
    // 8. The bound: an answer over 65,536 canonical bytes, refused with VPO:77's label (the shape's byte bound in
    // step 7 meets it first, with the same text).
    assert_eq!(rules(&|case| set(&mut case.quota, &["hard"], "padding", Value::str(&"a".repeat(70_000)))),
               Err(OBSERVATION_BYTES_TEXT));
}

#[test]
fn a_sequence_2_request_is_not_refused_by_the_chain_rules() {
    // I3D-1: answer runs VPO's observation rules without "initial chain", "chain gap" and "restart, drift or reused
    // challenge"; the session's chain is I01B5's, and the rollback is step 5.
    let case = Case::complete();
    let (derived, facts) = (case.derived(), case.passing());
    let first = i01_answer::answer(&derived, &case.request(), &facts, millis(OBSERVED_AT), None).expect("answered");
    let second = I01Request { sequence: 2, previous_digest: sha256::prefixed(&first), challenge: "b".repeat(64),
                              ..case.request() };
    let wall = millis("2026-09-08T00:00:02Z");
    let bytes = i01_answer::answer(&derived, &second, &facts, wall, Some(wall / 1000 - 1)).expect("a continuation");
    let answer = parsed(&bytes);
    assert_eq!(member(&answer, "sequence").as_int().and_then(|int| int.to_u64()), Some(2));
    assert_eq!(text(&answer, "previousObservationDigest"), second.previous_digest);
    // Neither a zero previous digest nor a reused challenge is answer's to refuse.
    for request in [I01Request { previous_digest: ZERO_DIGEST.to_string(), ..second.clone() },
                    I01Request { challenge: case.request().challenge, ..second.clone() }] {
        assert!(i01_answer::answer(&derived, &request, &facts, wall, None).is_ok());
    }
    // I3E-8: a sequence-2 request with one non-chain fault each, refused with its own text.
    let other = I01Request { run_nonce: "other-nonce".to_string(), ..second.clone() };
    assert_eq!(i01_answer::answer(&derived, &other, &facts, wall, None), Err(REQUEST_BINDING_TEXT));
    assert_eq!(i01_answer::answer(&derived, &second, &facts, millis("2026-09-07T23:59:59Z"), None),
               Err(ANSWER_WINDOW_TEXT));
    assert_eq!(i01_answer::answer(&derived, &second, &facts, wall, Some(wall / 1000 + 1)), Err(ANSWER_ROLLBACK_TEXT));
}

#[test]
fn self_check_keeps_vpos_chain_rules_with_previous_given() {
    // DIB section 8.1's continuation cases at self_check's level [I3D-6]: VPO:116-125 with previous given.
    let case = Case::complete();
    let (derived, facts) = (case.derived(), case.passing());
    let first_request = case.request();
    let first = i01_answer::answer(&derived, &first_request, &facts, millis(OBSERVED_AT), None).expect("answered");
    let previous = parsed(&first);
    let request = I01Request { sequence: 2, previous_digest: sha256::prefixed(&first), challenge: "b".repeat(64),
                               ..first_request.clone() };
    let wall = millis("2026-09-08T00:00:02Z");
    let current = parsed(&i01_answer::answer(&derived, &request, &facts, wall, None).expect("answered"));
    let now = wall / 1000 + 1;
    let check = |observation: &Value, request: &I01Request, previous: Option<&Value>| {
        i01_answer::self_check(observation, request, &case.binding, now, previous)
    };
    // A correct continuation; previous null makes it no initial chain; previous is shaped first.
    assert_eq!(check(&current, &request, Some(&previous)), Ok(()));
    assert_eq!(check(&current, &request, None), Err(INITIAL_CHAIN_TEXT));
    assert_eq!(check(&current, &request, Some(&with(&previous, &[], "extra", Value::Null))),
               Err(INVALID_OBSERVATION_TEXT));
    // A chain gap: the next sequence skipped, another previous digest, a previous of another run nonce.
    let skipped = I01Request { sequence: 3, ..request.clone() };
    assert_eq!(check(&with(&current, &[], "sequence", Value::int(3)), &skipped, Some(&previous)), Err(CHAIN_GAP_TEXT));
    let other = I01Request { previous_digest: ZERO_DIGEST.to_string(), ..request.clone() };
    assert_eq!(check(&with(&current, &[], "previousObservationDigest", Value::str(ZERO_DIGEST)), &other, Some(&previous)),
               Err(CHAIN_GAP_TEXT));
    let renonced = with(&previous, &[], "runNonce", Value::str("other-nonce"));
    let linked = I01Request { previous_digest: digest_of(&renonced), ..request.clone() };
    let pointed = with(&current, &[], "previousObservationDigest", Value::str(&linked.previous_digest));
    assert_eq!(check(&pointed, &linked, Some(&renonced)), Err(CHAIN_GAP_TEXT));
    // Restart, drift or reused challenge: the previous challenge again, a changed boot id, a changed generation.
    let reused = I01Request { challenge: first_request.challenge.clone(), ..request.clone() };
    assert_eq!(check(&with(&current, &[], "challenge", Value::str(&reused.challenge)), &reused, Some(&previous)),
               Err(RESTART_TEXT));
    let rebooted = with(&current, &[], "observerBootId", Value::str("52345678-1234-1234-1234-123456789000"));
    assert_eq!(check(&rebooted, &request, Some(&previous)), Err(RESTART_TEXT));
    assert_eq!(check(&with(&current, &[], "generation", Value::str(&"c".repeat(64))), &request, Some(&previous)),
               Err(RESTART_TEXT));
    // A clock rollback: the previous observed after the current; an equal observedAt is none (VPO's >=).
    for (previous_at, want) in [("2026-09-08T00:00:03Z", Err(CLOCK_ROLLBACK_TEXT)), ("2026-09-08T00:00:02Z", Ok(()))] {
        let moved = with(&previous, &[], "observedAt", Value::str(previous_at));
        let linked = I01Request { previous_digest: digest_of(&moved), ..request.clone() };
        let pointed = with(&current, &[], "previousObservationDigest", Value::str(&linked.previous_digest));
        assert_eq!(check(&pointed, &linked, Some(&moved)), want, "{previous_at}");
    }
}

#[test]
fn self_check_runs_vpos_rules_in_vpos_order() {
    let case = Case::complete();
    let (observation, request) = (case.observation(), case.request());
    let now = utc_seconds("2026-09-08T00:00:02Z").expect("a canonical UTC text");
    let check = |observation: &Value| i01_answer::self_check(observation, &request, &case.binding, now, None);
    assert_eq!(check(&observation), Ok(()));
    // The shape (VPO:74-79): `_bounded` (a float), `_ascii_fields` (a line end, a non-ASCII letter), the byte bound
    // with its own label before the schema, then the schema (a missing member, an extra one, a boolean sequence,
    // another schema version, a resourceVersion with a space). Each but the bound is VPO's generic text.
    let float = json::parse("1.5").expect("a float");
    let invalid = [with(&observation, &["quota", "hard"], "pods", float),
                   with(&observation, &["namespace"], "name", Value::str("planeon-qual\n")),
                   with(&observation, &["namespace"], "name", Value::str("plan\u{e9}on-qual")),
                   with(&observation, &[], "extra", Value::Null),
                   with(&observation, &[], "sequence", Value::Bool(true)),
                   with(&observation, &[], "schemaVersion", Value::str("planeon.internal.policy-observation/v2")),
                   with(&observation, &["namespace"], "resourceVersion", Value::str("1 0")),
                   with(&observation, &["projections", "rbac"], "kind", Value::str("E")),
                   with(&observation, &["projections", "rbac"], "namespace", Value::int(0))];
    for (index, changed) in invalid.iter().enumerate() {
        assert_eq!(check(changed), Err(INVALID_OBSERVATION_TEXT), "shape case {index}");
    }
    let mut missing = observation.clone();
    remove(&mut missing, &[], "quota");
    assert_eq!(check(&missing), Err(INVALID_OBSERVATION_TEXT));
    assert_eq!(check(&with(&observation, &[], "padding", Value::str(&"a".repeat(70_000)))), Err(OBSERVATION_BYTES_TEXT));
    // Then each rule's label, in VPO's order; where two rules fail, the earlier one's.
    let rbac_uid = with(&observation, &["projections", "rbac"], "uid", Value::str("another-uid"));
    assert_eq!(check(&rbac_uid), Err(OBSERVED_IDENTITY_TEXT));
    assert_eq!(check(&with(&rbac_uid, &["namespace"], "uid", Value::str("another-uid"))), Err(OBSERVED_IDENTITY_TEXT));
    assert_eq!(check(&with(&observation, &["namespace"], "uid", Value::str("another-uid"))), Err(OBSERVED_NAMESPACE_TEXT));
    let renonced = I01Request { run_nonce: "other-nonce".to_string(), ..request.clone() };
    let echoed = with(&observation, &[], "runNonce", Value::str("other-nonce"));
    assert_eq!(i01_answer::self_check(&echoed, &renonced, &case.binding, now, None), Err(REQUEST_BINDING_TEXT));
    assert_eq!(check(&with(&observation, &[], "challenge", Value::str(&"c".repeat(64)))),
               Err(RESPONSE_SUBSTITUTION_TEXT));
    let second = I01Request { sequence: 2, ..request.clone() };
    assert_eq!(i01_answer::self_check(&with(&observation, &[], "sequence", Value::int(2)), &second, &case.binding, now,
                                      None), Err(INITIAL_CHAIN_TEXT));
    assert_eq!(check(&with(&observation, &[], "observedAt", Value::str("2026-09-08T00:00:03Z"))),
               Err(STALE_OR_FUTURE_TEXT));
    assert_eq!(check(&with(&observation, &[], "expiresAt", Value::str("2026-09-08T00:00:07Z"))),
               Err(FRESHNESS_WINDOW_TEXT));
    assert_eq!(check(&with(&observation, &["enforcement"], "policyGeneration", Value::str(&"c".repeat(64)))),
               Err(ENFORCEMENT_PROOF_TEXT));
    assert_eq!(check(&with(&observation, &["quota", "used"], "configMaps", Value::int(2))), Err(QUOTA_HEADROOM_TEXT));
    // A time in the pattern's form that `_time` does not read raises: VPO's generic text.
    assert_eq!(check(&with(&observation, &[], "observedAt", Value::str("2026-02-30T00:00:01Z"))),
               Err(INVALID_OBSERVATION_TEXT));
}

#[test]
fn self_check_reads_times_as_vpcs_time_does() {
    // VPC's `_time` reads every canonical UTC text from year 0001 to 9999, so a scope starting before 1970 is VPO's
    // pass, and self_check's (VPO's decision, exactly); a day that does not exist raises.
    let case = Case::complete();
    let now = utc_seconds("2026-09-08T00:00:02Z").expect("a canonical UTC text");
    for (from, want) in [("1969-12-31T00:00:00Z", Ok(())), ("0001-01-01T00:00:00Z", Ok(())),
                         ("1900-02-29T00:00:00Z", Err(INVALID_OBSERVATION_TEXT))] {
        let binding = with(&case.binding, &["scope"], "validFrom", Value::str(from));
        let digest = digest_of(&binding);
        let request = I01Request { binding_digest: digest.clone(), ..case.request() };
        let observation = with(&case.observation(), &[], "bindingDigest", Value::str(&digest));
        assert_eq!(i01_answer::self_check(&observation, &request, &binding, now, None), want, "{from}");
    }
}
