//! HE-004-I01B3 (DESIGN-I01B3 rev 4 sections 3 and 7; the owner's Q-I01B3-SPLIT and the monitor's Q-I01B3-1..13 and
//! Q-I01B3D-1..3): `i01_answer`'s unit tests, over the I01 digest contract v2's complete positive
//! (`contracts/i01-digests-v2/vectors.json`, edge record v11's row 74: the `qual` snapshot, the enrolled record, the
//! `passing` capture and S1's triple).
//! - `derive`: each `Err` case, the one way each input leaves `Derived` unbuildable, and the per-key results it keeps
//!   without comparing them (Q-I01B3D-1 (a)).
//! - The `CaptureFacts` mapping to the capture gate: no completed set, an expired view, the slots and the two ages.
//! - `refusals`: per key, in key order, the derivation's refusal, then the gate's, then the comparison; each text once.

use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::sha256;
use planeon_observer::i01_answer::{self, CaptureFacts, Derived, ANSWER_WINDOW_TEXT, INVALID_OBSERVATION_TEXT,
                                   OBSERVED_NAMESPACE_TEXT, REQUEST_BINDING_TEXT};
use planeon_observer::i01_digest::{DigestKey, BROKER_ROW_INCOMPLETE};
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
