//! The I01 answer logic (HE-004-I01B3; DESIGN-I01B rev 3 sections 4 and 6-8 and DESIGN-I01B3 rev 4; the owner's
//! Q-I01B3-SPLIT and the monitor's Q-I01B3-1..13 and Q-I01B3D-1..3): the derivations of one snapshot, the model's
//! answer list, the answer and its self-check, over plain data. A pure logic module under the I01 logic whitelist plus
//! exactly `crate::kernel_text::utc_text` and `crate::kernel_text::utc_seconds` (`tools/gate.py`, Q-1e (a)): no clock,
//! no capture view, no system call beyond allocation, every function total, no panic, and no caller in the binary in
//! HE-004-I01B3 (G-I01B-1's I01B3 form); HE-004-I01B5 wires it.
//!
//! - [`derive`]: one snapshot's every projection and enforcement digest (`i01_digest`, the A2 render handed in), each
//!   kept as its value or its refusal text, with the namespace member, the signed binding with its digest and run nonce
//!   (computed as the binding gate's are), the record, the quota pair, the generation and the three windows. Nothing is
//!   compared at derive time (Q-I01B3D-1 (a)); `derive` refuses only when [`Derived`] cannot be built.
//! - [`Derived`] is closed (G-I01B-9): private fields, read only through its getters, one literal, as `derive`'s tail.
//! - [`CaptureFacts`]: the latest capture set as the service will hand it in (HE-004-I01B5), mapped to `i01_gate`'s
//!   input: no completed set is `None`, an expired view a set whose slots are all not taken (Q-1 (a)).
//! - [`refusals`]: the model's answer list (`observed` then `check_observation_digests`): per key, in key order, the
//!   derivation's refusal, else a gated key's capture-gate refusal, else "<key>: differs from the signed value"; each
//!   text once. It is the one composition of the answer lists (Q-1d (a), R1-6).
//!
//! Every text a function here returns is one of this module's pinned `*_TEXT` constants or a text `i01_digest` and
//! `i01_gate` return; the JSON member names are the pinned `KEY_*` constants; the `sha256:` prefix comes only from
//! i05-protocol's `sha256::prefixed` and the zero digest only from `crate::i01_request::ZERO_DIGEST` (G-I01B-8's I01B3
//! checks, I3F-1..3).

use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::sha256;

use crate::i01_admission_render;
use crate::i01_digest::{self, DigestKey, DigestSnapshot, EnforcementValue, ProjectionValue};
use crate::i01_gate::{self, LatestSet};
use crate::inputs::{object_name, Inputs, Resource};
use crate::kernel_text::utc_seconds;
use crate::snapshot::Closure;

// ------------------------------------------------------------------------------------------------ the texts

/// VPO's "request binding" (harness-onion scripts/validate_policy_observation.py:110-111 at f9882c1a).
pub const REQUEST_BINDING_TEXT: &str = "request binding";
/// VPO's "observed namespace" (harness-onion scripts/validate_policy_observation.py:109 at f9882c1a).
pub const OBSERVED_NAMESPACE_TEXT: &str = "observed namespace";
/// VPO's generic outcome for every failing rule, the shape's included (harness-onion
/// scripts/validate_policy_observation.py:136-138 at f9882c1a).
pub const INVALID_OBSERVATION_TEXT: &str = "invalid protected observation data";
/// An answer whose windows do not hold (R10-defined, MODEL_DEFINED R201).
pub const ANSWER_WINDOW_TEXT: &str = "answer outside its windows";

// ------------------------------------------------------------------------------------------------ the member names

/// The observation's members (`contracts/i01-v1/channel.schema.json` `$defs.observation`).
pub const KEY_SCHEMA_VERSION: &str = "schemaVersion";
pub const KEY_BINDING_DIGEST: &str = "bindingDigest";
pub const KEY_RUN_NONCE: &str = "runNonce";
pub const KEY_CHALLENGE: &str = "challenge";
pub const KEY_SEQUENCE: &str = "sequence";
pub const KEY_PREVIOUS_DIGEST: &str = "previousObservationDigest";
pub const KEY_BOOT_ID: &str = "observerBootId";
pub const KEY_GENERATION: &str = "generation";
pub const KEY_OBSERVED_AT: &str = "observedAt";
pub const KEY_EXPIRES_AT: &str = "expiresAt";
pub const KEY_NAMESPACE: &str = "namespace";
pub const KEY_PROJECTIONS: &str = "projections";
pub const KEY_QUOTA: &str = "quota";
pub const KEY_ENFORCEMENT: &str = "enforcement";
/// The namespace member's and a projection's members.
pub const KEY_NAME: &str = "name";
pub const KEY_UID: &str = "uid";
pub const KEY_RESOURCE_VERSION: &str = "resourceVersion";
pub const KEY_API_VERSION: &str = "apiVersion";
pub const KEY_KIND: &str = "kind";
pub const KEY_PROJECTION_DIGEST: &str = "projectionDigest";
/// The quota pair's members and its six units.
pub const KEY_HARD: &str = "hard";
pub const KEY_USED: &str = "used";
pub const KEY_PODS: &str = "pods";
pub const KEY_CONFIG_MAPS: &str = "configMaps";
pub const KEY_SERVICES: &str = "services";
pub const KEY_CPU_MILLIS: &str = "cpuMillis";
pub const KEY_MEMORY_BYTES: &str = "memoryBytes";
pub const KEY_EPHEMERAL_STORAGE_BYTES: &str = "ephemeralStorageBytes";
/// The enforcement member's generation.
pub const KEY_POLICY_GENERATION: &str = "policyGeneration";
/// The signed binding's members (`$defs.binding`).
pub const KEY_SCOPE: &str = "scope";
pub const KEY_VALID_FROM: &str = "validFrom";
pub const KEY_ENFORCEMENT_PINS: &str = "enforcementPins";
/// The enrolled native-qualification v4 record's host and its boot id.
pub const KEY_HOST: &str = "host";
pub const KEY_HOST_BOOT_ID: &str = "bootId";
/// The configuration's qualification namespace, and a listed object's metadata.
pub const KEY_QUALIFICATION_NAMESPACE: &str = "qualificationNamespace";
pub const KEY_METADATA: &str = "metadata";
/// The observation's schema version (`$defs.observation`'s `schemaVersion` const).
pub const KEY_OBSERVATION_SCHEMA: &str = "planeon.internal.policy-observation/v1";

// ------------------------------------------------------------------------------------------------ the derivations

/// One snapshot's derivations (DESIGN-I01B3 rev 4 section 3.1), closed (G-I01B-9): every field private, read only
/// through its getter, built only by [`derive`]'s one literal, deriving exactly `Debug`.
/// - `policy_values` and `digest_values`: each key's projection or enforcement digest, or its refusal text, in key
///   order.
/// - `namespace_member`: `{name, uid, resourceVersion}` of the one Namespace the configuration's qualification
///   namespace names, with the read's resourceVersion text.
/// - `binding_member`, `bound_digest` and `bound_nonce`: the signed binding, `sha256:` and the hex SHA-256 of its
///   canonical bytes, and its `scope.runNonce` (B3-6 (3)).
/// - `enrolled_record` and `boot_id`: the enrolled record (the capture gate's slots) and its `host.bootId`.
/// - `quota_pair` and `generation_hex`: the `{hard, used}` pair and the configuration's generation.
/// - `scope_window`, `record_window` and `config_window`: each `(from, until)` in seconds from the epoch.
#[derive(Debug)]
pub struct Derived {
    policy_values: Vec<(DigestKey, Result<ProjectionValue, &'static str>)>,
    digest_values: Vec<(DigestKey, Result<EnforcementValue, &'static str>)>,
    namespace_member: Value,
    binding_member: Value,
    bound_digest: String,
    bound_nonce: String,
    enrolled_record: Value,
    boot_id: String,
    quota_pair: Value,
    generation_hex: String,
    scope_window: (i64, i64),
    record_window: (i64, i64),
    config_window: (i64, i64),
}

impl Derived {
    /// The seven projections, each its value or its refusal, in the contract's order.
    pub fn policy_values(&self) -> &[(DigestKey, Result<ProjectionValue, &'static str>)] {
        &self.policy_values
    }

    /// The four enforcement digests, each its value or its refusal, in the contract's order.
    pub fn digest_values(&self) -> &[(DigestKey, Result<EnforcementValue, &'static str>)] {
        &self.digest_values
    }

    /// The observation's namespace member.
    pub fn namespace_member(&self) -> &Value {
        &self.namespace_member
    }

    /// The signed binding.
    pub fn binding_member(&self) -> &Value {
        &self.binding_member
    }

    /// The signed binding's digest.
    pub fn bound_digest(&self) -> &str {
        &self.bound_digest
    }

    /// The signed binding's run nonce.
    pub fn bound_nonce(&self) -> &str {
        &self.bound_nonce
    }

    /// The enrolled record.
    pub fn enrolled_record(&self) -> &Value {
        &self.enrolled_record
    }

    /// The record's `host.bootId`.
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    /// The quota pair `{hard, used}`.
    pub fn quota_pair(&self) -> &Value {
        &self.quota_pair
    }

    /// The configuration's generation.
    pub fn generation_hex(&self) -> &str {
        &self.generation_hex
    }

    /// The binding's scope window.
    pub fn scope_window(&self) -> (i64, i64) {
        self.scope_window
    }

    /// The record's scope window.
    pub fn record_window(&self) -> (i64, i64) {
        self.record_window
    }

    /// The configuration's validity window.
    pub fn config_window(&self) -> (i64, i64) {
        self.config_window
    }
}

/// The latest completed capture set at one answer, as the service hands it in (DIB section 4.1 route 1; B3-6 (2) pins
/// the literal's initialisers in HE-004-I01B5): whether a set completed, whether the view expired, the set's slots
/// with whether each is `TAKEN`, its two ages at the answer, and the set's record digest (compared in the answer, not a
/// gate input: Q-CB-11 (a)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureFacts {
    pub completed: bool,
    pub expired: bool,
    pub scheduled_after_now: bool,
    pub slots: Vec<(String, bool)>,
    pub mono_age_ms: u64,
    pub wall_age_ms: i64,
    pub record_digest: String,
}

/// Five 400-year Gregorian cycles: 2,000 years, 730,485 days, in seconds. Leap years recur every 400 years, so a
/// canonical UTC text moved by this many years keeps its validity and every difference to another moved text.
const SHIFT_YEARS: u64 = 2_000;
const SHIFT_SECONDS: i64 = 63_113_904_000;

/// VPC's `_time` (harness-onion scripts/validate_proxy_contract.py:98-101 at f9882c1a): a UTC text that `strptime`
/// reads with the form YYYY-MM-DDTHH:MM:SSZ and `strftime` writes back unchanged, so years 0001 to 9999, as seconds
/// from 1970-01-01T00:00:00Z (negative before). Years 1970 to 9999 are `kernel_text::utc_seconds`'s; an earlier year is
/// read 2,000 years later by the same function and moved back.
fn utc_instant(text: &str) -> Option<i64> {
    if let Some(seconds) = utc_seconds(text) {
        return i64::try_from(seconds).ok();
    }
    let digits = text.get(..4).filter(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()))?;
    let year = digits.parse::<u64>().ok().filter(|year| (1..1970).contains(year))?;
    let moved = [year.checked_add(SHIFT_YEARS)?.to_string().as_str(), text.get(4..)?].concat();
    i64::try_from(utc_seconds(&moved)?).ok()?.checked_sub(SHIFT_SECONDS)
}

/// A `(validFrom, expiresAt)` window of a scope, each canonical UTC text; missing or non-canonical, the window is
/// never open and `Derived` cannot be built.
fn window(scope: &Value) -> Result<(i64, i64), &'static str> {
    let from = scope.get(KEY_VALID_FROM).and_then(Value::as_str).and_then(utc_instant).ok_or(ANSWER_WINDOW_TEXT)?;
    let until = scope.get(KEY_EXPIRES_AT).and_then(Value::as_str).and_then(utc_instant).ok_or(ANSWER_WINDOW_TEXT)?;
    Ok((from, until))
}

/// The observation's namespace member [I3D-9 (d)]: the one Namespace in the checked lists that the configuration's
/// `qualificationNamespace` names, its `name` and `uid` from its metadata, and the read's resourceVersion text.
fn namespace_member(inputs: &Inputs, configuration: &Value, resource_version: &Value) -> Result<Value, &'static str> {
    let wanted = configuration.get(KEY_QUALIFICATION_NAMESPACE).and_then(Value::as_str).ok_or(OBSERVED_NAMESPACE_TEXT)?;
    let items = inputs.items(Resource::Namespaces).map_err(|_| OBSERVED_NAMESPACE_TEXT)?;
    let named: Vec<&Value> = items.iter().filter(|item| object_name(item) == Some(wanted)).collect();
    let [item] = named.as_slice() else {
        return Err(OBSERVED_NAMESPACE_TEXT);
    };
    let metadata = item.get(KEY_METADATA).ok_or(OBSERVED_NAMESPACE_TEXT)?;
    let name = metadata.get(KEY_NAME).filter(|name| name.as_str().is_some()).ok_or(OBSERVED_NAMESPACE_TEXT)?;
    let uid = metadata.get(KEY_UID).filter(|uid| uid.as_str().is_some()).ok_or(OBSERVED_NAMESPACE_TEXT)?;
    let version = Some(resource_version).filter(|version| version.as_str().is_some()).ok_or(OBSERVED_NAMESPACE_TEXT)?;
    let mut member = Object::new();
    member.insert(JStr::new(KEY_NAME), name.clone());
    member.insert(JStr::new(KEY_UID), uid.clone());
    member.insert(JStr::new(KEY_RESOURCE_VERSION), version.clone());
    Ok(Value::Object(member))
}

/// One snapshot's derivations (DESIGN-I01B3 rev 4 section 3.1; Q-1c (a)), each input plain data named from its live
/// source in HE-004-I01B5's pinned statement: B1's checked lists, the read's resourceVersion text, the configuration's
/// `{qualificationNamespace, pinnedManifestHash, sealedAdmission}`, ADM-4's loaded hash, the enrolled record, I06's
/// closure, the signed binding, the `{hard, used}` quota pair, and the configuration's generation and window. Every
/// projection and enforcement digest is derived (the A2 render handed in) and kept, value or refusal; nothing is
/// compared here. It refuses only when `Derived` cannot be built [I3D-9 (a)]: a binding whose canonical bytes fail or
/// without `scope.runNonce` ("request binding"); a binding or record scope window missing or not canonical UTC text
/// ("answer outside its windows"); a record without a text `host.bootId` (the generic text: no observation can be
/// assembled); a namespace member that cannot be composed ("observed namespace").
pub fn derive(inputs: &Inputs, resource_version: &Value, configuration: &Value, adm4_loaded_hash: &Value,
              record: &Value, closure: &Closure, binding: &Value, quota: &Value, generation: &str,
              not_before: u64, not_after: u64) -> Result<Derived, &'static str> {
    let encoded = json::canonical(binding).map_err(|_| REQUEST_BINDING_TEXT)?;
    let scope = binding.get(KEY_SCOPE).ok_or(REQUEST_BINDING_TEXT)?;
    let bound_nonce = scope.get(KEY_RUN_NONCE).and_then(Value::as_str).ok_or(REQUEST_BINDING_TEXT)?.to_string();
    let bound_digest = sha256::prefixed(&encoded);
    let scope_window = window(scope)?;
    let host = record.get(KEY_HOST).ok_or(INVALID_OBSERVATION_TEXT)?;
    let boot_id = host.get(KEY_HOST_BOOT_ID).and_then(Value::as_str).ok_or(INVALID_OBSERVATION_TEXT)?.to_string();
    let record_window = window(record.get(KEY_SCOPE).ok_or(ANSWER_WINDOW_TEXT)?)?;
    let config_window = (i64::try_from(not_before).unwrap_or(i64::MAX), i64::try_from(not_after).unwrap_or(i64::MAX));
    let namespace_member = namespace_member(inputs, configuration, resource_version)?;
    let snapshot = DigestSnapshot {
        inputs,
        resource_version: Some(resource_version),
        configuration: Some(configuration),
        adm4_loaded_hash: Some(adm4_loaded_hash),
        record: Some(record),
    };
    let policy_values = DigestKey::POLICIES
        .into_iter()
        .map(|key| (key, i01_digest::projection(key, &snapshot, binding, &i01_admission_render::render)))
        .collect();
    let digest_values = DigestKey::DIGESTS
        .into_iter()
        .map(|key| (key, i01_digest::enforcement(key, &snapshot, closure, &i01_admission_render::render)))
        .collect();
    let binding_member = binding.clone();
    let enrolled_record = record.clone();
    let quota_pair = quota.clone();
    let generation_hex = generation.to_string();
    Ok(Derived {
        policy_values,
        digest_values,
        namespace_member,
        binding_member,
        bound_digest,
        bound_nonce,
        enrolled_record,
        boot_id,
        quota_pair,
        generation_hex,
        scope_window,
        record_window,
        config_window,
    })
}

// ------------------------------------------------------------------------------------------------ the answer list

/// The capture gate for one gated key at the answer, over the facts mapped to `i01_gate`'s input (Q-1 (a)): no
/// completed set is `None`; an expired view is a set whose slots are all not taken (README section 3.3); otherwise the
/// set's slots and its two ages. A key that is not gated passes.
fn gate(key: DigestKey, facts: &CaptureFacts, record: &Value) -> Result<(), &'static str> {
    if !DigestKey::GATED.contains(&key) {
        return Ok(());
    }
    let cleared: Vec<(String, bool)> = facts.slots.iter().map(|(slot, _)| (slot.clone(), false)).collect();
    let slots = if facts.expired { cleared.as_slice() } else { facts.slots.as_slice() };
    let latest = LatestSet {
        slots,
        scheduled_after_now: facts.scheduled_after_now,
        mono_age_ms: facts.mono_age_ms,
        wall_age_ms: facts.wall_age_ms,
    };
    i01_gate::capture_gate(key, Some(&latest).filter(|_| facts.completed), record)
}

/// The model's answer list (DESIGN-I01B3 rev 4 section 3.3; `observed` followed by `check_observation_digests`): for
/// each key in key order, its derivation's refusal; else, for a gated key, the capture gate's refusal; else, when its
/// identity without `resourceVersion` is not the signed binding's `projections` member (Python equality) or its digest
/// not the signed `enforcementPins` member, "<key>: differs from the signed value". Each text once.
pub fn refusals(derived: &Derived, facts: &CaptureFacts) -> Vec<&'static str> {
    let binding = derived.binding_member();
    let record = derived.enrolled_record();
    let signed = binding.get(KEY_PROJECTIONS);
    let pins = binding.get(KEY_ENFORCEMENT_PINS);
    let policies = derived.policy_values().iter().map(|(key, result)| match result.as_ref() {
        Err(&refusal) => Err(refusal),
        Ok(value) => gate(*key, facts, record).and_then(|()| {
            let expected = signed.and_then(|signed| signed.get(key.name()));
            let same = expected.is_some_and(|expected| json::py_eq(&value.identity, expected));
            if same { Ok(()) } else { Err(key.differs()) }
        }),
    });
    let digests = derived.digest_values().iter().map(|(key, result)| match result.as_ref() {
        Err(&refusal) => Err(refusal),
        Ok(value) => gate(*key, facts, record).and_then(|()| {
            let pinned = pins.and_then(|pins| pins.get(key.name())).and_then(Value::as_str);
            if pinned == Some(value.digest.as_str()) { Ok(()) } else { Err(key.differs()) }
        }),
    });
    let mut list: Vec<&'static str> = Vec::new();
    for outcome in policies.chain(digests) {
        if let Err(text) = outcome {
            if !list.contains(&text) {
                list.push(text);
            }
        }
    }
    list
}
