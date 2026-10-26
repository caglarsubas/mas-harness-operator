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
//! - [`answer`]: the request's binding against the signed one, the answer list, the record digest, the windows at one
//!   wall reading, the session's rollback, the 14 members, VPO's observation rules without the chain rules (I3D-1),
//!   and the byte bound; the canonical bytes, or the first refusal.
//! - [`self_check`]: VPO's observation rules (`validate_messages`' observation side) with VPO's decision and rule order
//!   for `previous` given or not, returning the first failing rule's label, or VPO's generic text for every shape
//!   failure and every rule that would raise. `answer` and `self_check` share one private rule function.
//!
//! Every text a function here returns is one of this module's pinned `*_TEXT` constants or a text `i01_digest` and
//! `i01_gate` return; the JSON member names are the pinned `KEY_*` constants; the `sha256:` prefix comes only from
//! i05-protocol's `sha256::prefixed` and the zero digest only from `crate::i01_request::ZERO_DIGEST` (G-I01B-8's I01B3
//! checks, I3F-1..3).

use i05_protocol::json::{self, Int, JStr, Object, Value};
use i05_protocol::sha256;

use crate::i01_admission_render;
use crate::i01_digest::{self, DigestKey, DigestSnapshot, EnforcementValue, ProjectionValue};
use crate::i01_gate::{self, LatestSet, ANSWER_LIMIT, FRESHNESS_WINDOW_SECONDS};
use crate::i01_request::{I01Request, MAX_INTEGER, ZERO_DIGEST};
use crate::inputs::{object_name, Inputs, Resource};
use crate::kernel_text::{utc_seconds, utc_text};
use crate::snapshot::Closure;

// ------------------------------------------------------------------------------------------------ the texts

/// VPO's byte bound of a shaped observation (harness-onion scripts/validate_policy_observation.py:77 at f9882c1a).
pub const OBSERVATION_BYTES_TEXT: &str = "observation bytes exceeded";
/// VPO's generic outcome, the shape's text: the except return of `validate_messages` (harness-onion
/// scripts/validate_policy_observation.py:138 at f9882c1a), for every `_bounded`, `_ascii_fields` and schema failure
/// and every rule that raises.
pub const INVALID_OBSERVATION_TEXT: &str = "invalid protected observation data";
/// VPO's observed projections against the binding's (harness-onion scripts/validate_policy_observation.py:107-108 at
/// f9882c1a).
pub const OBSERVED_IDENTITY_TEXT: &str = "observed identity or digest";
/// VPO's observed namespace against the binding's (harness-onion scripts/validate_policy_observation.py:109 at
/// f9882c1a).
pub const OBSERVED_NAMESPACE_TEXT: &str = "observed namespace";
/// VPO's request against the binding (harness-onion scripts/validate_policy_observation.py:110-111 at f9882c1a).
pub const REQUEST_BINDING_TEXT: &str = "request binding";
/// VPO's echo members (harness-onion scripts/validate_policy_observation.py:112-113 at f9882c1a).
pub const RESPONSE_SUBSTITUTION_TEXT: &str = "response substitution";
/// VPO's first request of a chain (harness-onion scripts/validate_policy_observation.py:114-115 at f9882c1a).
pub const INITIAL_CHAIN_TEXT: &str = "initial chain";
/// VPO's chain continued from the previous observation (harness-onion scripts/validate_policy_observation.py:116-121
/// at f9882c1a).
pub const CHAIN_GAP_TEXT: &str = "chain gap";
/// VPO's same boot and generation with a new challenge (harness-onion scripts/validate_policy_observation.py:122-124
/// at f9882c1a).
pub const RESTART_TEXT: &str = "restart, drift or reused challenge";
/// VPO's observedAt not before the previous one (harness-onion scripts/validate_policy_observation.py:125 at
/// f9882c1a).
pub const CLOCK_ROLLBACK_TEXT: &str = "clock rollback";
/// VPO's scope window around observedAt, now and expiresAt (harness-onion
/// scripts/validate_policy_observation.py:126-127 at f9882c1a).
pub const STALE_OR_FUTURE_TEXT: &str = "stale or future";
/// VPO's expiresAt within 5 s of observedAt (harness-onion scripts/validate_policy_observation.py:128 at f9882c1a).
pub const FRESHNESS_WINDOW_TEXT: &str = "freshness window";
/// VPO's enforcement member against the binding's pins (harness-onion scripts/validate_policy_observation.py:129-130
/// at f9882c1a).
pub const ENFORCEMENT_PROOF_TEXT: &str = "enforcement proof mismatch";
/// VPO's quota headroom, whose `used <= hard` half R10 checks (harness-onion
/// scripts/validate_policy_observation.py:131-134 at f9882c1a).
pub const QUOTA_HEADROOM_TEXT: &str = "actual quota headroom";
/// A capture set's record digest other than the derived and signed hostPreflightDigest (R10-defined, MODEL_DEFINED
/// R201).
pub const RECORD_DIGEST_TEXT: &str = "capture record digest differs";
/// An answer whose windows do not hold (R10-defined, MODEL_DEFINED R201).
pub const ANSWER_WINDOW_TEXT: &str = "answer outside its windows";
/// An answer's observedAt before the session's last one (R10-defined, MODEL_DEFINED R201).
pub const ANSWER_ROLLBACK_TEXT: &str = "answer clock rollback";

/// An answer's expiresAt lies at least this many seconds before the enrolled record's (R10-defined, MODEL_DEFINED
/// R199; DIB section 4.3 step 6).
pub const RECORD_EXPIRY_MARGIN_SECONDS: u64 = 3;

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

// ----------------------------------------------------------------------------------------------- the observation rules

/// VPC's `_require` (harness-onion scripts/validate_proxy_contract.py:93-95 at f9882c1a): the rule's text when it does
/// not hold.
fn require(holds: bool, text: &'static str) -> Result<(), &'static str> {
    if holds { Ok(()) } else { Err(text) }
}

/// The number of lowercase hexadecimal digits of a SHA-256 digest, a challenge and a generation.
const HEX_DIGITS: usize = 64;

fn lower_hex(byte: &u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
}

/// `^[0-9a-f]{64}$`.
fn hex_form(text: &[u8]) -> bool {
    text.len() == HEX_DIGITS && text.iter().all(lower_hex)
}

/// `^sha256:[0-9a-f]{64}$`: the zero digest's form (`crate::i01_request::ZERO_DIGEST`, I3F-3), its `sha256:` prefix
/// and 64 lowercase hexadecimal digits.
fn digest_form(text: &[u8]) -> bool {
    let zero = ZERO_DIGEST.as_bytes();
    let prefix = zero.len().saturating_sub(HEX_DIGITS);
    text.len() == zero.len() && text.get(..prefix) == zero.get(..prefix) && text.get(prefix..).is_some_and(hex_form)
}

/// `^[a-z0-9][a-z0-9.-]{0,62}$` (a run nonce, a name, a namespace).
fn label_form(text: &[u8]) -> bool {
    let first = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let rest = |byte: &u8| first(byte) || *byte == b'.' || *byte == b'-';
    text.len() <= 63 && text.first().is_some_and(first) && text.iter().skip(1).all(rest)
}

/// `^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$` (a boot id).
fn boot_id_form(text: &[u8]) -> bool {
    let dashes = [8, 13, 18, 23];
    text.len() == 36
        && text.iter().enumerate().all(|(at, byte)| if dashes.contains(&at) { *byte == b'-' } else { lower_hex(byte) })
}

/// `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$` (a UTC time).
fn utc_form(text: &[u8]) -> bool {
    text.len() == 20
        && text.iter().enumerate().all(|(at, byte)| match at {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            19 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

/// `^[A-Za-z0-9-]{1,128}$` (a uid).
fn uid_form(text: &[u8]) -> bool {
    (1..=128).contains(&text.len()) && text.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

/// `^[A-Za-z0-9._:-]+$`, at most 128 characters (a resourceVersion).
fn version_form(text: &[u8]) -> bool {
    let marks = [b'.', b'_', b':', b'-'];
    (1..=128).contains(&text.len()) && text.iter().all(|byte| byte.is_ascii_alphanumeric() || marks.contains(byte))
}

/// `^[A-Za-z0-9./-]+$`, at most 128 characters (an apiVersion).
fn api_version_form(text: &[u8]) -> bool {
    let marks = [b'.', b'/', b'-'];
    (1..=128).contains(&text.len()) && text.iter().all(|byte| byte.is_ascii_alphanumeric() || marks.contains(byte))
}

/// `^[A-Za-z][A-Za-z0-9]+$`, at most 128 characters (a kind).
fn kind_form(text: &[u8]) -> bool {
    (2..=128).contains(&text.len()) && text.first().is_some_and(u8::is_ascii_alphabetic)
        && text.iter().all(u8::is_ascii_alphanumeric)
}

/// A text member of `object` in `form` (the form holds the member's `minLength` and `maxLength`).
fn text_in(object: &Object, name: &str, form: fn(&[u8]) -> bool) -> bool {
    matches!(object.get(name), Some(Value::Str(text)) if form(text.as_bytes()))
}

/// An integer member of `object` within `low..=high` (a JSON Schema integer: a boolean is none).
fn integer_in(object: &Object, name: &str, low: u64) -> bool {
    let high = i128::from(MAX_INTEGER);
    matches!(object.get(name), Some(Value::Int(int))
             if int.to_i128().is_some_and(|number| (i128::from(low)..=high).contains(&number)))
}

/// An object holding exactly `names` (`required` with `additionalProperties: false`).
fn closed<'a>(value: &'a Value, names: &[&str]) -> Option<&'a Object> {
    value
        .as_object()
        .filter(|object| object.len() == names.len() && names.iter().all(|name| object.get(name).is_some()))
}

/// The quota pair's six units, in the schema's order.
fn quota_units() -> [&'static str; 6] {
    [KEY_PODS, KEY_CONFIG_MAPS, KEY_SERVICES, KEY_CPU_MILLIS, KEY_MEMORY_BYTES, KEY_EPHEMERAL_STORAGE_BYTES]
}

/// One projection of `$defs.observation`: its seven members, each of its form, the namespace text or null.
fn projection_form(value: &Value) -> bool {
    let members = [KEY_API_VERSION, KEY_KIND, KEY_NAME, KEY_NAMESPACE, KEY_UID, KEY_PROJECTION_DIGEST,
                   KEY_RESOURCE_VERSION];
    closed(value, &members).is_some_and(|object| {
        text_in(object, KEY_API_VERSION, api_version_form)
            && text_in(object, KEY_KIND, kind_form)
            && text_in(object, KEY_NAME, label_form)
            && (matches!(object.get(KEY_NAMESPACE), Some(Value::Null)) || text_in(object, KEY_NAMESPACE, label_form))
            && text_in(object, KEY_UID, uid_form)
            && text_in(object, KEY_PROJECTION_DIGEST, digest_form)
            && text_in(object, KEY_RESOURCE_VERSION, version_form)
    })
}

/// `$defs.observation` (`contracts/i01-v1/channel.schema.json`, VPO's schema): exactly its 14 members, each of its
/// type and form; the seven projections; the quota pair's six counts in 0..=2^53 - 1 each side; the enforcement
/// member's generation and four digests. `format` is not asserted, as VPO's validator does not assert it.
fn observation_form(value: &Value) -> bool {
    let members = [KEY_SCHEMA_VERSION, KEY_BINDING_DIGEST, KEY_RUN_NONCE, KEY_CHALLENGE, KEY_SEQUENCE,
                   KEY_PREVIOUS_DIGEST, KEY_BOOT_ID, KEY_GENERATION, KEY_OBSERVED_AT, KEY_EXPIRES_AT, KEY_NAMESPACE,
                   KEY_PROJECTIONS, KEY_QUOTA, KEY_ENFORCEMENT];
    let Some(object) = closed(value, &members) else {
        return false;
    };
    let version = matches!(object.get(KEY_SCHEMA_VERSION),
                           Some(Value::Str(text)) if text.as_bytes() == KEY_OBSERVATION_SCHEMA.as_bytes());
    let echo = text_in(object, KEY_BINDING_DIGEST, digest_form)
        && text_in(object, KEY_RUN_NONCE, label_form)
        && text_in(object, KEY_CHALLENGE, hex_form)
        && integer_in(object, KEY_SEQUENCE, 1)
        && text_in(object, KEY_PREVIOUS_DIGEST, digest_form);
    let own = text_in(object, KEY_BOOT_ID, boot_id_form)
        && text_in(object, KEY_GENERATION, hex_form)
        && text_in(object, KEY_OBSERVED_AT, utc_form)
        && text_in(object, KEY_EXPIRES_AT, utc_form);
    let namespace_members = [KEY_NAME, KEY_UID, KEY_RESOURCE_VERSION];
    let namespace = object.get(KEY_NAMESPACE).and_then(|member| closed(member, &namespace_members))
        .is_some_and(|member| {
            text_in(member, KEY_NAME, label_form) && text_in(member, KEY_UID, uid_form)
                && text_in(member, KEY_RESOURCE_VERSION, version_form)
        });
    let policies = DigestKey::POLICIES.map(DigestKey::name);
    let projections = object.get(KEY_PROJECTIONS).and_then(|member| closed(member, &policies))
        .is_some_and(|member| member.iter().all(|(_, projection)| projection_form(projection)));
    let units = quota_units();
    let counts = |pair: &Value| {
        closed(pair, &units).is_some_and(|pair| units.iter().all(|unit| integer_in(pair, unit, 0)))
    };
    let quota = object.get(KEY_QUOTA).and_then(|member| closed(member, &[KEY_HARD, KEY_USED]))
        .is_some_and(|member| member.iter().all(|(_, pair)| counts(pair)));
    let mut proof = vec![KEY_POLICY_GENERATION];
    proof.extend(DigestKey::DIGESTS.map(DigestKey::name));
    let enforcement = object.get(KEY_ENFORCEMENT).and_then(|member| closed(member, &proof)).is_some_and(|member| {
        text_in(member, KEY_POLICY_GENERATION, hex_form)
            && DigestKey::DIGESTS.iter().all(|key| text_in(member, key.name(), digest_form))
    });
    version && echo && own && namespace && projections && quota && enforcement
}

/// VPO's `_ascii_fields` (harness-onion scripts/validate_policy_observation.py:60-71 at f9882c1a): every text and
/// every member name printable ASCII.
fn ascii_fields(value: &Value) -> bool {
    let printable = |text: &JStr| text.as_bytes().iter().all(|byte| (0x20..=0x7e).contains(byte));
    let mut stack = vec![value];
    while let Some(node) = stack.pop() {
        match node {
            Value::Str(text) => {
                if !printable(text) {
                    return false;
                }
            }
            Value::Array(items) => stack.extend(items.iter()),
            Value::Object(object) => {
                for (name, member) in object.iter() {
                    if !printable(name) {
                        return false;
                    }
                    stack.push(member);
                }
            }
            Value::Null | Value::Bool(_) | Value::Int(_) | Value::Float(_) => {}
        }
    }
    true
}

/// VPO's `_shape` of an observation (harness-onion scripts/validate_policy_observation.py:74-79 at f9882c1a), in its
/// order: VPC's `_bounded` (:75; `i01_digest::exactness` decides as it does, floats refused), `_ascii_fields` (:76),
/// the canonical bytes at most 65,536 (:77, its own label), then `$defs.observation` (:79). Every failure but the
/// byte bound is VPO's generic text (:138).
fn shape(observation: &Value) -> Result<(), &'static str> {
    require(i01_digest::exactness(observation).is_ok(), INVALID_OBSERVATION_TEXT)?;
    require(ascii_fields(observation), INVALID_OBSERVATION_TEXT)?;
    let size = json::canonical(observation).map(|bytes| bytes.len()).map_err(|_| INVALID_OBSERVATION_TEXT)?;
    require(size <= ANSWER_LIMIT, OBSERVATION_BYTES_TEXT)?;
    require(observation_form(observation), INVALID_OBSERVATION_TEXT)
}

/// A member read as text.
fn text_of<'a>(holder: &'a Value, name: &str) -> Option<&'a str> {
    holder.get(name).and_then(Value::as_str)
}

/// A member read as a count.
fn integer_of(holder: &Value, name: &str) -> Option<u64> {
    holder.get(name).and_then(Value::as_int).and_then(|int| int.to_u64())
}

/// A member read as VPC's `_time` reads it; a text it would not read raises, VPO's generic text.
fn instant_of(holder: &Value, name: &str) -> Result<i64, &'static str> {
    text_of(holder, name).and_then(utc_instant).ok_or(INVALID_OBSERVATION_TEXT)
}

/// Which chain rules the rule function applies (DESIGN-I01B3 rev 4 section 3.4): VPO's, with `previous` absent or
/// given (`self_check`), or none (`answer`, whose chain is the session's).
#[derive(Clone, Copy, Debug)]
enum ChainMode<'a> {
    Vpo(Option<&'a Value>),
    Skip,
}

/// VPO's observation rules (harness-onion scripts/validate_policy_observation.py:107-134 at f9882c1a, the observation
/// side of `validate_messages`), in VPO's order, with `now` in whole seconds and the chain rules by `mode`. The
/// binding's `scope` stands for VPO's profile scope, which VPO holds equal to it (:91-92); the profile-side rules and
/// the quota's `requested` half are HE-008's. A value VPO would fail to read (a missing member, a time `_time` does not
/// read) is VPO's generic text; every other failing rule is its label.
fn observation_rules(observation: &Value, request: &I01Request, binding: &Value, now: u64, mode: ChainMode<'_>)
                     -> Result<(), &'static str> {
    shape(observation)?;
    // Observed identity or digest (:96-97, 107-108): each projection without its resourceVersion is the binding's.
    let projections = observation.get(KEY_PROJECTIONS).ok_or(INVALID_OBSERVATION_TEXT)?;
    let signed = binding.get(KEY_PROJECTIONS).ok_or(INVALID_OBSERVATION_TEXT)?;
    for key in DigestKey::POLICIES {
        let expected = signed.get(key.name()).ok_or(INVALID_OBSERVATION_TEXT)?;
        let observed = projections.get(key.name()).and_then(Value::as_object).ok_or(INVALID_OBSERVATION_TEXT)?;
        let mut actual = Object::new();
        for (name, member) in observed.iter() {
            if name.as_bytes() != KEY_RESOURCE_VERSION.as_bytes() {
                actual.insert(name.clone(), member.clone());
            }
        }
        require(json::py_eq(&Value::Object(actual), expected), OBSERVED_IDENTITY_TEXT)?;
    }
    // Observed namespace (:109): its name and uid are the binding's namespace.
    let namespace = observation.get(KEY_NAMESPACE).ok_or(INVALID_OBSERVATION_TEXT)?;
    let mut pair = Object::new();
    for name in [KEY_NAME, KEY_UID] {
        pair.insert(JStr::new(name), namespace.get(name).ok_or(INVALID_OBSERVATION_TEXT)?.clone());
    }
    let bound_namespace = binding.get(KEY_NAMESPACE).ok_or(INVALID_OBSERVATION_TEXT)?;
    require(json::py_eq(&Value::Object(pair), bound_namespace), OBSERVED_NAMESPACE_TEXT)?;
    // Request binding (:110-111): the binding's canonical digest, then the scope's run nonce.
    let bound = json::canonical(binding).map(|bytes| sha256::prefixed(&bytes)).map_err(|_| INVALID_OBSERVATION_TEXT)?;
    let scope = binding.get(KEY_SCOPE).ok_or(INVALID_OBSERVATION_TEXT)?;
    if request.binding_digest == bound {
        let nonce = scope.get(KEY_RUN_NONCE).ok_or(INVALID_OBSERVATION_TEXT)?;
        require(nonce.as_str() == Some(request.run_nonce.as_str()), REQUEST_BINDING_TEXT)?;
    } else {
        return Err(REQUEST_BINDING_TEXT);
    }
    // Response substitution (:112-113): the five echo members are the request's.
    let echoed = text_of(observation, KEY_BINDING_DIGEST) == Some(request.binding_digest.as_str())
        && text_of(observation, KEY_RUN_NONCE) == Some(request.run_nonce.as_str())
        && text_of(observation, KEY_CHALLENGE) == Some(request.challenge.as_str())
        && integer_of(observation, KEY_SEQUENCE) == Some(request.sequence)
        && text_of(observation, KEY_PREVIOUS_DIGEST) == Some(request.previous_digest.as_str());
    require(echoed, RESPONSE_SUBSTITUTION_TEXT)?;
    // The chain rules (:114-125), by mode.
    match mode {
        ChainMode::Skip => {}
        ChainMode::Vpo(None) => {
            require(request.sequence == 1 && request.previous_digest == ZERO_DIGEST, INITIAL_CHAIN_TEXT)?;
        }
        ChainMode::Vpo(Some(previous)) => {
            shape(previous)?;
            let follows = integer_of(previous, KEY_SEQUENCE).and_then(|sequence| sequence.checked_add(1));
            let linked = text_of(previous, KEY_BINDING_DIGEST) == Some(request.binding_digest.as_str())
                && text_of(previous, KEY_RUN_NONCE) == Some(request.run_nonce.as_str())
                && follows == Some(request.sequence);
            let chained = linked
                && json::canonical(previous)
                    .is_ok_and(|bytes| sha256::prefixed(&bytes) == request.previous_digest);
            require(chained, CHAIN_GAP_TEXT)?;
            let same = text_of(observation, KEY_BOOT_ID) == text_of(previous, KEY_BOOT_ID)
                && text_of(observation, KEY_GENERATION) == text_of(previous, KEY_GENERATION)
                && text_of(previous, KEY_CHALLENGE) != Some(request.challenge.as_str());
            require(same, RESTART_TEXT)?;
            let current = instant_of(observation, KEY_OBSERVED_AT)?;
            require(current >= instant_of(previous, KEY_OBSERVED_AT)?, CLOCK_ROLLBACK_TEXT)?;
        }
    }
    // Stale or future (:126-127): validFrom <= observedAt <= now < expiresAt <= expiresAt of the scope, read in VPO's
    // order (the scope's expiresAt only once the rest holds).
    let start = instant_of(observation, KEY_OBSERVED_AT)?;
    let end = instant_of(observation, KEY_EXPIRES_AT)?;
    let instant = i64::try_from(now).unwrap_or(i64::MAX);
    let from = instant_of(scope, KEY_VALID_FROM)?;
    require(from <= start && start <= instant && instant < end, STALE_OR_FUTURE_TEXT)?;
    require(end <= instant_of(scope, KEY_EXPIRES_AT)?, STALE_OR_FUTURE_TEXT)?;
    // Freshness window (:128): 0 < expiresAt - observedAt <= 5 s.
    let fresh = i64::try_from(FRESHNESS_WINDOW_SECONDS).unwrap_or(0);
    require(end.checked_sub(start).is_some_and(|gap| 0 < gap && gap <= fresh), FRESHNESS_WINDOW_TEXT)?;
    // Enforcement proof (:129-130): {policyGeneration: generation, **enforcementPins}.
    let generation = observation.get(KEY_GENERATION).ok_or(INVALID_OBSERVATION_TEXT)?;
    let mut proof = Object::new();
    proof.insert(JStr::new(KEY_POLICY_GENERATION), generation.clone());
    let pins = binding.get(KEY_ENFORCEMENT_PINS).and_then(Value::as_object).ok_or(INVALID_OBSERVATION_TEXT)?;
    for (name, pin) in pins.iter() {
        proof.insert(name.clone(), pin.clone());
    }
    let enforcement = observation.get(KEY_ENFORCEMENT).ok_or(INVALID_OBSERVATION_TEXT)?;
    require(json::py_eq(enforcement, &Value::Object(proof)), ENFORCEMENT_PROOF_TEXT)?;
    // Actual quota headroom (:131-134), its `used <= hard` half for each unit.
    let quota = observation.get(KEY_QUOTA).ok_or(INVALID_OBSERVATION_TEXT)?;
    let hard = quota.get(KEY_HARD).ok_or(INVALID_OBSERVATION_TEXT)?;
    let used = quota.get(KEY_USED).ok_or(INVALID_OBSERVATION_TEXT)?;
    for unit in quota_units() {
        let limit = hard.get(unit).and_then(Value::as_int).ok_or(INVALID_OBSERVATION_TEXT)?;
        let spent = used.get(unit).and_then(Value::as_int).ok_or(INVALID_OBSERVATION_TEXT)?;
        require(spent <= limit, QUOTA_HEADROOM_TEXT)?;
    }
    Ok(())
}

/// VPO's observation rules on a given observation (DESIGN-I01B3 rev 4 section 3.4): VPO's decision and rule order for
/// `previous` absent (the initial chain) or given (shaped first, then the chain gap, the restart, drift or reused
/// challenge and the clock rollback), with `now` in whole seconds and `binding` the signed binding. `Ok` when VPO would
/// accept; otherwise the first failing rule's label, or VPO's generic text.
pub fn self_check(observation: &Value, request: &I01Request, binding: &Value, now: u64,
                  previous: Option<&Value>) -> Result<(), &'static str> {
    observation_rules(observation, request, binding, now, ChainMode::Vpo(previous))
}

// ------------------------------------------------------------------------------------------------ the answer

/// The answer to one checked request (DESIGN-I01B3 rev 4 section 3.4; DIB section 4.3 step 6), in this order, each
/// refusal closing:
/// 1. the request's `bindingDigest` and `runNonce` are the signed binding's ("request binding");
/// 2. the answer list ([`refusals`]) is empty, else its first text;
/// 3. the capture set's record digest is the derived `hostPreflightDigest`, which is the signed pin;
/// 4. one wall reading `wall_ms`, `now` its whole seconds: `observedAt` is `now`'s UTC text, at or after the scope's,
///    the record's and the configuration's starts, and `expiresAt` the least of `observedAt` + 5 s, the scope's end,
///    the record's end less [`RECORD_EXPIRY_MARGIN_SECONDS`] and the configuration's end, after `observedAt`;
/// 5. `observedAt` is not before the session's last one, both whole seconds;
/// 6. the 14 members: the schema version, the request's five echo members, the record's `host.bootId`, the two times,
///    the generation (and `policyGeneration`), the namespace member, the projections with their resourceVersion, the
///    quota pair and the four digests;
/// 7. VPO's observation rules, without the chain rules (I3D-1), on the signed binding at `now`;
/// 8. the canonical bytes, at most 65,536.
pub fn answer(derived: &Derived, checked: &I01Request, facts: &CaptureFacts, wall_ms: u64,
              last_observed: Option<u64>) -> Result<Vec<u8>, &'static str> {
    // 1. The binding (B3-6 (3)).
    require(checked.binding_digest == derived.bound_digest() && checked.run_nonce == derived.bound_nonce(),
            REQUEST_BINDING_TEXT)?;
    // 2. The answer list.
    if let Some(&refusal) = refusals(derived, facts).first() {
        return Err(refusal);
    }
    // 3. The record digest.
    let preflight = derived
        .digest_values()
        .iter()
        .find(|(key, _)| *key == DigestKey::HostPreflightDigest)
        .and_then(|(_, outcome)| outcome.as_ref().ok())
        .map(|value| value.digest.as_str());
    let pinned = derived
        .binding_member()
        .get(KEY_ENFORCEMENT_PINS)
        .and_then(|pins| pins.get(DigestKey::HostPreflightDigest.name()))
        .and_then(Value::as_str);
    require(preflight.is_some() && preflight == Some(facts.record_digest.as_str()) && pinned == preflight,
            RECORD_DIGEST_TEXT)?;
    // 4. The windows at one reading.
    let now = wall_ms / 1000;
    let observed_at = utc_text(now).ok_or(ANSWER_WINDOW_TEXT)?;
    let instant = i64::try_from(now).map_err(|_| ANSWER_WINDOW_TEXT)?;
    let (scope_from, scope_until) = derived.scope_window();
    let (record_from, record_until) = derived.record_window();
    let (config_from, config_until) = derived.config_window();
    require(instant >= scope_from && instant >= record_from && instant >= config_from, ANSWER_WINDOW_TEXT)?;
    let fresh = i64::try_from(FRESHNESS_WINDOW_SECONDS).ok().and_then(|seconds| instant.checked_add(seconds));
    let margin = i64::try_from(RECORD_EXPIRY_MARGIN_SECONDS).ok().and_then(|seconds| record_until.checked_sub(seconds));
    let (Some(fresh), Some(margin)) = (fresh, margin) else {
        return Err(ANSWER_WINDOW_TEXT);
    };
    let expires = fresh.min(scope_until).min(margin).min(config_until);
    require(expires > instant, ANSWER_WINDOW_TEXT)?;
    let expires_at = u64::try_from(expires).ok().and_then(utc_text).ok_or(ANSWER_WINDOW_TEXT)?;
    // 5. The session's rollback.
    require(last_observed.is_none_or(|last| now >= last), ANSWER_ROLLBACK_TEXT)?;
    // 6. The members.
    let mut projections = Object::new();
    for (key, outcome) in derived.policy_values() {
        let value = match outcome.as_ref() {
            Ok(value) => value,
            Err(&refusal) => return Err(refusal),
        };
        let mut member = value.identity.as_object().cloned().ok_or(INVALID_OBSERVATION_TEXT)?;
        member.insert(JStr::new(KEY_RESOURCE_VERSION), value.resource_version.clone());
        projections.insert(JStr::new(key.name()), Value::Object(member));
    }
    let mut enforcement = Object::new();
    enforcement.insert(JStr::new(KEY_POLICY_GENERATION), Value::str(derived.generation_hex()));
    for (key, outcome) in derived.digest_values() {
        let value = match outcome.as_ref() {
            Ok(value) => value,
            Err(&refusal) => return Err(refusal),
        };
        enforcement.insert(JStr::new(key.name()), Value::str(&value.digest));
    }
    let mut observation = Object::new();
    observation.insert(JStr::new(KEY_SCHEMA_VERSION), Value::str(KEY_OBSERVATION_SCHEMA));
    observation.insert(JStr::new(KEY_BINDING_DIGEST), Value::str(&checked.binding_digest));
    observation.insert(JStr::new(KEY_RUN_NONCE), Value::str(&checked.run_nonce));
    observation.insert(JStr::new(KEY_CHALLENGE), Value::str(&checked.challenge));
    observation.insert(JStr::new(KEY_SEQUENCE), Value::Int(Int::from_u64(checked.sequence)));
    observation.insert(JStr::new(KEY_PREVIOUS_DIGEST), Value::str(&checked.previous_digest));
    observation.insert(JStr::new(KEY_BOOT_ID), Value::str(derived.boot_id()));
    observation.insert(JStr::new(KEY_GENERATION), Value::str(derived.generation_hex()));
    observation.insert(JStr::new(KEY_OBSERVED_AT), Value::str(&observed_at));
    observation.insert(JStr::new(KEY_EXPIRES_AT), Value::str(&expires_at));
    observation.insert(JStr::new(KEY_NAMESPACE), derived.namespace_member().clone());
    observation.insert(JStr::new(KEY_PROJECTIONS), Value::Object(projections));
    observation.insert(JStr::new(KEY_QUOTA), derived.quota_pair().clone());
    observation.insert(JStr::new(KEY_ENFORCEMENT), Value::Object(enforcement));
    let observation = Value::Object(observation);
    // 7. The observation rules without the chain rules, on the signed binding (I3D-1, I3D-5).
    observation_rules(&observation, checked, derived.binding_member(), now, ChainMode::Skip)?;
    // 8. The bound.
    let bytes = json::canonical(&observation).map_err(|_| OBSERVATION_BYTES_TEXT)?;
    require(bytes.len() <= ANSWER_LIMIT, OBSERVATION_BYTES_TEXT)?;
    Ok(bytes)
}
