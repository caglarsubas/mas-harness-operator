//! The I01 capture gate (HE-004-I01B1; DESIGN-I01B rev 3 sections 2 and 6 and DESIGN-I01B1 rev 2; owner decision
//! Q-HE4I1-2 and the monitor's Q-I01B-13, Q-I01B-14 and Q-I01B-21): whether a capture-gated value may be in an I01
//! answer, exactly the contract's rule (`contracts/i01-digests-v1/README.md` section 3.3, `definitions.json`
//! `captureGate`, the pinned reference model's `capture_gate` and `required_slots`), over plain data. A pure logic
//! module under the I01 logic whitelist (`tools/gate.py`, I01_LOGIC_PATHS): no clock, no capture view, no system call
//! beyond allocation, every function total, no panic, and no caller in the binary (G-I01B-1).
//!
//! - The latest completed capture set at the answer is handed in ([`LatestSet`]): each slot with whether it is `TAKEN`
//!   in that set, and the set's two ages at the answer. No completed set is `None`. An Expired view is presented as a
//!   set whose slots are all not taken (README section 3.3).
//! - The rule: a completed set exists (else the value's own text); every slot the value requires is taken in it (else
//!   the value's own text); its monotonic age (the answer's reading minus the set's own scheduled start) and its wall
//!   age (the answer's wall reading minus the set's `set_started_ms`) both lie in 0..=90,000 ms (else "<key>: capture
//!   set too old"). The texts are the contract's, held in `i01_digest` (`DigestKey::capture_not_passed`,
//!   `capture_too_old`, `malformed`).
//! - The gate bound and G-I01B-8's three literal pins live here; `CYCLE` (`observe.rs`), `SCRAPE_TO_SET` and
//!   `SET_BUDGET` (`capture.rs`) stay where they are. `tools/gate.py` checks each against its source.
//! - Not here: the facts' construction from R10's capture view and clocks, and the answer (HE-004-I01B3).

use i05_protocol::json::Value;

use crate::i01_digest::DigestKey;

/// The capture gate's bound (README section 3.3; `definitions.json` `captureGate.boundMs`): R10's 60 s cycle
/// (`CYCLE`), plus the 5 s start bound (`SCRAPE_TO_SET`), plus the 25 s set budget (`SET_BUDGET`).
pub const GATE_BOUND_MS: u64 = 90_000;

/// G-I01B-8's literal pin: an answer's canonical bytes are at most 65,536 (VPO's `_shape` of the observation,
/// harness-onion `scripts/validate_policy_observation.py:86-88` at `2043cc27`; VPO pinned by digest in PROVENANCE).
pub const ANSWER_LIMIT: usize = 65_536;

/// G-I01B-8's literal pin: an answer's `expiresAt` is at most 5 s after its `observedAt` (VPO's freshness rule,
/// harness-onion `scripts/validate_policy_observation.py:128` at `2043cc27`).
pub const FRESHNESS_WINDOW_SECONDS: u64 = 5;

/// G-I01B-8's literal pin: no answer later than the request's receipt plus 2 s on the monotonic clock (the monitor's
/// Q-I01B-21 (a)).
pub const EXCHANGE_DEADLINE_SECONDS: u64 = 2;

/// The capture slots (README section 3.3; `definitions.json` `captureGate.slots`): the five roles' slots in the
/// model's order, the lifecycle slot and the prefix of each backend component's slot.
pub const ROLE_SLOTS: [&str; 5] = ["role/SERVER", "role/OBSERVER", "role/BROKER", "role/WORKER", "role/EFFECT_GATE"];
pub const LIFECYCLE_SLOT: &str = "lifecycle";
pub const BACKEND_SLOT_PREFIX: &str = "backend/";
/// The one slot `mutationBroker` requires, and the one `networkEnforcementDigest` requires
/// (`definitions.json` `captureGate.requiredSlots`).
const BROKER_SLOT: &str = "role/BROKER";
const AGENT_SLOT: &str = "backend/NETWORK_POLICY_AGENT";

/// The latest completed capture set at one answer, as plain data (DESIGN-I01B rev 3 section 2).
/// - `slots`: each slot's name with whether it is `TAKEN` in that set.
/// - `mono_age_ms`: the answer's monotonic reading minus the set's own scheduled start. When the start lies after the
///   answer, `scheduled_after_now` is set and the age is not read.
/// - `wall_age_ms`: the answer's wall reading minus the set's `set_started_ms`; negative after a backward step.
#[derive(Clone, Copy, Debug)]
pub struct LatestSet<'a> {
    pub slots: &'a [(String, bool)],
    pub scheduled_after_now: bool,
    pub mono_age_ms: u64,
    pub wall_age_ms: i64,
}

/// The capture gate for one gated value at one answer (the model's `capture_gate`), or the contract's refusal text:
/// - a key that is not capture-gated is that key's malformed input (the model's "unknown gated key" is no contract
///   text; R10 never asks);
/// - no completed set: the value's own text;
/// - a required slot not taken: the value's own text (for `hostPreflightDigest`, a record without a non-empty
///   `backendComponents` object is its malformed input, after a completed set is found, as in the model);
/// - either age outside 0..=[`GATE_BOUND_MS`]: "<key>: capture set too old".
pub fn capture_gate(key: DigestKey, latest: Option<&LatestSet<'_>>, record: &Value) -> Result<(), &'static str> {
    let (Some(not_passed), Some(too_old)) = (key.capture_not_passed(), key.capture_too_old()) else {
        return Err(key.malformed());
    };
    let Some(latest) = latest else {
        return Err(not_passed);
    };
    let required = required_slots(key, record)?;
    if !required.iter().all(|slot| taken(latest.slots, slot)) {
        return Err(not_passed);
    }
    let monotonic = !latest.scheduled_after_now && latest.mono_age_ms <= GATE_BOUND_MS;
    let wall = i64::try_from(GATE_BOUND_MS).is_ok_and(|bound| (0..=bound).contains(&latest.wall_age_ms));
    if !(monotonic && wall) {
        return Err(too_old);
    }
    Ok(())
}

/// The slots a gated value requires (the model's `required_slots`), each as its name's bytes: `role/BROKER` for
/// `mutationBroker`, `backend/NETWORK_POLICY_AGENT` for `networkEnforcementDigest`, and for `hostPreflightDigest` the
/// five role slots, `lifecycle` and `backend/<component>` for each member of the record's `backendComponents`, in
/// code-point order. A component name holding a lone surrogate keeps its generalized UTF-8 bytes, which no slot name
/// equals, so it is never taken.
fn required_slots(key: DigestKey, record: &Value) -> Result<Vec<Vec<u8>>, &'static str> {
    match key {
        DigestKey::MutationBroker => Ok(vec![BROKER_SLOT.as_bytes().to_vec()]),
        DigestKey::NetworkEnforcementDigest => Ok(vec![AGENT_SLOT.as_bytes().to_vec()]),
        _ => {
            let components = record
                .get("backendComponents")
                .and_then(Value::as_object)
                .filter(|components| !components.is_empty())
                .ok_or(key.malformed())?;
            let mut backends: Vec<Vec<u8>> = components
                .iter()
                .map(|(name, _)| [BACKEND_SLOT_PREFIX.as_bytes(), name.as_bytes()].concat())
                .collect();
            backends.sort_unstable();
            let mut slots: Vec<Vec<u8>> = ROLE_SLOTS.iter().map(|slot| slot.as_bytes().to_vec()).collect();
            slots.push(LIFECYCLE_SLOT.as_bytes().to_vec());
            slots.extend(backends);
            Ok(slots)
        }
    }
}

/// Whether the set holds the slot and every entry of that name is taken (a name listed twice must be taken twice).
fn taken(slots: &[(String, bool)], slot: &[u8]) -> bool {
    let mut seen = false;
    for (name, is_taken) in slots {
        if name.as_bytes() == slot {
            if !is_taken {
                return false;
            }
            seen = true;
        }
    }
    seen
}
