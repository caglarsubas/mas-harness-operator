//! I05, the broker's side of the gate channel (HE-005B: DESIGN-HE005 revision 5 sections 1 (O14, O18) and 3.3 steps 2
//! and 7; the HE-005B plan's item 4; MON-HE005B-PLAN). A logic module: pure (no I/O, no system call, safe Rust only),
//! no panic, std only and i05-protocol's public items as they are: its `i05_v3_schema()` (the vendored
//! `contracts/i05-v3/channel.schema.json`, which i05-protocol itself embeds; this module embeds nothing) and its
//! `decode_frame` (I05's 16 KiB limit is that decoder's). No client codec goes into i05-protocol (H5D-12). Nothing in
//! `main`, `serve`, `seal.rs`, `status.rs` or `linux_listen.rs` names it, so planeon-broker's behaviour stays HE-005A's
//! (G-HE5B-1).
//!
//! [`I05Client`] holds one gate generation's channel from the broker's side (the i05-v3 README's "Channel"; v4 adds no
//! frame and no operation):
//! - the opening request is GENERATION_STATUS with sequence 1, the all-zero previous digest, the gate's generation
//!   and a fresh 256-bit challenge, both supplied by the caller; every later frame carries the same generation and
//!   challenge;
//! - the lockstep: odd sequences are the broker's requests, even ones the gate's responses, one response per request
//!   and no unsolicited gate frame; `previousDigest` is the SHA-256 of the exact bytes of the frame before it;
//! - the request builders: GENERATION_STATUS, BIND_EXECUTION (with `peerQualificationDigest` and the worker's pid and
//!   start ticks as inputs, O14, O18), ARM_ACTION, ACTION_OUTCOME and CLOSE_GENERATION, each checked by `decode_frame`
//!   under the same schema before it is returned;
//! - each gate response decoded by `decode_frame` under that schema, then its direction, sequence, chain, generation,
//!   challenge and operation checked, and the execution and action ids an OK answer repeats. "The broker verifies the
//!   gate's frames the same way" (i05-v3 README:76): any deviation is the channel's end, with no repair or retry.
//!
//! Whether a refused BIND_EXECUTION answers the server's DISPATCH is i02.rs's refusal map ([`Response::bind_refusal`]).

use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::schema::Schema;
use i05_protocol::sha256;
use i05_protocol::{decode_frame, i05_v3_schema, Datagram, FrameError};

use crate::i02::{BindRefusal, Verb, ZERO_DIGEST};

/// The I05 v3 frame version (unchanged in v4).
pub const I05_FRAME_VERSION: &str = "planeon.internal.effect-gate-frame/v3";
/// The two directions.
pub const BROKER_TO_GATE: &str = "BROKER_TO_GATE";
pub const GATE_TO_BROKER: &str = "GATE_TO_BROKER";

/// The five request operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    GenerationStatus,
    BindExecution,
    ArmAction,
    ActionOutcome,
    CloseGeneration,
}

impl Operation {
    pub fn wire(self) -> &'static str {
        match self {
            Operation::GenerationStatus => "GENERATION_STATUS",
            Operation::BindExecution => "BIND_EXECUTION",
            Operation::ArmAction => "ARM_ACTION",
            Operation::ActionOutcome => "ACTION_OUTCOME",
            Operation::CloseGeneration => "CLOSE_GENERATION",
        }
    }
}

/// CLOSE_GENERATION's reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    NormalDrain,
    Revocation,
    Expiry,
    PeerFailure,
    StorageFailure,
    ObservationFailure,
    ReconciliationRequired,
}

impl CloseReason {
    pub fn wire(self) -> &'static str {
        match self {
            CloseReason::NormalDrain => "NORMAL_DRAIN",
            CloseReason::Revocation => "REVOCATION",
            CloseReason::Expiry => "EXPIRY",
            CloseReason::PeerFailure => "PEER_FAILURE",
            CloseReason::StorageFailure => "STORAGE_FAILURE",
            CloseReason::ObservationFailure => "OBSERVATION_FAILURE",
            CloseReason::ReconciliationRequired => "RECONCILIATION_REQUIRED",
        }
    }

    pub fn from_wire(name: &str) -> Option<CloseReason> {
        Some(match name {
            "NORMAL_DRAIN" => CloseReason::NormalDrain,
            "REVOCATION" => CloseReason::Revocation,
            "EXPIRY" => CloseReason::Expiry,
            "PEER_FAILURE" => CloseReason::PeerFailure,
            "STORAGE_FAILURE" => CloseReason::StorageFailure,
            "OBSERVATION_FAILURE" => CloseReason::ObservationFailure,
            "RECONCILIATION_REQUIRED" => CloseReason::ReconciliationRequired,
            _ => return None,
        })
    }
}

/// BIND_EXECUTION's inputs, a plain value: the DISPATCH's fields, the broker's execution id, the server certificate
/// digest (HE-005D's and HE-008's source), the frozen worker's pid and start ticks (section 3.3 step 7, O14) and the
/// signed configured `peerQualificationDigest` (O18).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bind {
    pub execution_id: String,
    pub binding_digest: String,
    pub reservation_digest: String,
    pub run_nonce: String,
    pub case_id: String,
    pub request_digest: String,
    pub dispatch_generation: String,
    pub server_certificate_digest: String,
    pub worker_pid: i64,
    pub worker_start_ticks: i64,
    pub peer_qualification_digest: String,
}

/// Why the channel ended on the broker's side. Every one is the channel's end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelEnd {
    /// The caller's generation or challenge is not 64 lowercase hexadecimal digits.
    Form,
    /// i05-protocol's I05 v3 schema did not load.
    Schema,
    /// The first request is not GENERATION_STATUS.
    Opening,
    /// A request while another is outstanding (the lockstep).
    Outstanding,
    /// A built request that `decode_frame` refuses.
    Request(FrameError),
    /// A gate frame with no request outstanding.
    Unsolicited,
    /// A gate frame that `decode_frame` refuses.
    Frame(FrameError),
    /// A frame that is not GATE_TO_BROKER.
    Direction,
    /// A sequence other than the outstanding request's plus one.
    Sequence,
    /// A previous digest other than the SHA-256 of the request's exact bytes.
    Chain,
    /// Another generation.
    Generation,
    /// Another challenge.
    Challenge,
    /// Another operation than the outstanding request's.
    Operation,
    /// An OK answer that repeats another execution id or action id than its request's.
    Answer,
    /// The channel has ended.
    Ended,
}

/// The outstanding request.
#[derive(Clone, Debug)]
struct Pending {
    operation: Operation,
    sequence: i64,
    execution_id: Option<String>,
    action_id: Option<i64>,
}

/// One accepted gate response.
#[derive(Clone, Debug)]
pub struct Response {
    operation: Operation,
    sequence: i64,
    payload: Value,
}

impl Response {
    pub fn operation(&self) -> Operation {
        self.operation
    }

    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    pub fn payload(&self) -> &Value {
        &self.payload
    }

    /// Whether the gate refused the request (`result` REFUSED).
    pub fn is_refused(&self) -> bool {
        text(&self.payload, "result") == Some("REFUSED")
    }

    /// A refused BIND_EXECUTION's reason, for i02.rs's refusal map; `None` for any other response.
    pub fn bind_refusal(&self) -> Option<BindRefusal> {
        if self.operation != Operation::BindExecution || !self.is_refused() {
            return None;
        }
        text(&self.payload, "reason").and_then(BindRefusal::from_wire)
    }
}

/// One gate generation's channel, from the broker's side.
pub struct I05Client {
    schema: Schema,
    generation: String,
    challenge: String,
    next_sequence: i64,
    last_digest: String,
    pending: Option<Pending>,
    opened: bool,
    over: bool,
}

impl I05Client {
    /// The channel for the gate's `generation` with the broker's fresh `challenge` (each 64 lowercase hexadecimal
    /// digits), before its opening request.
    pub fn open(generation: &str, challenge: &str) -> Result<I05Client, ChannelEnd> {
        if !is_hex64(generation) || !is_hex64(challenge) {
            return Err(ChannelEnd::Form);
        }
        let schema = i05_v3_schema().map_err(|_| ChannelEnd::Schema)?;
        Ok(I05Client {
            schema,
            generation: String::from(generation),
            challenge: String::from(challenge),
            next_sequence: 1,
            last_digest: String::from(ZERO_DIGEST),
            pending: None,
            opened: false,
            over: false,
        })
    }

    /// Whether the channel has ended.
    pub fn is_over(&self) -> bool {
        self.over
    }

    /// The outstanding request's operation, if one is outstanding.
    pub fn awaiting(&self) -> Option<Operation> {
        self.pending.as_ref().map(|pending| pending.operation)
    }

    /// GENERATION_STATUS, the opening request (and a status request later).
    pub fn generation_status(&mut self) -> Result<Vec<u8>, ChannelEnd> {
        self.request(Operation::GenerationStatus, Vec::new(), None, None)
    }

    /// BIND_EXECUTION.
    pub fn bind_execution(&mut self, bind: &Bind) -> Result<Vec<u8>, ChannelEnd> {
        let payload = vec![
            ("executionId", Value::str(&bind.execution_id)),
            ("bindingDigest", Value::str(&bind.binding_digest)),
            ("reservationDigest", Value::str(&bind.reservation_digest)),
            ("runNonce", Value::str(&bind.run_nonce)),
            ("caseId", Value::str(&bind.case_id)),
            ("requestDigest", Value::str(&bind.request_digest)),
            ("dispatchGeneration", Value::str(&bind.dispatch_generation)),
            ("serverCertificateDigest", Value::str(&bind.server_certificate_digest)),
            ("workerPid", Value::int(bind.worker_pid)),
            ("workerStartTicks", Value::int(bind.worker_start_ticks)),
            ("peerQualificationDigest", Value::str(&bind.peer_qualification_digest)),
        ];
        self.request(Operation::BindExecution, payload, Some(bind.execution_id.clone()), None)
    }

    /// ARM_ACTION: `recorded_uid` is a DELETE's recorded uid, `None` otherwise.
    pub fn arm_action(&mut self, execution_id: &str, action_id: i64, verb: Verb, manifest_digest: &str,
                      request_template_digest: &str, recorded_uid: Option<&str>) -> Result<Vec<u8>, ChannelEnd> {
        let payload = vec![
            ("executionId", Value::str(execution_id)),
            ("actionId", Value::int(action_id)),
            ("verb", Value::str(verb.wire())),
            ("manifestDigest", Value::str(manifest_digest)),
            ("requestTemplateDigest", Value::str(request_template_digest)),
            ("recordedUid", recorded_uid.map_or(Value::Null, Value::str)),
        ];
        self.request(Operation::ArmAction, payload, Some(String::from(execution_id)), Some(action_id))
    }

    /// ACTION_OUTCOME.
    pub fn action_outcome(&mut self, execution_id: &str, action_id: i64) -> Result<Vec<u8>, ChannelEnd> {
        let payload = vec![("executionId", Value::str(execution_id)), ("actionId", Value::int(action_id))];
        self.request(Operation::ActionOutcome, payload, Some(String::from(execution_id)), Some(action_id))
    }

    /// CLOSE_GENERATION.
    pub fn close_generation(&mut self, reason: CloseReason) -> Result<Vec<u8>, ChannelEnd> {
        self.request(Operation::CloseGeneration, vec![("reason", Value::str(reason.wire()))], None, None)
    }

    fn request(&mut self, operation: Operation, payload: Vec<(&str, Value)>, execution_id: Option<String>,
               action_id: Option<i64>) -> Result<Vec<u8>, ChannelEnd> {
        if self.over {
            return Err(ChannelEnd::Ended);
        }
        if self.pending.is_some() {
            return self.end(ChannelEnd::Outstanding);
        }
        if !self.opened && operation != Operation::GenerationStatus {
            return self.end(ChannelEnd::Opening);
        }
        let mut body = Object::new();
        for (name, value) in payload {
            body.insert(JStr::new(name), value);
        }
        let sequence = self.next_sequence;
        let frame = self.envelope(sequence, operation, Value::Object(body));
        let Ok(raw) = json::canonical(&frame) else {
            return self.end(ChannelEnd::Request(FrameError::F06));
        };
        if let Err(code) = decode_frame(Datagram::Bytes(&raw), &self.schema) {
            return self.end(ChannelEnd::Request(code));
        }
        self.last_digest = sha256::prefixed(&raw);
        self.pending = Some(Pending { operation, sequence, execution_id, action_id });
        self.opened = true;
        Ok(raw)
    }

    fn envelope(&self, sequence: i64, operation: Operation, payload: Value) -> Value {
        let mut frame = Object::new();
        frame.insert(JStr::new("schemaVersion"), Value::str(I05_FRAME_VERSION));
        frame.insert(JStr::new("generation"), Value::str(&self.generation));
        frame.insert(JStr::new("challenge"), Value::str(&self.challenge));
        frame.insert(JStr::new("sequence"), Value::int(sequence));
        frame.insert(JStr::new("previousDigest"), Value::str(&self.last_digest));
        frame.insert(JStr::new("direction"), Value::str(BROKER_TO_GATE));
        frame.insert(JStr::new("operation"), Value::str(operation.wire()));
        frame.insert(JStr::new("payload"), payload);
        Value::Object(frame)
    }

    /// Checks one received gate datagram against the outstanding request and, if it holds, takes it as its response.
    pub fn receive(&mut self, raw: &[u8]) -> Result<Response, ChannelEnd> {
        if self.over {
            return Err(ChannelEnd::Ended);
        }
        let result = self.check(raw);
        if result.is_err() {
            self.over = true;
        }
        result
    }

    fn check(&mut self, raw: &[u8]) -> Result<Response, ChannelEnd> {
        let Some(pending) = self.pending.clone() else {
            return Err(ChannelEnd::Unsolicited);
        };
        let frame = decode_frame(Datagram::Bytes(raw), &self.schema).map_err(ChannelEnd::Frame)?;
        if text(&frame, "direction") != Some(GATE_TO_BROKER) {
            return Err(ChannelEnd::Direction);
        }
        let sequence = pending.sequence.checked_add(1).ok_or(ChannelEnd::Sequence)?;
        if integer(&frame, "sequence") != Some(sequence) {
            return Err(ChannelEnd::Sequence);
        }
        if text(&frame, "previousDigest") != Some(self.last_digest.as_str()) {
            return Err(ChannelEnd::Chain);
        }
        if text(&frame, "generation") != Some(self.generation.as_str()) {
            return Err(ChannelEnd::Generation);
        }
        if text(&frame, "challenge") != Some(self.challenge.as_str()) {
            return Err(ChannelEnd::Challenge);
        }
        if text(&frame, "operation") != Some(pending.operation.wire()) {
            return Err(ChannelEnd::Operation);
        }
        let payload = frame.get("payload").ok_or(ChannelEnd::Frame(FrameError::F00))?;
        if !answers(&pending, payload) {
            return Err(ChannelEnd::Answer);
        }
        let payload = payload.clone();
        self.last_digest = sha256::prefixed(raw);
        self.next_sequence = sequence.saturating_add(1);
        self.pending = None;
        Ok(Response { operation: pending.operation, sequence, payload })
    }

    fn end<T>(&mut self, end: ChannelEnd) -> Result<T, ChannelEnd> {
        self.over = true;
        Err(end)
    }
}

/// Whether an OK answer repeats its request's execution id and action id where it carries them (BIND_EXECUTION's
/// executionId; ARM_ACTION's and ACTION_OUTCOME's actionId). A refusal carries only its reason.
fn answers(pending: &Pending, payload: &Value) -> bool {
    if text(payload, "result") != Some("OK") {
        return true;
    }
    let execution = match (&pending.execution_id, payload.get("executionId")) {
        (Some(expected), Some(_)) => text(payload, "executionId") == Some(expected.as_str()),
        _ => true,
    };
    let action = match (pending.action_id, payload.get("actionId")) {
        (Some(expected), Some(_)) => integer(payload, "actionId") == Some(expected),
        _ => true,
    };
    execution && action
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn integer(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_int).and_then(json::Int::to_i64)
}

/// 64 lowercase hexadecimal digits.
fn is_hex64(candidate: &str) -> bool {
    candidate.len() == 64 && candidate.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
