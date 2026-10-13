//! The I07 replay driver shared by the I07 contract and R10-local vector tests (HE-002B). FRAME events become I05 broker
//! frames as in `support`; W_FRAME events become the writer frame a correct writer sends next (HE-002B DESIGN §7, N18): the
//! current session's next sequence and last digest, whether it opened or not, otherwise 1 and the zero digest, with
//! the challenge of the latest W_CONNECT event (refused or not), then the event's `mutate` operations. Every other
//! event is typed directly. Outputs and the final snapshot are recorded as JSON values.
#![allow(dead_code)]

use effect_gate::{Event, PolicyEvent, PolicyGate, UpstreamOutcome, UpstreamResponse, WRITER_FRAME_VERSION};
use i05_protocol::json::{JStr, Object, Value};

use crate::support::*;

pub const I07_VECTORS: &str = include_str!("../../../../contracts/i07-v3/vectors.json");
pub const KINDS: &str = include_str!("../../../../contracts/i07-v3/policy-kinds.json");

/// A replay with its broker-frame count (`replay.frames`) and its writer-frame count.
pub struct PolicyReplay {
    pub replay: Replay,
    pub writer_frames: usize,
}

/// The writer frame a W_FRAME event stands for.
pub fn writer_frame(challenge: &Value, next_sequence: i64, last_digest: &str, event: &Value) -> Value {
    let mut envelope = Object::new();
    envelope.insert(JStr::new("schemaVersion"), Value::str(WRITER_FRAME_VERSION));
    envelope.insert(JStr::new("challenge"), challenge.clone());
    envelope.insert(JStr::new("sequence"), Value::int(next_sequence));
    envelope.insert(JStr::new("previousDigest"), Value::str(last_digest));
    envelope.insert(JStr::new("direction"), Value::str("WRITER_TO_GATE"));
    envelope.insert(JStr::new("operation"), field(event, "operation").clone());
    envelope.insert(JStr::new("payload"), field(event, "payload").clone());
    apply_mutations(Value::Object(envelope), event.get("mutate"))
}

fn optional_text(value: &Value, key: &str) -> Option<String> {
    match field(value, key) {
        Value::Null => None,
        other => Some(other.as_str().unwrap_or_else(|| panic!("{key} is text or null")).to_string()),
    }
}

/// A W_UPSTREAM event's outcome: `"LOST"`, `"TIMEOUT"` or a response object.
pub fn upstream_outcome(upstream: &Value) -> UpstreamOutcome {
    match upstream {
        Value::Str(_) if upstream.as_str() == Some("LOST") => UpstreamOutcome::Lost,
        Value::Str(_) if upstream.as_str() == Some("TIMEOUT") => UpstreamOutcome::Timeout,
        Value::Object(_) => UpstreamOutcome::Response(UpstreamResponse {
            http_status: field(upstream, "httpStatus").as_int().and_then(|status| status.to_i64()).expect("status"),
            body_digest: text(upstream, "bodyDigest").to_string(),
            uid: optional_text(upstream, "uid"),
            resource_version: optional_text(upstream, "resourceVersion"),
        }),
        other => panic!("unknown upstream outcome {}", show(other)),
    }
}

/// Replays one event list on a fresh PolicyGate.
pub fn replay_i07(config_value: &Value, kinds_value: &Value, events: &[Value], mode: Mode, context: &str) -> PolicyReplay {
    let mut gate =
        PolicyGate::new(config_value, kinds_value).unwrap_or_else(|error| panic!("{context}: configuration refused: {error:?}"));
    let broker_schema = i05_protocol::i05_v3_schema().expect("I05 schema");
    let writer_schema = i05_protocol::i07_v3_schema().expect("I07 schema");
    let mut replay = Replay { outputs: Vec::new(), snapshot: Value::Null, frames: 0, value_fallbacks: 0 };
    let mut writer_frames = 0usize;
    let mut challenge = Value::Null;
    for (index, event) in events.iter().enumerate() {
        let context = format!("{context} event {index}");
        let typed = match text(event, "type") {
            "FRAME" => {
                let base = gate.gate();
                let built = broker_frame(config_value, base.next_sequence(), base.last_digest(), event);
                assert_bytes_path_agrees(&built, &broker_schema, &context);
                replay.frames += 1;
                PolicyEvent::Base(Event::Frame(frame_input(built, mode, &mut replay.value_fallbacks)))
            }
            "W_CONNECT" => {
                challenge = field(event, "challenge").clone();
                PolicyEvent::WConnect { challenge: text(event, "challenge").to_string() }
            }
            "W_FRAME" => {
                let built = writer_frame(&challenge, gate.writer_next_sequence(), gate.writer_last_digest(), event);
                assert_bytes_path_agrees(&built, &writer_schema, &context);
                writer_frames += 1;
                PolicyEvent::WFrame(frame_input(built, mode, &mut replay.value_fallbacks))
            }
            "W_UPSTREAM" => {
                let write_id = field(event, "writeId").as_int().and_then(|id| id.to_u64()).expect("writeId");
                PolicyEvent::WUpstream {
                    write_id: u16::try_from(write_id).expect("writeId"),
                    outcome: upstream_outcome(field(event, "upstream")),
                }
            }
            "W_CHANNEL_LOST" => PolicyEvent::WChannelLost,
            "W_PEER_CHANGED" => PolicyEvent::WPeerChanged,
            _ => PolicyEvent::Base(base_event(event, &context)),
        };
        let output = gate.handle(typed).unwrap_or_else(|error| panic!("{context}: {error:?}"));
        replay.outputs.push(output.to_doc().to_value());
    }
    replay.snapshot = gate.snapshot().to_value();
    PolicyReplay { replay, writer_frames }
}
