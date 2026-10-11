//! The replay driver shared by the contract and R10-local vector tests: it turns vector events into typed gate events,
//! builds each FRAME envelope as a correct broker would send it next (the vectors' replay rule), applies the event's
//! `mutate` operations, and records every output and the final snapshot as JSON values.
#![allow(dead_code)]

use effect_gate::{Config, Event, FrameInput, Gate, UpstreamResponse};
use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::{frame, Datagram, FrameError, Schema, FRAME_VERSION};

pub fn load(text: &str) -> Value {
    json::parse(text).expect("vector file parses")
}

pub fn field<'a>(row: &'a Value, key: &str) -> &'a Value {
    row.get(key).unwrap_or_else(|| panic!("missing {key}"))
}

pub fn text<'a>(row: &'a Value, key: &str) -> &'a str {
    field(row, key).as_str().unwrap_or_else(|| panic!("{key} is not text"))
}

pub fn rows<'a>(document: &'a Value, key: &str) -> &'a [Value] {
    field(document, key).as_array().unwrap_or_else(|| panic!("{key} is not an array"))
}

pub fn show(value: &Value) -> String {
    json::canonical(value).map(|raw| String::from_utf8_lossy(&raw).into_owned()).unwrap_or_else(|_| format!("{value:?}"))
}

/// How FRAME events reach the gate.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// As values through `check_frame` (the contract's replay form).
    Value,
    /// Encoded canonically and decoded by `decode_frame` (DESIGN §13 E12); a frame without a canonical encoding falls
    /// back to the value path.
    Bytes,
}

pub struct Replay {
    pub outputs: Vec<Value>,
    pub snapshot: Value,
    pub frames: usize,
    pub value_fallbacks: usize,
}

fn child_mut<'a>(node: &'a mut Value, key: &Value) -> &'a mut Value {
    match (node, key) {
        (Value::Object(object), Value::Str(name)) => object.get_key_mut(name).expect("mutation path"),
        (Value::Array(items), Value::Int(index)) => {
            let index = index.to_u64().and_then(|index| usize::try_from(index).ok()).expect("mutation index");
            items.get_mut(index).expect("mutation index")
        }
        _ => panic!("mutation path through a scalar"),
    }
}

/// The vectors' `mutate` operations (`set` and `delete` at a path).
pub fn apply_mutations(mut value: Value, operations: Option<&Value>) -> Value {
    let Some(operations) = operations else { return value };
    for operation in operations.as_array().expect("mutate is a list") {
        let path = field(operation, "path").as_array().expect("path is a list");
        let (last, parents) = path.split_last().expect("non-empty path");
        let mut node = &mut value;
        for key in parents {
            node = child_mut(node, key);
        }
        match (text(operation, "op"), node, last) {
            ("set", Value::Object(object), Value::Str(name)) => object.insert(name.clone(), field(operation, "value").clone()),
            ("set", Value::Array(items), Value::Int(index)) => {
                let index = usize::try_from(index.to_u64().expect("index")).expect("index");
                *items.get_mut(index).expect("index") = field(operation, "value").clone();
            }
            ("delete", Value::Object(object), Value::Str(name)) => {
                object.remove(name).expect("deleted key exists");
            }
            ("delete", Value::Array(items), Value::Int(index)) => {
                let index = usize::try_from(index.to_u64().expect("index")).expect("index");
                assert!(index < items.len(), "deleted index exists");
                items.remove(index);
            }
            (op, _, _) => panic!("unsupported mutation {op}"),
        }
    }
    value
}

/// The bytes path reaches the same verdict as `check_frame` whenever the frame has a canonical encoding within 16 KiB.
pub fn assert_bytes_path_agrees(frame_value: &Value, schema: &Schema, context: &str) {
    let by_value = frame::check_frame(frame_value, schema);
    let Ok(encoded) = json::canonical(frame_value) else {
        assert!(by_value.is_err(), "{context}: a frame without a canonical encoding passed check_frame");
        return;
    };
    let by_bytes = frame::decode_frame(Datagram::Bytes(&encoded), schema).map(|_| ());
    if encoded.len() > frame::MAX_FRAME_BYTES {
        assert_eq!(by_bytes, Err(FrameError::F02), "{context}");
        assert!(by_value.is_err(), "{context}");
    } else {
        assert_eq!(by_bytes, by_value, "{context}: bytes and value paths disagree");
    }
}

fn opt_text(event: &Value, key: &str) -> Option<String> {
    match field(event, key) {
        Value::Null => None,
        other => Some(other.as_str().unwrap_or_else(|| panic!("{key} is text or null")).to_string()),
    }
}

/// Replays one event list on a fresh gate.
pub fn replay(config_value: &Value, events: &[Value], mode: Mode, context: &str) -> Replay {
    let config = Config::from_value(config_value).unwrap_or_else(|error| panic!("{context}: config refused: {error:?}"));
    let mut gate = Gate::new(config).expect("gate");
    let schema = i05_protocol::i05_v3_schema().expect("schema");
    let mut replay = Replay { outputs: Vec::new(), snapshot: Value::Null, frames: 0, value_fallbacks: 0 };
    for (index, event) in events.iter().enumerate() {
        let context = format!("{context} event {index}");
        let conn = || text(event, "conn").to_string();
        let typed = match text(event, "type") {
            "FRAME" => {
                let mut envelope = Object::new();
                envelope.insert(JStr::new("schemaVersion"), Value::str(FRAME_VERSION));
                envelope.insert(JStr::new("generation"), field(config_value, "generation").clone());
                envelope.insert(JStr::new("challenge"), field(config_value, "brokerChallenge").clone());
                envelope.insert(JStr::new("sequence"), Value::int(gate.next_sequence()));
                envelope.insert(JStr::new("previousDigest"), Value::str(gate.last_digest()));
                envelope.insert(JStr::new("direction"), Value::str("BROKER_TO_GATE"));
                envelope.insert(JStr::new("operation"), field(event, "operation").clone());
                envelope.insert(JStr::new("payload"), field(event, "payload").clone());
                let built = apply_mutations(Value::Object(envelope), event.get("mutate"));
                assert_bytes_path_agrees(&built, &schema, &context);
                replay.frames += 1;
                Event::Frame(match mode {
                    Mode::Value => FrameInput::Value(built),
                    Mode::Bytes => match json::canonical(&built) {
                        Ok(raw) => FrameInput::Bytes(raw),
                        Err(_) => {
                            replay.value_fallbacks += 1;
                            FrameInput::Value(built)
                        }
                    },
                })
            }
            "BACKLOG" => Event::Backlog { conn: conn() },
            "ACCEPT" => Event::Accept { conn: conn() },
            "REQUEST" => Event::Request {
                conn: conn(),
                certificate_digest: text(event, "certificateDigest").to_string(),
                head: text(event, "head").to_string(),
                body_digest: opt_text(event, "bodyDigest"),
            },
            "UPSTREAM_RESPONSE" => Event::UpstreamResponse {
                conn: conn(),
                response: UpstreamResponse {
                    http_status: field(event, "httpStatus").as_int().and_then(|status| status.to_i64()).expect("status"),
                    body_digest: text(event, "bodyDigest").to_string(),
                    uid: opt_text(event, "uid"),
                    resource_version: opt_text(event, "resourceVersion"),
                },
            },
            "UPSTREAM_LOST" => Event::UpstreamLost { conn: conn() },
            "UPSTREAM_TIMEOUT" => Event::UpstreamTimeout { conn: conn() },
            // `torn` counts only when it is exactly true (the model's `event.get("torn", False) is True`).
            "STORAGE_FAIL_NEXT" => Event::StorageFailNext { torn: matches!(event.get("torn"), Some(Value::Bool(true))) },
            "MARKER_FAIL_NEXT" => Event::MarkerFailNext,
            "STORAGE_FAIL_AFTER" => Event::StorageFailAfter {
                after: field(event, "after").as_int().and_then(|after| after.to_u64()).expect("after"),
            },
            "DRAIN_REQUEST" => Event::DrainRequest,
            "EXPIRE" => Event::Expire,
            "CHANNEL_LOST" => Event::ChannelLost,
            "SECOND_CHANNEL" => Event::SecondChannel,
            "PEER_CHANGED" => Event::PeerChanged,
            "GATE_RESTART" => Event::GateRestart,
            other => panic!("{context}: unknown event type {other}"),
        };
        let output = gate.handle(typed).unwrap_or_else(|error| panic!("{context}: {error:?}"));
        replay.outputs.push(output.to_doc().to_value());
    }
    replay.snapshot = gate.snapshot().to_value();
    replay
}

/// Compares a replay with a row's expected outputs and final snapshot; returns the first difference.
pub fn compare(replay: &Replay, row: &Value) -> Result<(), String> {
    let expected = rows(row, "outputs");
    if expected.len() != replay.outputs.len() {
        return Err(format!("{} outputs, expected {}", replay.outputs.len(), expected.len()));
    }
    for (index, (got, want)) in replay.outputs.iter().zip(expected).enumerate() {
        if !json::json_eq(got, want) {
            return Err(format!("output {index}: got {} expected {}", show(got), show(want)));
        }
    }
    let want = field(row, "final");
    if !json::json_eq(&replay.snapshot, want) {
        return Err(format!("final: got {} expected {}", show(&replay.snapshot), show(want)));
    }
    Ok(())
}
