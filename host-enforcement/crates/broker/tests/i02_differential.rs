//! HE-005B condition 1 (Q-HE5B-3 (a), MON-HE005B-PLAN, MON-R10-KIT (a)): the differential test of `i02.rs`'s decode.
//! `i02::decode_datagram`, run with the limit 16,384, against i05-protocol's `decode_frame(Datagram::Bytes(raw),
//! schema)` with the same schema: they give the same `Ok` value (equal canonical bytes) or the same `FrameError`, on
//!
//! - every frame of `contracts/i05-v3/vectors.json` (its 34 frame rows, its 14 byte rows and the frames of its 120
//!   transcripts), `contracts/i05-v3-supplement/vectors.json` and `contracts/i05-v4/vectors.json`, positive and
//!   negative, with `i05_v3_schema()`. The transcripts hold events and response payloads, not frame bytes, so each
//!   FRAME event becomes the broker frame and each response the gate frame that effect-gate's replay support builds:
//!   the envelope with the config's generation and broker challenge (v3's when a config names none), the running
//!   sequence and chain, then the event's `mutate` operations. A byte row's bytearray and str inputs, which
//!   `decode_frame` refuses F07 by type, are compared on their bytes: the I02 decode takes bytes only;
//! - every message of `contracts/broker-handoff-v1/vectors.json` (each positive's binding, DISPATCH and frames), with
//!   the I02 schema;
//! - one case of each named form, built from a vector frame of each contract: oversize, truncated, trailing byte, not
//!   UTF-8, duplicate key, float, control character, depth 17, schema miss;
//! - the digest-mismatch form. `decode_frame` does not check the chain (effect-gate's `gate.rs` does), so the reference
//!   is `decode_frame` followed by this test's own check: `previousDigest` equal to `sha256::prefixed` over the
//!   previous frame's canonical bytes, as `check_frame_encoded` returns them. For each I02 vector transcript and each of its
//!   frames, one changed `previousDigest`: the I02 transcript refuses at exactly the frame where the reference refuses.
//!
//! At I02's own limits (O21), one case each: a datagram of 65,536 bytes passes the size step and one of 65,537 bytes
//! is refused F02; a DISPATCH and a RESOURCE_ACTION of 16,385 bytes are refused; and for an otherwise-valid frame of
//! 16,385 to 65,536 bytes, `decode_frame`'s only refusal is F02, the one difference allowed.

use i05_protocol::frame::check_frame_encoded;
use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::schema::Schema;
use i05_protocol::{base64, decode_frame, i05_v3_schema, sha256, Datagram, FrameError, MAX_FRAME_BYTES};
use planeon_broker::i02::{
    check_control_size, check_dispatch, decode, decode_datagram, Breach, ConfiguredDigests, Kind, Schemas, Transcript,
    MAX_DATAGRAM_BYTES, ZERO_DIGEST,
};

const I05_V3: &str = include_str!("../../../contracts/i05-v3/vectors.json");
const I05_V3_SUPPLEMENT: &str = include_str!("../../../contracts/i05-v3-supplement/vectors.json");
const I05_V4: &str = include_str!("../../../contracts/i05-v4/vectors.json");
const BROKER_HANDOFF: &str = include_str!("../../../contracts/broker-handoff-v1/vectors.json");

const I05_FRAME_VERSION: &str = "planeon.internal.effect-gate-frame/v3";

/// The named forms, each with the refusal both decoders give under the limit 16,384.
const FORMS: [(&str, FrameError); 9] = [
    ("oversize", FrameError::F02),
    ("truncated", FrameError::F06),
    ("trailing byte", FrameError::F06),
    ("not UTF-8", FrameError::F06),
    ("duplicate key", FrameError::F05),
    ("float", FrameError::F03),
    ("control character", FrameError::F04),
    ("depth 17", FrameError::F01),
    ("schema miss", FrameError::F00),
];

/// The form `decode_frame` alone cannot show, with its reference check.
const DIGEST_MISMATCH: &str = "digest mismatch";

// ------------------------------------------------------------------------------------------------ helpers

fn load(text: &str) -> Value {
    json::parse(text).expect("a vector file parses")
}

fn member<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or_else(|| panic!("member {key}"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    member(value, key).as_str().unwrap_or_else(|| panic!("text {key}"))
}

fn rows<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value.get(key).and_then(Value::as_array).unwrap_or(&[])
}

fn canonical(value: &Value) -> Vec<u8> {
    json::canonical(value).expect("a canonical encoding")
}

fn i02_schemas() -> Schemas {
    Schemas::embedded().expect("the embedded channel schema loads")
}

/// `value` with the member at `path` set to `member`.
fn with(value: &Value, path: &[&str], member: Value) -> Value {
    let mut copy = value.clone();
    let (last, parents) = path.split_last().expect("a member path");
    let mut node = &mut copy;
    for key in parents {
        let current = node;
        node = match current {
            Value::Object(object) => object.get_key_mut(&JStr::new(key)).expect("a parent member"),
            _ => panic!("{key}: not an object"),
        };
    }
    match node {
        Value::Object(object) => object.insert(JStr::new(last), member),
        _ => panic!("{last}: not an object"),
    }
    copy
}

fn nested(levels: usize) -> Value {
    let mut value = Value::Array(Vec::new());
    for _ in 1..levels {
        value = Value::Array(vec![value]);
    }
    value
}

/// `frame` with a `padding` member that makes its canonical encoding exactly `length` bytes.
fn padded(frame: &Value, length: usize) -> Value {
    let base = canonical(&with(frame, &["padding"], Value::str(""))).len();
    let fill = length.checked_sub(base).expect("room to pad");
    let padded = with(frame, &["padding"], Value::str(&"p".repeat(fill)));
    assert_eq!(canonical(&padded).len(), length);
    padded
}

/// The two decoders on the same bytes and schema: the same canonical value or the same refusal.
fn agree(raw: &[u8], schema: &Schema, context: &str) -> Result<Vec<u8>, FrameError> {
    let ours = decode_datagram(raw, MAX_FRAME_BYTES, schema).map(|value| canonical(&value));
    let reference = decode_frame(Datagram::Bytes(raw), schema).map(|value| canonical(&value));
    assert_eq!(ours, reference, "{context}: i02's decode and decode_frame disagree");
    ours
}

/// effect-gate's replay support's `apply_mutations` (`set` only, the one operation the vectors use).
fn mutate(mut value: Value, operations: Option<&Value>) -> Value {
    let Some(operations) = operations else { return value };
    for operation in operations.as_array().expect("mutate is a list") {
        assert_eq!(text(operation, "op"), "set", "the vectors' one mutation");
        let path = member(operation, "path").as_array().expect("a path");
        let (last, parents) = path.split_last().expect("a non-empty path");
        let mut node = &mut value;
        for key in parents {
            let current = node;
            node = child(current, key);
        }
        match (node, last) {
            (Value::Object(object), Value::Str(name)) => {
                object.insert(name.clone(), member(operation, "value").clone());
            }
            (Value::Array(items), Value::Int(index)) => {
                let index = usize::try_from(index.to_u64().expect("an index")).expect("an index");
                *items.get_mut(index).expect("an item") = member(operation, "value").clone();
            }
            _ => panic!("an unsupported mutation"),
        }
    }
    value
}

fn child<'a>(node: &'a mut Value, key: &Value) -> &'a mut Value {
    match (node, key) {
        (Value::Object(object), Value::Str(name)) => object.get_key_mut(name).expect("a member"),
        (Value::Array(items), Value::Int(index)) => {
            let index = usize::try_from(index.to_u64().expect("an index")).expect("an index");
            items.get_mut(index).expect("an item")
        }
        _ => panic!("a path through a scalar"),
    }
}

fn i05_frame(generation: &Value, challenge: &Value, sequence: i64, previous: &str, direction: &str, operation: &Value,
             payload: &Value) -> Value {
    let mut frame = Object::new();
    frame.insert(JStr::new("schemaVersion"), Value::str(I05_FRAME_VERSION));
    frame.insert(JStr::new("generation"), generation.clone());
    frame.insert(JStr::new("challenge"), challenge.clone());
    frame.insert(JStr::new("sequence"), Value::int(sequence));
    frame.insert(JStr::new("previousDigest"), Value::str(previous));
    frame.insert(JStr::new("direction"), Value::str(direction));
    frame.insert(JStr::new("operation"), operation.clone());
    frame.insert(JStr::new("payload"), payload.clone());
    Value::Object(frame)
}

/// Every frame of a vector file's transcripts, compared; the number compared.
fn transcript_frames(document: &Value, schema: &Schema, file: &str) -> usize {
    let fallback = load(I05_V3);
    let active = member(member(&fallback, "configs"), "ACTIVE");
    let configs = member(document, "configs");
    let mut compared = 0;
    for key in ["transcripts", "orderTranscripts"] {
        for transcript in rows(document, key) {
            let config = member(configs, text(transcript, "config"));
            let generation = config.get("generation").unwrap_or_else(|| member(active, "generation"));
            let challenge = config.get("brokerChallenge").unwrap_or_else(|| member(active, "brokerChallenge"));
            let id = text(transcript, "id");
            let (mut sequence, mut last) = (1i64, ZERO_DIGEST.to_string());
            let events = rows(transcript, "events");
            let outputs = rows(transcript, "outputs");
            assert_eq!(events.len(), outputs.len(), "{file} {id}: one output per event");
            for (index, (event, output)) in events.iter().zip(outputs).enumerate() {
                if event.get("type").and_then(Value::as_str) != Some("FRAME") {
                    assert!(output.get("response").is_none(), "{file} {id}: a response answers a FRAME event");
                    continue;
                }
                let operation = member(event, "operation");
                let request = i05_frame(generation, challenge, sequence, &last, "BROKER_TO_GATE", operation,
                                        member(event, "payload"));
                let request = canonical(&mutate(request, event.get("mutate")));
                let _ = agree(&request, schema, &format!("{file} {id} event {index} (request)"));
                compared += 1;
                last = sha256::prefixed(&request);
                sequence += 1;
                if let Some(response) = output.get("response") {
                    let answer =
                        i05_frame(generation, challenge, sequence, &last, "GATE_TO_BROKER", operation, response);
                    let answer = canonical(&answer);
                    let _ = agree(&answer, schema, &format!("{file} {id} event {index} (response)"));
                    compared += 1;
                    last = sha256::prefixed(&answer);
                    sequence += 1;
                }
            }
        }
    }
    compared
}

fn configured(positive: &Value) -> ConfiguredDigests {
    let binding = member(positive, "binding");
    ConfiguredDigests {
        broker_manifest: text(binding, "brokerManifestDigest").to_string(),
        broker_executable: text(binding, "brokerExecutableDigest").to_string(),
        worker_manifest: text(binding, "workerManifestDigest").to_string(),
        worker_artifact: text(binding, "workerArtifactDigest").to_string(),
    }
}

fn broker_positives() -> Vec<Value> {
    rows(&load(BROKER_HANDOFF), "positive").to_vec()
}

/// The bytes of one named form, built from `frame`.
fn form(name: &str, frame: &Value) -> Vec<u8> {
    let raw = canonical(frame);
    match name {
        "oversize" => canonical(&padded(frame, MAX_FRAME_BYTES + 1)),
        "truncated" => raw[..raw.len() - 1].to_vec(),
        "trailing byte" => {
            let mut bytes = raw;
            bytes.push(b'x');
            bytes
        }
        "not UTF-8" => {
            let mut bytes = raw;
            let at = bytes.iter().position(|byte| *byte == b'"').expect("a string") + 1;
            bytes[at] = 0xFF;
            bytes
        }
        "duplicate key" => {
            let mut bytes = b"{\"sequence\":0,".to_vec();
            bytes.extend_from_slice(&raw[1..]);
            bytes
        }
        "float" => canonical(&with(frame, &["sequence"], Value::Float(1.0))),
        "control character" => canonical(&with(frame, &["schemaVersion"], Value::str("control\u{1}character"))),
        "depth 17" => canonical(&with(frame, &["payload"], nested(16))),
        "schema miss" => canonical(&with(frame, &["schemaVersion"], Value::str("schema-miss"))),
        other => panic!("form {other}"),
    }
}

// ------------------------------------------------------------------------------------------------ every frame

#[test]
fn every_i05_vector_frame_decodes_alike() {
    assert_eq!(MAX_FRAME_BYTES, 16_384);
    let schema = i05_v3_schema().expect("the I05 v3 schema");
    let v3 = load(I05_V3);
    let frame_rows = rows(&v3, "frames");
    assert_eq!(frame_rows.len(), 34);
    for row in frame_rows {
        let raw = canonical(member(row, "frame"));
        let _ = agree(&raw, &schema, &format!("i05-v3 frame {}", text(row, "id")));
    }
    let byte_rows = rows(&v3, "byteFrames");
    assert_eq!(byte_rows.len(), 14);
    for row in byte_rows {
        let raw = base64::decode_strict(text(row, "base64").as_bytes()).expect("a byte row's base64");
        let _ = agree(&raw, &schema, &format!("i05-v3 byte row {}", text(row, "id")));
    }
    assert_eq!(transcript_frames(&v3, &schema, "i05-v3"), 988);
    assert_eq!(transcript_frames(&load(I05_V3_SUPPLEMENT), &schema, "i05-v3-supplement"), 50);
    assert_eq!(transcript_frames(&load(I05_V4), &schema, "i05-v4"), 180);
}

#[test]
fn every_broker_handoff_vector_message_decodes_alike() {
    let schemas = i02_schemas();
    let mut compared = 0;
    for positive in broker_positives() {
        for message in [member(&positive, "binding"), member(&positive, "request")] {
            let decoded = agree(&canonical(message), schemas.channel(), "broker-handoff message");
            assert_eq!(decoded, Ok(canonical(message)), "a positive message passes");
            compared += 1;
        }
        for frame in rows(&positive, "frames") {
            let decoded = agree(&canonical(frame), schemas.channel(), "broker-handoff frame");
            assert_eq!(decoded, Ok(canonical(frame)), "a positive frame passes");
            compared += 1;
        }
    }
    assert_eq!(compared, 22);
}

// ------------------------------------------------------------------------------------------------ the named forms

#[test]
fn each_named_form_is_refused_alike() {
    let i02 = i02_schemas();
    let i05 = i05_v3_schema().expect("the I05 v3 schema");
    let v3 = load(I05_V3);
    let positive_row = rows(&v3, "frames").iter().find(|row| member(row, "expect").is_null());
    let i05_frame = member(positive_row.expect("a positive frame row"), "frame").clone();
    let i02_frame = rows(&broker_positives()[0], "frames")[0].clone();
    for (base, schema, contract) in [(&i02_frame, i02.channel(), "broker-handoff-v1"), (&i05_frame, &i05, "i05-v3")] {
        assert!(agree(&canonical(base), schema, contract).is_ok(), "{contract}: the base frame passes");
        for (name, code) in FORMS {
            let bytes = form(name, base);
            assert_eq!(agree(&bytes, schema, &format!("{contract} {name}")), Err(code), "{contract} {name}");
        }
    }
}

#[test]
fn a_digest_mismatch_is_refused_where_the_reference_refuses() {
    let schemas = i02_schemas();
    let mut cases = 0;
    for positive in broker_positives() {
        let frames = rows(&positive, "frames").to_vec();
        let request = canonical(member(&positive, "request"));
        let binding = canonical(member(&positive, "binding"));
        let dispatch = check_dispatch(&request, &binding, &configured(&positive), &schemas).expect("the DISPATCH");
        for changed in 0..frames.len() {
            let mut datagrams: Vec<Vec<u8>> = frames.iter().map(canonical).collect();
            let other = format!("sha256:{}", "1".repeat(64));
            datagrams[changed] = canonical(&with(&frames[changed], &["previousDigest"], Value::str(&other)));
            // The reference: decode_frame, then the chain over check_frame_encoded's canonical bytes.
            let mut reference = None;
            let mut previous = ZERO_DIGEST.to_string();
            for (index, raw) in datagrams.iter().enumerate() {
                let value = decode_frame(Datagram::Bytes(raw), schemas.channel()).expect("each frame decodes");
                if text(&value, "previousDigest") != previous {
                    reference = Some(index);
                    break;
                }
                previous = sha256::prefixed(&check_frame_encoded(&value, schemas.channel()).expect("encoded"));
            }
            // The I02 transcript.
            let mut transcript = Transcript::new(&dispatch, text(&frames[0], "executionId")).expect("a transcript");
            let mut refused = None;
            for (index, (raw, frame)) in datagrams.iter().zip(&frames).enumerate() {
                let from = Kind::from_wire(text(frame, "kind")).expect("a kind").peer();
                if let Err(breach) = transcript.accept(raw, from, &schemas) {
                    assert_eq!(breach, Breach::Chain, "{DIGEST_MISMATCH} at frame {}", index + 1);
                    refused = Some(index);
                    break;
                }
            }
            assert_eq!(reference, Some(changed), "{DIGEST_MISMATCH}: the reference refuses the changed frame");
            assert_eq!(refused, reference, "{DIGEST_MISMATCH}: the I02 transcript refuses where the reference does");
            cases += 1;
        }
    }
    assert_eq!(cases, 18);
}

// ------------------------------------------------------------------------------------------------ I02's own limits

#[test]
fn the_datagram_limit_is_65536_bytes() {
    let schemas = i02_schemas();
    let frame = rows(&broker_positives()[0], "frames")[0].clone();
    // No schema-valid I02 message reaches 64 KiB (the largest, a RECEIPT_CHUNK of 32,768 base64 characters, is about
    // 33 KB), so at 65,536 bytes the size step passes and the schema step refuses.
    let at_limit = canonical(&padded(&frame, MAX_DATAGRAM_BYTES));
    let over = canonical(&padded(&frame, MAX_DATAGRAM_BYTES + 1));
    assert_eq!(decode(&at_limit, &schemas).err(), Some(FrameError::F00));
    assert_eq!(decode(&over, &schemas).err(), Some(FrameError::F02));
    // Under a schema that admits anything, 65,536 bytes are admitted.
    let anything = Schema::from_json(b"true").expect("the schema true");
    assert!(decode_datagram(&at_limit, MAX_DATAGRAM_BYTES, &anything).is_ok());
    assert_eq!(decode_datagram(&over, MAX_DATAGRAM_BYTES, &anything).err(), Some(FrameError::F02));
    // The largest schema-valid frame.
    let largest = with(&rows(&broker_positives()[0], "frames")[1], &["payload", "dataBase64"],
                       Value::str(&"A".repeat(32_768)));
    let largest = canonical(&largest);
    assert!(largest.len() < MAX_DATAGRAM_BYTES);
    assert!(decode(&largest, &schemas).is_ok());
}

#[test]
fn a_dispatch_or_resource_action_of_16385_bytes_is_refused() {
    let schemas = i02_schemas();
    let positive = broker_positives().into_iter().nth(1).expect("the second positive");
    let dispatch = member(&positive, "request").clone();
    let resource_action = rows(&positive, "frames")[1].clone();
    assert_eq!(text(&resource_action, "kind"), "RESOURCE_ACTION");
    for value in [&dispatch, &resource_action] {
        // Both are closed and bounded (about 700 and 1,000 bytes at most), so a 16,385-byte one is outside the schema
        // and the schema step refuses it before the kind limit; the kind limit itself refuses F02.
        let big = canonical(&padded(value, MAX_FRAME_BYTES + 1));
        assert_eq!(decode(&big, &schemas).err(), Some(FrameError::F00));
        assert_eq!(check_control_size(value, MAX_FRAME_BYTES + 1), Err(FrameError::F02));
        assert_eq!(check_control_size(value, MAX_FRAME_BYTES), Ok(()));
    }
}

#[test]
fn the_one_allowed_difference_is_decode_frame_refusing_f02() {
    let schemas = i02_schemas();
    let positive = broker_positives().into_iter().nth(1).expect("the second positive");
    let result = rows(&positive, "frames")[2].clone();
    assert_eq!(text(&result, "kind"), "RESOURCE_RESULT");
    let base = canonical(&with(&result, &["payload", "objectBase64"], Value::str(""))).len();
    let exact = with(&result, &["payload", "objectBase64"], Value::str(&"A".repeat(MAX_FRAME_BYTES + 1 - base)));
    let chunk = with(&rows(&positive, "frames")[11], &["payload", "dataBase64"], Value::str(&"A".repeat(32_768)));
    assert_eq!(text(&rows(&positive, "frames")[11], "kind"), "RECEIPT_CHUNK");
    let exact = canonical(&exact);
    let chunk = canonical(&chunk);
    assert_eq!(exact.len(), MAX_FRAME_BYTES + 1);
    for raw in [&exact, &chunk] {
        assert!(raw.len() > MAX_FRAME_BYTES && raw.len() <= MAX_DATAGRAM_BYTES);
        // decode_frame's only refusal is F02: under a 64 KiB limit the same pipeline admits the frame.
        assert_eq!(decode_frame(Datagram::Bytes(raw), schemas.channel()).err(), Some(FrameError::F02));
        assert_eq!(decode_datagram(raw, MAX_FRAME_BYTES, schemas.channel()).err(), Some(FrameError::F02));
        assert!(decode_datagram(raw, MAX_DATAGRAM_BYTES, schemas.channel()).is_ok());
        assert!(decode(raw, &schemas).is_ok());
    }
}

#[test]
fn every_named_form_is_exercised() {
    let names: Vec<&str> = FORMS.iter().map(|(name, _)| *name).collect();
    assert_eq!(names, ["oversize", "truncated", "trailing byte", "not UTF-8", "duplicate key", "float",
                       "control character", "depth 17", "schema miss"]);
    assert_eq!(DIGEST_MISMATCH, "digest mismatch");
}
