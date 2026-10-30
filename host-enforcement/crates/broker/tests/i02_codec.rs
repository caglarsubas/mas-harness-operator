//! HE-005B's I02 tests (the HE-005B plan's items 2 and 6; MON-HE005B-PLAN): the two positive vectors of
//! `contracts/broker-handoff-v1/vectors.json` (DATA_CHECK_ONLY) replayed end to end (the data checks, the DISPATCH and
//! its binding, the chain, the echo, the order, the receipt and cleanup binding); the broker's frames rebuilt byte for
//! byte through the builders; R10's negatives, one failing case per rule (Q-HE5-1 (a): the vectors are positive only);
//! the binding check's differences; the 16 KiB kind limit; and the refusal map. The decode's differential test against
//! i05-protocol's `decode_frame` is `i02_differential.rs`.

use i05_protocol::base64;
use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::sha256;
use i05_protocol::FrameError;
use planeon_broker::i02::{
    answer, check_control_size, check_dispatch, decode, Accepted, BindRefusal, Breach, ConfiguredDigests,
    DispatchError, Failure, Kind, Peer, RefusedReason, Schemas, TerminalStatus, Transcript, Verb, ECHO_FIELDS,
    MAX_CHUNK_BYTES, ZERO_DIGEST,
};

const VECTORS: &str = include_str!("../../../contracts/broker-handoff-v1/vectors.json");

// ------------------------------------------------------------------------------------------------ helpers

fn schemas() -> Schemas {
    Schemas::embedded().expect("the embedded channel schema loads")
}

fn positives() -> Vec<Value> {
    let vectors = json::parse(VECTORS).expect("the vectors parse");
    assert_eq!(vectors.get("evidenceClass").and_then(Value::as_str), Some("DATA_CHECK_ONLY"));
    vectors.get("positive").and_then(Value::as_array).expect("positive vectors").to_vec()
}

fn member<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or_else(|| panic!("member {key}"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    member(value, key).as_str().unwrap_or_else(|| panic!("text {key}"))
}

fn int(value: &Value, key: &str) -> i64 {
    member(value, key).as_int().and_then(|number| number.to_i64()).unwrap_or_else(|| panic!("integer {key}"))
}

fn canonical(value: &Value) -> Vec<u8> {
    json::canonical(value).expect("a canonical encoding")
}

fn frames(positive: &Value) -> Vec<Value> {
    member(positive, "frames").as_array().expect("frames").to_vec()
}

fn object(members: &[(&str, Value)]) -> Value {
    let mut object = Object::new();
    for (key, value) in members {
        object.insert(JStr::new(key), value.clone());
    }
    Value::Object(object)
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

fn digest_of(fill: char) -> String {
    let mut digest = String::from("sha256:");
    digest.extend(std::iter::repeat(fill).take(64));
    digest
}

fn hex_of(fill: char) -> String {
    std::iter::repeat(fill).take(64).collect()
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

fn kind_peer(frame: &Value) -> Peer {
    Kind::from_wire(text(frame, "kind")).expect("a frame kind").peer()
}

fn chunk(index: i64, data: &[u8]) -> Value {
    object(&[("index", Value::int(index)), ("dataBase64", Value::str(&base64::encode(data)))])
}

fn reason(reason: &str) -> Value {
    object(&[("reason", Value::str(reason))])
}

fn action(action_id: i64, manifest: &str) -> Value {
    object(&[("actionId", Value::int(action_id)), ("verb", Value::str("GET")),
        ("manifestDigest", Value::str(manifest))])
}

fn result(action_id: i64) -> Value {
    object(&[("actionId", Value::int(action_id)), ("outcome", Value::str("ABSENT")), ("objectBase64", Value::Null)])
}

fn cleanup(digest: &str) -> Value {
    object(&[("cleanupDigest", Value::str(digest)), ("state", Value::str("CLEAN")),
        ("remainingResources", Value::Array(Vec::new()))])
}

/// One positive vector's transcript, fed frame by frame; inserted frames are chained to the last accepted one.
struct Run {
    schemas: Schemas,
    transcript: Transcript,
    template: Value,
    last: Vec<u8>,
    next: i64,
}

impl Run {
    fn new(positive: &Value) -> Run {
        let schemas = schemas();
        let request = canonical(member(positive, "request"));
        let binding = canonical(member(positive, "binding"));
        let dispatch =
            check_dispatch(&request, &binding, &configured(positive), &schemas).expect("the DISPATCH passes");
        let first = frames(positive).into_iter().next().expect("a first frame");
        let transcript = Transcript::new(&dispatch, text(&first, "executionId")).expect("a transcript");
        Run { schemas, transcript, template: first, last: Vec::new(), next: 1 }
    }

    fn feed_from(&mut self, frame: &Value, from: Peer) -> Result<Accepted, Breach> {
        let raw = canonical(frame);
        let accepted = self.transcript.accept(&raw, from, &self.schemas);
        if accepted.is_ok() {
            self.last = raw;
            self.next += 1;
        }
        accepted
    }

    fn feed(&mut self, frame: &Value) -> Result<Accepted, Breach> {
        self.feed_from(frame, kind_peer(frame))
    }

    fn feed_raw(&mut self, raw: &[u8], from: Peer) -> Result<Accepted, Breach> {
        self.transcript.accept(raw, from, &self.schemas)
    }

    fn feed_all(&mut self, frames: &[Value]) {
        for (index, frame) in frames.iter().enumerate() {
            if let Err(breach) = self.feed(frame) {
                panic!("vector frame {} refused: {breach:?}", index + 1);
            }
        }
    }

    /// The next frame of `kind` with `payload`, chained to the last accepted frame, otherwise as the vector's first.
    fn next_frame(&self, kind: &str, payload: Value) -> Value {
        let previous = if self.last.is_empty() { ZERO_DIGEST.to_string() } else { sha256::prefixed(&self.last) };
        let frame = with(&self.template, &["sequence"], Value::int(self.next));
        let frame = with(&frame, &["previousDigest"], Value::str(&previous));
        let frame = with(&frame, &["kind"], Value::str(kind));
        with(&frame, &["payload"], payload)
    }
}

/// positive[0]: STARTED, RECEIPT_CHUNK, CLEANUP_RECORDED, TERMINAL. positive[1]: STARTED, five RESOURCE_ACTION and
/// RESOURCE_RESULT pairs, RECEIPT_CHUNK, CLEANUP_RECORDED, TERMINAL.
fn vector(index: usize) -> Value {
    positives().into_iter().nth(index).expect("a positive vector")
}

// ------------------------------------------------------------------------------------------------ the vectors

#[test]
fn the_two_positive_vectors_replay_end_to_end() {
    let positives = positives();
    assert_eq!(positives.len(), 2);
    let mut lengths = Vec::new();
    for positive in &positives {
        let binding = member(positive, "binding");
        let request = member(positive, "request");
        // The data checks: the binding's and its two inputs' digests are the SHA-256 of their canonical encodings.
        assert_eq!(text(binding, "profileDigest"), sha256::prefixed(&canonical(member(positive, "profile"))));
        assert_eq!(text(binding, "observationBindingDigest"),
                   sha256::prefixed(&canonical(member(positive, "observationBinding"))));
        assert_eq!(text(request, "bindingDigest"), sha256::prefixed(&canonical(binding)));
        let mut run = Run::new(positive);
        let frames = frames(positive);
        for (index, frame) in frames.iter().enumerate() {
            let accepted = run.feed(frame).unwrap_or_else(|breach| panic!("frame {}: {breach:?}", index + 1));
            assert_eq!(accepted.sequence(), index as i64 + 1);
            assert_eq!(accepted.kind().wire(), text(frame, "kind"));
        }
        assert!(run.transcript.is_over(), "TERMINAL ends the transcript");
        lengths.push(frames.len());
    }
    assert_eq!(lengths, vec![4, 14]);
}

#[test]
fn the_dispatch_selects_only_the_bound_case() {
    let schemas = schemas();
    for positive in positives() {
        let request = canonical(member(&positive, "request"));
        let binding_value = member(&positive, "binding");
        let dispatch = check_dispatch(&request, &canonical(binding_value), &configured(&positive), &schemas)
            .expect("the DISPATCH passes");
        for name in ECHO_FIELDS {
            assert_eq!(dispatch.echo().get(name), Some(text(member(&positive, "request"), name)), "{name}");
        }
        let case = text(member(&positive, "request"), "caseId");
        let set: Vec<&str> = member(member(binding_value, "caseResourceDigests"), case).as_array().expect("a set")
            .iter().map(|digest| digest.as_str().expect("a digest")).collect();
        let held: Vec<&str> = dispatch.case_resources().iter().map(String::as_str).collect();
        let mut expected = set.clone();
        expected.sort_unstable();
        assert_eq!(held, expected, "the bound case's resource set");
    }
}

#[test]
fn the_builders_rebuild_the_broker_frames_byte_for_byte() {
    for positive in positives() {
        let mut run = Run::new(&positive);
        let schemas = schemas();
        for frame in frames(&positive) {
            let raw = canonical(&frame);
            let payload = member(&frame, "payload");
            let built = match text(&frame, "kind") {
                "STARTED" => {
                    run.transcript.started(&schemas, int(payload, "workerPid"), int(payload, "workerStartTicks"))
                }
                "RESOURCE_ACTION" => {
                    let verb = match text(payload, "verb") {
                        "CREATE" => Verb::Create,
                        "GET" => Verb::Get,
                        "DELETE" => Verb::Delete,
                        other => panic!("verb {other}"),
                    };
                    let manifest = text(payload, "manifestDigest");
                    run.transcript.resource_action(&schemas, int(payload, "actionId"), verb, manifest)
                }
                "RECEIPT_CHUNK" => {
                    let data = base64::decode_strict(text(payload, "dataBase64").as_bytes()).expect("base64");
                    run.transcript.receipt_chunk(&schemas, &data)
                }
                "TERMINAL" => {
                    let status = match text(payload, "status") {
                        "COMPLETED" => TerminalStatus::Completed,
                        "FAILED" => TerminalStatus::Failed,
                        "UNAVAILABLE" => TerminalStatus::Unavailable,
                        other => panic!("status {other}"),
                    };
                    run.transcript.terminal(&schemas, status)
                }
                _ => {
                    run.feed_raw(&raw, Peer::Server).expect("a server frame");
                    continue;
                }
            };
            assert_eq!(built.expect("a built frame"), raw, "{} rebuilt byte for byte", text(&frame, "kind"));
        }
        assert!(run.transcript.is_over());
    }
}

// ------------------------------------------------------------------------------------------------ decode negatives

/// The first vector frame's bytes, changed as text.
fn first_frame_text() -> String {
    String::from_utf8(canonical(&frames(&vector(0))[0])).expect("UTF-8")
}

#[test]
fn a_datagram_over_64_kib_is_refused() {
    let mut run = Run::new(&vector(0));
    assert_eq!(run.feed_raw(&vec![b' '; 65_537], Peer::Broker).unwrap_err(), Breach::Frame(FrameError::F02));
    let schemas = schemas();
    let positive = vector(0);
    let binding = canonical(member(&positive, "binding"));
    assert_eq!(check_dispatch(&vec![b' '; 65_537], &binding, &configured(&positive), &schemas).unwrap_err(),
               DispatchError::Frame(FrameError::F02));
}

#[test]
fn the_decode_refusals_reach_the_transcript() {
    let raw = first_frame_text();
    let mut depth = Value::Array(Vec::new());
    for _ in 1..16 {
        depth = Value::Array(vec![depth]);
    }
    let deep = String::from_utf8(canonical(&with(&frames(&vector(0))[0], &["payload"], depth))).expect("UTF-8");
    let not_kind = String::from_utf8(canonical(&with(&frames(&vector(0))[0], &["kind"], Value::str("NOPE"))))
        .expect("UTF-8");
    let cases: Vec<(&str, Vec<u8>, FrameError)> = vec![
        ("non-canonical bytes", raw.replacen('{', "{ ", 1).into_bytes(), FrameError::F06),
        ("duplicate key", raw.replacen('{', "{\"bindingDigest\":\"x\",", 1).into_bytes(), FrameError::F05),
        ("float", raw.replacen("\"sequence\":1}", "\"sequence\":1.0}", 1).into_bytes(), FrameError::F03),
        ("control character", raw.replacen("unit-nonce", "unit\\u0001nonce", 1).into_bytes(), FrameError::F04),
        ("depth 17", deep.into_bytes(), FrameError::F01),
        ("schema miss", not_kind.into_bytes(), FrameError::F00),
    ];
    for (name, bytes, code) in cases {
        assert_ne!(bytes, raw.as_bytes(), "{name}: the case changes the bytes");
        let mut run = Run::new(&vector(0));
        assert_eq!(run.feed_raw(&bytes, Peer::Broker).unwrap_err(), Breach::Frame(code), "{name}");
        assert_eq!(run.feed(&frames(&vector(0))[0]).unwrap_err(), Breach::Ended, "{name}: the breach ends it");
    }
}

#[test]
fn the_kind_limit_is_16_kib_for_dispatch_and_resource_action_only() {
    let positive = vector(1);
    let dispatch = member(&positive, "request").clone();
    let resource_action = frames(&positive)[1].clone();
    assert_eq!(text(&resource_action, "kind"), "RESOURCE_ACTION");
    for value in [&dispatch, &resource_action] {
        assert_eq!(check_control_size(value, 16_384), Ok(()));
        assert_eq!(check_control_size(value, 16_385), Err(FrameError::F02));
    }
    for value in [&frames(&positive)[0], member(&positive, "binding"), &frames(&positive)[2]] {
        assert_eq!(check_control_size(value, 65_536), Ok(()));
    }
}

// ------------------------------------------------------------------------------------------------ transcript negatives

#[test]
fn a_broken_chain_is_refused_at_its_frame() {
    let positive = vector(1);
    let frames = frames(&positive);
    for index in 0..frames.len() {
        let mut run = Run::new(&positive);
        run.feed_all(&frames[..index]);
        let broken = with(&frames[index], &["previousDigest"], Value::str(&digest_of('1')));
        assert_eq!(run.feed(&broken).unwrap_err(), Breach::Chain, "frame {}", index + 1);
        assert_eq!(run.feed(&frames[index]).unwrap_err(), Breach::Ended);
    }
}

#[test]
fn a_skipped_or_repeated_sequence_is_refused() {
    let positive = vector(1);
    let frames = frames(&positive);
    for sequence in [1, 3, 2048] {
        let mut run = Run::new(&positive);
        run.feed_all(&frames[..1]);
        assert_eq!(run.feed(&with(&frames[1], &["sequence"], Value::int(sequence))).unwrap_err(), Breach::Sequence);
    }
}

#[test]
fn the_wrong_direction_is_refused() {
    let positive = vector(1);
    let frames = frames(&positive);
    let mut run = Run::new(&positive);
    assert_eq!(run.feed_from(&frames[0], Peer::Server).unwrap_err(), Breach::Direction);
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..2]);
    assert_eq!(run.feed_from(&frames[2], Peer::Broker).unwrap_err(), Breach::Direction);
}

#[test]
fn a_changed_echo_field_or_execution_id_is_refused() {
    let positive = vector(1);
    let frames = frames(&positive);
    let changed = [("bindingDigest", Value::str(&digest_of('1'))), ("reservationDigest", Value::str(&digest_of('1'))),
        ("runNonce", Value::str("other-nonce")), ("caseId", Value::str("LINUX_TARGET_BUILD")),
        ("requestDigest", Value::str(&digest_of('1'))), ("observationDigest", Value::str(&digest_of('1'))),
        ("generation", Value::str(&hex_of('d'))), ("challenge", Value::str(&hex_of('e')))];
    assert_eq!(changed.iter().map(|(name, _)| *name).collect::<Vec<_>>(), ECHO_FIELDS.to_vec());
    for (name, value) in changed {
        assert_ne!(Some(text(&frames[1], name)), value.as_str(), "{name} changes");
        let mut run = Run::new(&positive);
        run.feed_all(&frames[..1]);
        assert_eq!(run.feed(&with(&frames[1], &[name], value)).unwrap_err(), Breach::Echo, "{name}");
    }
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    assert_eq!(run.feed(&with(&frames[1], &["executionId"], Value::str(&hex_of('d')))).unwrap_err(),
               Breach::Execution);
}

#[test]
fn the_first_frame_is_started_or_refused() {
    let positive = vector(0);
    let frames = frames(&positive);
    let mut run = Run::new(&positive);
    let first = run.next_frame("RECEIPT_CHUNK", chunk(0, b"receipt"));
    assert_eq!(run.feed(&first).unwrap_err(), Breach::FirstFrame);
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    let again = run.next_frame("STARTED", member(&frames[0], "payload").clone());
    assert_eq!(run.feed(&again).unwrap_err(), Breach::StartedRepeated);
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    let refused = run.next_frame("REFUSED", reason("UNAVAILABLE"));
    assert_eq!(run.feed(&refused).unwrap_err(), Breach::RefusedNotFirst);
    // A REFUSED first frame ends the transcript.
    let mut run = Run::new(&positive);
    let refused = run.next_frame("REFUSED", reason("CAPACITY_HELD"));
    run.feed(&refused).expect("REFUSED first");
    assert!(run.transcript.is_over());
    let after = run.next_frame("ABORT", reason("DEADLINE"));
    assert_eq!(run.feed(&after).unwrap_err(), Breach::Ended);
}

#[test]
fn an_outstanding_action_blocks_every_other_step() {
    let positive = vector(1);
    let frames = frames(&positive);
    let manifest = text(member(&frames[1], "payload"), "manifestDigest").to_string();
    let after_action = |kind: &str, payload: Value| {
        let mut run = Run::new(&positive);
        run.feed_all(&frames[..2]);
        let next = run.next_frame(kind, payload);
        run.feed(&next).unwrap_err()
    };
    assert_eq!(after_action("RECEIPT_CHUNK", chunk(0, b"receipt")), Breach::ActionOutstanding);
    assert_eq!(after_action("RESOURCE_ACTION", action(2, &manifest)), Breach::ActionOutstanding);
    assert_eq!(after_action("CLEANUP_RECORDED", cleanup(&digest_of('2'))), Breach::ActionOutstanding);
    assert_eq!(after_action("RESOURCE_RESULT", result(2)), Breach::ActionMismatch);
    // A result with no action outstanding.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    let next = run.next_frame("RESOURCE_RESULT", result(1));
    assert_eq!(run.feed(&next).unwrap_err(), Breach::NoActionOutstanding);
    // ABORT may arrive with an action outstanding; the result still answers it.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..2]);
    let abort = run.next_frame("ABORT", reason("REVOKED"));
    run.feed(&abort).expect("ABORT");
    let answered = run.next_frame("RESOURCE_RESULT", result(1));
    run.feed(&answered).expect("the outstanding action's result");
}

#[test]
fn a_resource_action_stays_in_the_bound_case() {
    let positive = vector(1);
    let frames = frames(&positive);
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    let outside = with(&frames[1], &["payload", "manifestDigest"], Value::str(&digest_of('1')));
    assert_eq!(run.feed(&outside).unwrap_err(), Breach::ManifestOutsideCase);
    // Zero-resource mode: positive[0]'s case set is empty, so every RESOURCE_ACTION is refused.
    let empty = vector(0);
    let mut run = Run::new(&empty);
    run.feed_all(&member(&empty, "frames").as_array().expect("frames")[..1]);
    let manifest = text(member(&frames[1], "payload"), "manifestDigest").to_string();
    let next = run.next_frame("RESOURCE_ACTION", action(1, &manifest));
    assert_eq!(run.feed(&next).unwrap_err(), Breach::ManifestOutsideCase);
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    let schemas = schemas();
    assert_eq!(run.transcript.resource_action(&schemas, 1, Verb::Get, &digest_of('1')).unwrap_err(),
               Breach::ManifestOutsideCase);
    // After the server's ABORT, and after CLEANUP_RECORDED, no new action.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    let abort = run.next_frame("ABORT", reason("DEADLINE"));
    run.feed(&abort).expect("ABORT");
    let next = run.next_frame("RESOURCE_ACTION", member(&frames[1], "payload").clone());
    assert_eq!(run.feed(&next).unwrap_err(), Breach::ActionAfterAbort);
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..13]);
    let next = run.next_frame("RESOURCE_ACTION", member(&frames[1], "payload").clone());
    assert_eq!(run.feed(&next).unwrap_err(), Breach::ActionAfterCleanup);
}

#[test]
fn receipt_chunks_are_contiguous_bounded_and_canonical() {
    let positive = vector(0);
    let frames = frames(&positive);
    // A gap.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    assert_eq!(run.feed(&with(&frames[1], &["payload", "index"], Value::int(1))).unwrap_err(), Breach::ChunkIndex);
    // Non-canonical base64: strict, but with non-zero trailing bits.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    let trailing_bits = object(&[("index", Value::int(0)), ("dataBase64", Value::str("QR=="))]);
    let trailing = run.next_frame("RECEIPT_CHUNK", trailing_bits);
    assert_eq!(run.feed(&trailing).unwrap_err(), Breach::ChunkEncoding);
    // 24 KiB decoded passes; one byte more is outside the schema's base64 bound.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    let full = run.next_frame("RECEIPT_CHUNK", chunk(0, &vec![7u8; MAX_CHUNK_BYTES]));
    run.feed(&full).expect("a 24 KiB chunk");
    let over = run.next_frame("RECEIPT_CHUNK", chunk(1, &vec![7u8; MAX_CHUNK_BYTES + 1]));
    assert_eq!(run.feed(&over).unwrap_err(), Breach::Frame(FrameError::F00));
    // The 172nd chunk's index, 171, is outside the schema.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    let late = run.next_frame("RECEIPT_CHUNK", chunk(171, b"receipt"));
    assert_eq!(run.feed(&late).unwrap_err(), Breach::Frame(FrameError::F00));
    // After CLEANUP_RECORDED, no chunk.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..3]);
    let next = run.next_frame("RECEIPT_CHUNK", chunk(1, b"receipt"));
    assert_eq!(run.feed(&next).unwrap_err(), Breach::ChunkAfterCleanup);
}

#[test]
fn one_hundred_seventy_one_chunks_pass_and_more_than_4_mib_is_refused() {
    let positive = vector(0);
    let frames = frames(&positive);
    let schemas = schemas();
    // 171 one-byte chunks, then CLEANUP_RECORDED and TERMINAL binding their 171 bytes.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    for index in 0..171 {
        let next = run.next_frame("RECEIPT_CHUNK", chunk(index, b"r"));
        run.feed(&next).unwrap_or_else(|breach| panic!("chunk {index}: {breach:?}"));
    }
    let recorded = run.next_frame("CLEANUP_RECORDED", cleanup(&digest_of('2')));
    run.feed(&recorded).expect("CLEANUP_RECORDED");
    let terminal = run.transcript.terminal(&schemas, TerminalStatus::Completed).expect("TERMINAL");
    let terminal = decode(&terminal, &schemas).expect("TERMINAL decodes");
    assert_eq!(int(member(&terminal, "payload"), "receiptSize"), 171);
    let mut expected = Vec::new();
    expected.resize(171, b'r');
    assert_eq!(text(member(&terminal, "payload"), "receiptDigest"), sha256::prefixed(&expected));
    // 170 full chunks are 4,177,920 bytes; the 171st full chunk passes 4 MiB.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    let full = vec![9u8; MAX_CHUNK_BYTES];
    for _ in 0..170 {
        run.transcript.receipt_chunk(&schemas, &full).expect("a full chunk");
    }
    assert_eq!(run.transcript.receipt_chunk(&schemas, &full).unwrap_err(), Breach::ReceiptTooLarge);
}

#[test]
fn cleanup_and_terminal_bind_the_receipt() {
    let positive = vector(0);
    let frames = frames(&positive);
    let schemas = schemas();
    // CLEANUP_RECORDED before any chunk, and twice.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    let early = run.next_frame("CLEANUP_RECORDED", member(&frames[2], "payload").clone());
    assert_eq!(run.feed(&early).unwrap_err(), Breach::ChunksIncomplete);
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..3]);
    let again = run.next_frame("CLEANUP_RECORDED", member(&frames[2], "payload").clone());
    assert_eq!(run.feed(&again).unwrap_err(), Breach::CleanupRepeated);
    // TERMINAL before CLEANUP_RECORDED, as received and through the builder.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..2]);
    let early = run.next_frame("TERMINAL", member(&frames[3], "payload").clone());
    assert_eq!(run.feed(&early).unwrap_err(), Breach::TerminalBeforeCleanup);
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..2]);
    let early = run.transcript.terminal(&schemas, TerminalStatus::Completed);
    assert_eq!(early.unwrap_err(), Breach::TerminalBeforeCleanup);
    assert!(run.transcript.is_over());
    // The receipt's size and digest and the cleanup digest.
    for (path, value, breach) in [
        ("receiptSize", Value::int(72), Breach::ReceiptSize),
        ("receiptDigest", Value::str(&digest_of('1')), Breach::ReceiptDigest),
        ("cleanupDigest", Value::str(&digest_of('1')), Breach::CleanupDigest),
    ] {
        let mut run = Run::new(&positive);
        run.feed_all(&frames[..3]);
        assert_eq!(run.feed(&with(&frames[3], &["payload", path], value)).unwrap_err(), breach, "{path}");
    }
    // Nothing after TERMINAL.
    let mut run = Run::new(&positive);
    run.feed_all(&frames);
    let after = run.next_frame("ABORT", reason("DEADLINE"));
    assert_eq!(run.feed(&after).unwrap_err(), Breach::Ended);
}

/// The H5G-4 case (DESIGN-HE005 section 3.3 step 10; PR review round 1, R1-2; MON-R10-HE005B-R1 and
/// MON-R10-HE005B-H5G4): an exec failure after STARTED, so the worker sends no receipt. Today's transcript gives such a
/// run no ending through steps 12-14: CLEANUP_RECORDED needs a chunk, TERMINAL needs CLEANUP_RECORDED, and a REFUSED
/// after STARTED is refused, so the broker's only ending is closing the channel without a TERMINAL (the lost-terminal
/// path). ABORT is the server's frame, not the broker's ending, and is not exercised here. HE-005D adopts EDGE-V13's
/// no-receipt TERMINAL before live wiring and replaces this vector with steps 12-14.
#[test]
fn h5g4_exec_failure_after_started() {
    let positive = vector(0);
    let frames = frames(&positive);
    let schemas = schemas();
    // STARTED, then no RECEIPT_CHUNK: the worker never execs.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    assert!(!run.transcript.is_over(), "STARTED leaves the run open");
    // CLEANUP_RECORDED is refused: with no chunk the receipt is not complete.
    let cleanup = run.next_frame("CLEANUP_RECORDED", member(&frames[2], "payload").clone());
    assert_eq!(run.feed(&cleanup).unwrap_err(), Breach::ChunksIncomplete);
    // TERMINAL is unreachable: the builder refuses it before CLEANUP_RECORDED, whatever its status, and a received one
    // is refused the same way.
    for status in [TerminalStatus::Completed, TerminalStatus::Failed, TerminalStatus::Unavailable] {
        let mut run = Run::new(&positive);
        run.feed_all(&frames[..1]);
        assert_eq!(run.transcript.terminal(&schemas, status).unwrap_err(), Breach::TerminalBeforeCleanup, "{status:?}");
    }
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    let terminal = run.next_frame("TERMINAL", member(&frames[3], "payload").clone());
    assert_eq!(run.feed(&terminal).unwrap_err(), Breach::TerminalBeforeCleanup);
    // A REFUSED after STARTED is refused, built or received.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    assert_eq!(run.transcript.refused(&schemas, RefusedReason::Unavailable).unwrap_err(), Breach::RefusedNotFirst);
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    let refused = run.next_frame("REFUSED", reason("UNAVAILABLE"));
    assert_eq!(run.feed(&refused).unwrap_err(), Breach::RefusedNotFirst);
    // So no frame the broker can build ends the run: it stays open until the channel is closed without a TERMINAL.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    assert!(!run.transcript.is_over(), "the broker's only ending is the channel's close (the lost-terminal path)");
}

#[test]
fn at_most_one_abort() {
    let positive = vector(0);
    let frames = frames(&positive);
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..1]);
    let first = run.next_frame("ABORT", reason("DEADLINE"));
    run.feed(&first).expect("one ABORT");
    let second = run.next_frame("ABORT", reason("REVOKED"));
    assert_eq!(run.feed(&second).unwrap_err(), Breach::SecondAbort);
    // After one ABORT the run still ends with its chunks, CLEANUP_RECORDED and TERMINAL.
    let mut run = Run::new(&positive);
    run.feed_all(&frames[..3]);
    let abort = run.next_frame("ABORT", reason("PEER_CHANGED"));
    run.feed(&abort).expect("ABORT after CLEANUP_RECORDED");
    let terminal = run.next_frame("TERMINAL", member(&frames[3], "payload").clone());
    run.feed(&terminal).expect("TERMINAL after ABORT");
    assert!(run.transcript.is_over());
}

#[test]
fn messages_other_than_frames_and_bad_execution_ids_are_refused() {
    let positive = vector(0);
    let mut run = Run::new(&positive);
    assert_eq!(run.feed_raw(&canonical(member(&positive, "request")), Peer::Broker).unwrap_err(), Breach::NotFrame);
    let mut run = Run::new(&positive);
    assert_eq!(run.feed_raw(&canonical(member(&positive, "binding")), Peer::Server).unwrap_err(), Breach::NotFrame);
    let schemas = schemas();
    let request = canonical(member(&positive, "request"));
    let binding = canonical(member(&positive, "binding"));
    let dispatch = check_dispatch(&request, &binding, &configured(&positive), &schemas).expect("the DISPATCH passes");
    for execution_id in [hex_of('C'), hex_of('g'), "c".repeat(63), "c".repeat(65)] {
        assert!(matches!(Transcript::new(&dispatch, &execution_id), Err(Breach::ExecutionIdForm)), "{execution_id}");
    }
}

// ------------------------------------------------------------------------------------------------ the binding check

#[test]
fn each_binding_difference_is_refused_invalid_authority() {
    let schemas = schemas();
    let positive = vector(1);
    let request = member(&positive, "request").clone();
    let binding = member(&positive, "binding").clone();
    let good = configured(&positive);
    let refused = |request: &Value, binding: &[u8], configured: &ConfiguredDigests| {
        match check_dispatch(&canonical(request), binding, configured, &schemas) {
            Err(DispatchError::Authority(echo)) => echo,
            other => panic!("not refused INVALID_AUTHORITY: {:?}", other.map(|_| "passed")),
        }
    };
    // The DISPATCH's bindingDigest differs from the binding's SHA-256.
    let echo = refused(&with(&request, &["bindingDigest"], Value::str(&digest_of('1'))), &canonical(&binding), &good);
    assert_eq!(echo.get("bindingDigest"), Some(digest_of('1').as_str()));
    // Each of the four configured digests differs.
    for index in 0..4 {
        let mut configured = good.clone();
        let field = [&mut configured.broker_manifest, &mut configured.broker_executable,
            &mut configured.worker_manifest, &mut configured.worker_artifact].into_iter().nth(index).expect("a field");
        *field = digest_of('1');
        refused(&request, &canonical(&binding), &configured);
    }
    // The binding's bytes are not canonical.
    let mut spaced = canonical(&binding);
    spaced.insert(1, b' ');
    refused(&request, &spaced, &good);
    // The binding is outside $defs/binding, even with a matching digest.
    let extra = canonical(&with(&binding, &["extra"], Value::str("x")));
    refused(&with(&request, &["bindingDigest"], Value::str(&sha256::prefixed(&extra))), &extra, &good);
    // The profile and observation-binding digests are not among the configured four: a binding that differs only
    // there, with its own digest in the DISPATCH, passes.
    let other = canonical(&with(&binding, &["profileDigest"], Value::str(&digest_of('3'))));
    let request = with(&request, &["bindingDigest"], Value::str(&sha256::prefixed(&other)));
    check_dispatch(&canonical(&request), &other, &good, &schemas).expect("only the four digests are compared");
}

#[test]
fn a_refused_dispatch_answers_refused_once() {
    let schemas = schemas();
    let positive = vector(0);
    let request = canonical(member(&positive, "request"));
    let binding = canonical(member(&positive, "binding"));
    let mut configured = configured(&positive);
    configured.worker_artifact = digest_of('1');
    let Err(DispatchError::Authority(echo)) = check_dispatch(&request, &binding, &configured, &schemas) else {
        panic!("refused INVALID_AUTHORITY");
    };
    let execution_id = hex_of('c');
    let mut transcript = Transcript::refusing(&echo, &execution_id).expect("a refusing transcript");
    assert_eq!(transcript.started(&schemas, 1234, 123).unwrap_err(), Breach::FirstFrame);
    let mut transcript = Transcript::refusing(&echo, &execution_id).expect("a refusing transcript");
    let answer = transcript.refused(&schemas, RefusedReason::InvalidAuthority).expect("REFUSED");
    assert!(transcript.is_over());
    let answer = decode(&answer, &schemas).expect("REFUSED decodes");
    assert_eq!(text(member(&answer, "payload"), "reason"), "INVALID_AUTHORITY");
    assert_eq!(int(&answer, "sequence"), 1);
    assert_eq!(text(&answer, "previousDigest"), ZERO_DIGEST);
    for name in ECHO_FIELDS {
        assert_eq!(Some(text(&answer, name)), echo.get(name), "{name}");
    }
}

#[test]
fn a_datagram_that_is_no_dispatch_is_refused() {
    let schemas = schemas();
    let positive = vector(0);
    let binding = canonical(member(&positive, "binding"));
    let good = configured(&positive);
    let frame = canonical(&frames(&positive)[0]);
    assert_eq!(check_dispatch(&frame, &binding, &good, &schemas).unwrap_err(), DispatchError::NotDispatch);
    assert_eq!(check_dispatch(&binding, &binding, &good, &schemas).unwrap_err(), DispatchError::NotDispatch);
    let mut spaced = canonical(member(&positive, "request"));
    spaced.insert(1, b' ');
    assert_eq!(check_dispatch(&spaced, &binding, &good, &schemas).unwrap_err(), DispatchError::Frame(FrameError::F06));
}

// ------------------------------------------------------------------------------------------------ the refusal map

#[test]
fn the_refusal_map() {
    let reasons = ["NOT_ACTIVE", "ACTION_OUTSTANDING", "EXECUTION_REPLAY", "GENERATION_MISMATCH", "UNKNOWN_BINDING",
        "CERTIFICATE_MISMATCH", "MANIFEST_REUSED", "WORKER_NOT_OBSERVED", "STORAGE_FAILURE"];
    for name in reasons {
        let refusal = BindRefusal::from_wire(name).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(answer(Failure::BindRefused(refusal)), Some(RefusedReason::Unavailable), "{name}");
    }
    assert_eq!(BindRefusal::from_wire("ACTION_ID_OUT_OF_ORDER"), None);
    let rows = [
        (Failure::Held, Some(RefusedReason::CapacityHeld)),
        (Failure::BindingMismatch, Some(RefusedReason::InvalidAuthority)),
        (Failure::GateQualification, Some(RefusedReason::Unavailable)),
        (Failure::GateChannel, Some(RefusedReason::Unavailable)),
        (Failure::ScriptCheck, Some(RefusedReason::Unavailable)),
        (Failure::LeafCheck, Some(RefusedReason::Unavailable)),
        (Failure::Spawn, Some(RefusedReason::Unavailable)),
        (Failure::BindChannel, Some(RefusedReason::Unavailable)),
        (Failure::LeafNotEmpty, None),
    ];
    for (failure, expected) in rows {
        assert_eq!(answer(failure), expected, "{failure:?}");
    }
    let wire: Vec<&str> = [RefusedReason::Unavailable, RefusedReason::Replay, RefusedReason::GenerationMismatch,
        RefusedReason::CapacityHeld, RefusedReason::InvalidAuthority].iter().map(|reason| reason.wire()).collect();
    assert_eq!(wire, ["UNAVAILABLE", "REPLAY", "GENERATION_MISMATCH", "CAPACITY_HELD", "INVALID_AUTHORITY"]);
}
