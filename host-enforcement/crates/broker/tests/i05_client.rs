//! HE-005B's I05 client tests (the HE-005B plan's items 4 and 6; O14, O18): the broker's I05 vectors replayed from
//! the broker's side, and one failing case per client rule.
//!
//! The replay: in each transcript of `contracts/i05-v3/vectors.json`, `contracts/i05-v3-supplement/vectors.json` and
//! `contracts/i05-v4/vectors.json` (transcripts and order transcripts), one client per channel. Each FRAME event's
//! request is built through the client's builder and must equal, byte for byte, the frame effect-gate's replay support
//! sends (the config's generation and broker challenge, v3's when a config names none; the running sequence and
//! chain). Each response the vectors give is wrapped as the gate wraps it (`gate.rs`: the same generation and
//! challenge, the request's sequence plus one, the SHA-256 of the request's bytes, GATE_TO_BROKER) and must be
//! accepted, with its payload unchanged. A channel's replay ends where the gate's channel ends: a CHANNEL_LOST,
//! PEER_CHANGED or GATE_RESTART event, a mutated frame (a deliberately wrong broker frame), or a request the gate does
//! not answer, which the client must either refuse to build or send without an answer.

use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::sha256;
use i05_protocol::FrameError;
use planeon_broker::i02::{answer, Failure, RefusedReason, Verb, ZERO_DIGEST};
use planeon_broker::i05_client::{
    Bind, ChannelEnd, CloseReason, I05Client, Operation, BROKER_TO_GATE, GATE_TO_BROKER, I05_FRAME_VERSION,
};

const I05_V3: &str = include_str!("../../../contracts/i05-v3/vectors.json");
const I05_V3_SUPPLEMENT: &str = include_str!("../../../contracts/i05-v3-supplement/vectors.json");
const I05_V4: &str = include_str!("../../../contracts/i05-v4/vectors.json");

/// The events that end the gate's channel.
const CHANNEL_ENDS: [&str; 3] = ["CHANNEL_LOST", "PEER_CHANGED", "GATE_RESTART"];

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

fn hex_of(fill: char) -> String {
    std::iter::repeat(fill).take(64).collect()
}

fn frame(generation: &str, challenge: &str, sequence: i64, previous: &str, direction: &str, operation: &str,
         payload: &Value) -> Value {
    let mut frame = Object::new();
    frame.insert(JStr::new("schemaVersion"), Value::str(I05_FRAME_VERSION));
    frame.insert(JStr::new("generation"), Value::str(generation));
    frame.insert(JStr::new("challenge"), Value::str(challenge));
    frame.insert(JStr::new("sequence"), Value::int(sequence));
    frame.insert(JStr::new("previousDigest"), Value::str(previous));
    frame.insert(JStr::new("direction"), Value::str(direction));
    frame.insert(JStr::new("operation"), Value::str(operation));
    frame.insert(JStr::new("payload"), payload.clone());
    Value::Object(frame)
}

/// The gate's response frame to `request` (its exact bytes), as `gate.rs` builds it.
fn response_to(request: &[u8], payload: &Value) -> Value {
    let request_value = json::parse(std::str::from_utf8(request).expect("UTF-8")).expect("JSON");
    let sequence = member(&request_value, "sequence").as_int().and_then(|n| n.to_i64()).expect("a sequence");
    frame(text(&request_value, "generation"), text(&request_value, "challenge"), sequence + 1,
          &sha256::prefixed(request), GATE_TO_BROKER, text(&request_value, "operation"), payload)
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

/// The request a FRAME event stands for, through the client's typed builders; `None` when its payload is not one the
/// builders can be given (another operation, a missing, extra or mistyped member).
fn build(client: &mut I05Client, operation: &str, payload: &Value) -> Option<Result<Vec<u8>, ChannelEnd>> {
    let members = payload.as_object()?.len();
    let string = |key: &str| payload.get(key).and_then(Value::as_str);
    let integer = |key: &str| payload.get(key).and_then(Value::as_int).and_then(|n| n.to_i64());
    Some(match operation {
        "GENERATION_STATUS" if members == 0 => client.generation_status(),
        "BIND_EXECUTION" if members == 11 => {
            let bind = Bind {
                execution_id: string("executionId")?.to_string(),
                binding_digest: string("bindingDigest")?.to_string(),
                reservation_digest: string("reservationDigest")?.to_string(),
                run_nonce: string("runNonce")?.to_string(),
                case_id: string("caseId")?.to_string(),
                request_digest: string("requestDigest")?.to_string(),
                dispatch_generation: string("dispatchGeneration")?.to_string(),
                server_certificate_digest: string("serverCertificateDigest")?.to_string(),
                worker_pid: integer("workerPid")?,
                worker_start_ticks: integer("workerStartTicks")?,
                peer_qualification_digest: string("peerQualificationDigest")?.to_string(),
            };
            client.bind_execution(&bind)
        }
        "ARM_ACTION" if members == 6 => {
            let verb = match string("verb")? {
                "CREATE" => Verb::Create,
                "GET" => Verb::Get,
                "DELETE" => Verb::Delete,
                _ => return None,
            };
            let uid = match payload.get("recordedUid")? {
                Value::Null => None,
                other => Some(other.as_str()?),
            };
            client.arm_action(string("executionId")?, integer("actionId")?, verb, string("manifestDigest")?,
                              string("requestTemplateDigest")?, uid)
        }
        "ACTION_OUTCOME" if members == 2 => client.action_outcome(string("executionId")?, integer("actionId")?),
        "CLOSE_GENERATION" if members == 1 => client.close_generation(CloseReason::from_wire(string("reason")?)?),
        _ => return None,
    })
}

/// One vector file replayed from the broker's side: (requests reached, responses accepted).
fn replay(document: &Value, file: &str) -> (usize, usize) {
    let fallback = load(I05_V3);
    let active = member(member(&fallback, "configs"), "ACTIVE");
    let configs = member(document, "configs");
    let (mut reached, mut answered) = (0, 0);
    for key in ["transcripts", "orderTranscripts"] {
        for transcript in rows(document, key) {
            let id = text(transcript, "id");
            let config = member(configs, text(transcript, "config"));
            let generation = config.get("generation").unwrap_or_else(|| member(active, "generation"));
            let challenge = config.get("brokerChallenge").unwrap_or_else(|| member(active, "brokerChallenge"));
            let (generation, challenge) = (generation.as_str().expect("text"), challenge.as_str().expect("text"));
            let mut client =
                I05Client::open(generation, challenge).unwrap_or_else(|end| panic!("{file} {id}: {end:?}"));
            let (mut sequence, mut last) = (1i64, ZERO_DIGEST.to_string());
            let steps = rows(transcript, "events").iter().zip(rows(transcript, "outputs"));
            for (index, (event, output)) in steps.enumerate() {
                let context = format!("{file} {id} event {index}");
                let kind = text(event, "type");
                if kind != "FRAME" {
                    if CHANNEL_ENDS.contains(&kind) {
                        break;
                    }
                    continue;
                }
                if event.get("mutate").is_some() {
                    break;
                }
                reached += 1;
                let operation = text(event, "operation");
                let payload = member(event, "payload");
                let sent = frame(generation, challenge, sequence, &last, BROKER_TO_GATE, operation, payload);
                match (build(&mut client, operation, payload), output.get("response")) {
                    (Some(Ok(raw)), Some(response)) => {
                        assert_eq!(raw, canonical(&sent), "{context}: the request, byte for byte");
                        assert_eq!(client.awaiting().map(Operation::wire), Some(operation), "{context}");
                        let answer = canonical(&response_to(&raw, response));
                        let accepted = client.receive(&answer).unwrap_or_else(|end| panic!("{context}: {end:?}"));
                        assert_eq!(canonical(accepted.payload()), canonical(response), "{context}: the payload");
                        assert_eq!(accepted.sequence(), sequence + 1, "{context}");
                        answered += 1;
                        last = sha256::prefixed(&answer);
                        sequence += 2;
                    }
                    (_, None) => break,
                    (built, Some(_)) => panic!("{context}: the gate answered a request the client refused: {:?}",
                                               built.map(|result| result.err())),
                }
            }
        }
    }
    (reached, answered)
}

/// An opened client: GENERATION_STATUS sent and answered with the vectors' first status response.
fn opened() -> I05Client {
    let mut client = I05Client::open(&hex_of('a'), &hex_of('c')).expect("a client");
    let request = client.generation_status().expect("GENERATION_STATUS");
    client.receive(&canonical(&response_to(&request, &status_payload()))).expect("the status response");
    client
}

fn status_payload() -> Value {
    let v3 = load(I05_V3);
    let first = rows(&v3, "transcripts").first().expect("T01").clone();
    member(rows(&first, "outputs").first().expect("an output"), "response").clone()
}

fn bind() -> Bind {
    Bind {
        execution_id: hex_of('1'),
        binding_digest: format!("sha256:{}", hex_of('b')),
        reservation_digest: format!("sha256:{}", hex_of('d')),
        run_nonce: String::from("run-one"),
        case_id: String::from("KUBERNETES_SMOKE"),
        request_digest: format!("sha256:{}", hex_of('f')),
        dispatch_generation: hex_of('a'),
        server_certificate_digest: format!("sha256:{}", hex_of('4')),
        worker_pid: 4100,
        worker_start_ticks: 900_001,
        peer_qualification_digest: format!("sha256:{}", hex_of('e')),
    }
}

fn object(members: &[(&str, Value)]) -> Value {
    let mut object = Object::new();
    for (key, value) in members {
        object.insert(JStr::new(key), value.clone());
    }
    Value::Object(object)
}

fn refused(reason: &str) -> Value {
    object(&[("result", Value::str("REFUSED")), ("reason", Value::str(reason))])
}

// ------------------------------------------------------------------------------------------------ the replay

#[test]
fn the_i05_vectors_replay_from_the_brokers_side() {
    assert_eq!(replay(&load(I05_V3), "i05-v3"), (491, 485));
    assert_eq!(replay(&load(I05_V3_SUPPLEMENT), "i05-v3-supplement"), (25, 25));
    assert_eq!(replay(&load(I05_V4), "i05-v4"), (92, 88));
}

// ------------------------------------------------------------------------------------------------ opening, lockstep

#[test]
fn the_opening_request_and_the_lockstep() {
    let mut client = I05Client::open(&hex_of('a'), &hex_of('c')).expect("a client");
    let request = client.generation_status().expect("GENERATION_STATUS");
    let value = json::parse(std::str::from_utf8(&request).expect("UTF-8")).expect("JSON");
    assert_eq!(text(&value, "operation"), "GENERATION_STATUS");
    assert_eq!(member(&value, "sequence").as_int().and_then(|n| n.to_i64()), Some(1));
    assert_eq!(text(&value, "previousDigest"), ZERO_DIGEST);
    assert_eq!(text(&value, "direction"), BROKER_TO_GATE);
    assert_eq!(text(&value, "generation"), hex_of('a'));
    assert_eq!(text(&value, "challenge"), hex_of('c'));
    // A second request before the response.
    assert_eq!(client.generation_status().unwrap_err(), ChannelEnd::Outstanding);
    assert_eq!(client.generation_status().unwrap_err(), ChannelEnd::Ended);
    // The next request after a response is odd and chained to the response's exact bytes.
    let mut client = I05Client::open(&hex_of('a'), &hex_of('c')).expect("a client");
    let request = client.generation_status().expect("GENERATION_STATUS");
    let answer = canonical(&response_to(&request, &status_payload()));
    client.receive(&answer).expect("the status response");
    let next = client.bind_execution(&bind()).expect("BIND_EXECUTION");
    let next = json::parse(std::str::from_utf8(&next).expect("UTF-8")).expect("JSON");
    assert_eq!(member(&next, "sequence").as_int().and_then(|n| n.to_i64()), Some(3));
    assert_eq!(text(&next, "previousDigest"), sha256::prefixed(&answer));
}

#[test]
fn the_first_request_is_generation_status() {
    let mut client = I05Client::open(&hex_of('a'), &hex_of('c')).expect("a client");
    assert_eq!(client.bind_execution(&bind()).unwrap_err(), ChannelEnd::Opening);
    assert!(client.is_over());
    let mut client = I05Client::open(&hex_of('a'), &hex_of('c')).expect("a client");
    assert_eq!(client.close_generation(CloseReason::NormalDrain).unwrap_err(), ChannelEnd::Opening);
}

#[test]
fn the_generation_and_challenge_are_256_bit_hex() {
    let forms = [(hex_of('A'), hex_of('c')), (hex_of('a'), "c".repeat(63)), (hex_of('a'), hex_of('x'))];
    for (generation, challenge) in forms {
        assert!(matches!(I05Client::open(&generation, &challenge), Err(ChannelEnd::Form)));
    }
}

#[test]
fn an_unsolicited_gate_frame_ends_the_channel() {
    let mut client = I05Client::open(&hex_of('a'), &hex_of('c')).expect("a client");
    let stray = frame(&hex_of('a'), &hex_of('c'), 2, ZERO_DIGEST, GATE_TO_BROKER, "GENERATION_STATUS",
                      &status_payload());
    assert_eq!(client.receive(&canonical(&stray)).unwrap_err(), ChannelEnd::Unsolicited);
    let mut client = opened();
    assert_eq!(client.receive(&canonical(&stray)).unwrap_err(), ChannelEnd::Unsolicited);
    assert_eq!(client.generation_status().unwrap_err(), ChannelEnd::Ended);
}

// ------------------------------------------------------------------------------------------------ the response checks

/// The good status response changed in one way, each still inside the schema except the three byte forms.
fn deviate(name: &str, good: &Value) -> Vec<u8> {
    match name {
        // A request-shaped frame (its payload empty, as GENERATION_STATUS's request is) in the broker's direction.
        "direction" => {
            let other = with(good, &["direction"], Value::str(BROKER_TO_GATE));
            canonical(&with(&other, &["payload"], object(&[])))
        }
        "sequence" => canonical(&with(good, &["sequence"], Value::int(4))),
        "chain" => canonical(&with(good, &["previousDigest"], Value::str(&format!("sha256:{}", hex_of('9'))))),
        "generation" => canonical(&with(good, &["generation"], Value::str(&hex_of('b')))),
        "challenge" => canonical(&with(good, &["challenge"], Value::str(&hex_of('d')))),
        "operation" => {
            let other = with(good, &["operation"], Value::str("BIND_EXECUTION"));
            canonical(&with(&other, &["payload"], refused("NOT_ACTIVE")))
        }
        "non-canonical bytes" => {
            let mut bytes = canonical(good);
            bytes.insert(1, b' ');
            bytes
        }
        "over 16 KiB" => {
            let mut bytes = canonical(good);
            bytes.resize(16_385, b' ');
            bytes
        }
        "schema miss" => canonical(&with(good, &["payload"], object(&[]))),
        other => panic!("deviation {other}"),
    }
}

#[test]
fn each_response_deviation_ends_the_channel() {
    let deviations = [
        ("direction", ChannelEnd::Direction),
        ("sequence", ChannelEnd::Sequence),
        ("chain", ChannelEnd::Chain),
        ("generation", ChannelEnd::Generation),
        ("challenge", ChannelEnd::Challenge),
        ("operation", ChannelEnd::Operation),
        ("non-canonical bytes", ChannelEnd::Frame(FrameError::F06)),
        ("over 16 KiB", ChannelEnd::Frame(FrameError::F02)),
        ("schema miss", ChannelEnd::Frame(FrameError::F00)),
    ];
    for (name, expected) in deviations {
        let mut client = I05Client::open(&hex_of('a'), &hex_of('c')).expect("a client");
        let request = client.generation_status().expect("GENERATION_STATUS");
        let good = response_to(&request, &status_payload());
        assert_eq!(client.receive(&deviate(name, &good)).unwrap_err(), expected, "{name}");
        assert!(client.is_over(), "{name}");
        assert_eq!(client.receive(&canonical(&good)).unwrap_err(), ChannelEnd::Ended, "{name}: no repair");
    }
}

#[test]
fn an_ok_answer_repeats_its_requests_ids() {
    // BIND_EXECUTION's executionId.
    let mut client = opened();
    let request = client.bind_execution(&bind()).expect("BIND_EXECUTION");
    let other = object(&[("result", Value::str("OK")), ("executionId", Value::str(&hex_of('2'))),
        ("caseManifestSetDigest", Value::str(&format!("sha256:{}", hex_of('5'))))]);
    assert_eq!(client.receive(&canonical(&response_to(&request, &other))).unwrap_err(), ChannelEnd::Answer);
    // ARM_ACTION's actionId.
    let mut client = opened();
    let request = client.bind_execution(&bind()).expect("BIND_EXECUTION");
    let bound = object(&[("result", Value::str("OK")), ("executionId", Value::str(&hex_of('1'))),
        ("caseManifestSetDigest", Value::str(&format!("sha256:{}", hex_of('5'))))]);
    client.receive(&canonical(&response_to(&request, &bound))).expect("bound");
    let manifest = format!("sha256:{}", hex_of('6'));
    let template = format!("sha256:{}", hex_of('7'));
    let request = client.arm_action(&hex_of('1'), 1, Verb::Get, &manifest, &template, None).expect("ARM_ACTION");
    let armed = |action: i64| object(&[("result", Value::str("OK")), ("actionId", Value::int(action)),
        ("flushedConnections", Value::int(0))]);
    assert_eq!(client.receive(&canonical(&response_to(&request, &armed(2)))).unwrap_err(), ChannelEnd::Answer);
    // ACTION_OUTCOME's actionId.
    let mut client = opened();
    let request = client.bind_execution(&bind()).expect("BIND_EXECUTION");
    client.receive(&canonical(&response_to(&request, &bound))).expect("bound");
    let request = client.arm_action(&hex_of('1'), 1, Verb::Get, &manifest, &template, None).expect("ARM_ACTION");
    client.receive(&canonical(&response_to(&request, &armed(1)))).expect("armed");
    let request = client.action_outcome(&hex_of('1'), 1).expect("ACTION_OUTCOME");
    let outcome = |action: i64| object(&[("result", Value::str("OK")), ("actionId", Value::int(action)),
        ("classification", Value::str("NOT_FORWARDED")), ("admittedBeforeInvalidation", Value::Bool(false)),
        ("httpStatus", Value::Null), ("resultDigest", Value::Null), ("observedUid", Value::Null),
        ("observedResourceVersion", Value::Null)]);
    assert_eq!(client.receive(&canonical(&response_to(&request, &outcome(2)))).unwrap_err(), ChannelEnd::Answer);
    // The same answers with the request's ids are accepted, and a refusal carries no id.
    let mut client = opened();
    let request = client.bind_execution(&bind()).expect("BIND_EXECUTION");
    client.receive(&canonical(&response_to(&request, &bound))).expect("bound");
    let request = client.arm_action(&hex_of('1'), 1, Verb::Get, &manifest, &template, None).expect("ARM_ACTION");
    client.receive(&canonical(&response_to(&request, &armed(1)))).expect("armed");
    let request = client.action_outcome(&hex_of('1'), 1).expect("ACTION_OUTCOME");
    client.receive(&canonical(&response_to(&request, &outcome(1)))).expect("the outcome");
    let request = client.close_generation(CloseReason::NormalDrain).expect("CLOSE_GENERATION");
    let answer = client.receive(&canonical(&response_to(&request, &refused("ACTION_IN_FLIGHT")))).expect("refused");
    assert!(answer.is_refused());
    assert_eq!(answer.operation(), Operation::CloseGeneration);
}

#[test]
fn a_request_outside_the_schema_ends_the_channel() {
    let mut client = opened();
    let mut low = bind();
    low.worker_pid = 1;
    assert_eq!(client.bind_execution(&low).unwrap_err(), ChannelEnd::Request(FrameError::F00));
    assert!(client.is_over());
    let mut client = opened();
    assert_eq!(client.action_outcome(&hex_of('1'), 257).unwrap_err(), ChannelEnd::Request(FrameError::F00));
}

// ------------------------------------------------------------------------------------------------ the refusal map

#[test]
fn a_refused_bind_answers_through_the_refusal_map() {
    for reason in ["NOT_ACTIVE", "ACTION_OUTSTANDING", "EXECUTION_REPLAY", "GENERATION_MISMATCH", "UNKNOWN_BINDING",
                   "CERTIFICATE_MISMATCH", "MANIFEST_REUSED", "WORKER_NOT_OBSERVED", "STORAGE_FAILURE"] {
        let mut client = opened();
        let request = client.bind_execution(&bind()).expect("BIND_EXECUTION");
        let response = client.receive(&canonical(&response_to(&request, &refused(reason)))).expect("a refusal");
        let refusal = response.bind_refusal().unwrap_or_else(|| panic!("{reason}"));
        assert_eq!(answer(Failure::BindRefused(refusal)), Some(RefusedReason::Unavailable), "{reason}");
    }
    let mut client = I05Client::open(&hex_of('a'), &hex_of('c')).expect("a client");
    let request = client.generation_status().expect("GENERATION_STATUS");
    let status = client.receive(&canonical(&response_to(&request, &status_payload()))).expect("status");
    assert_eq!(status.bind_refusal(), None);
}

#[test]
fn the_close_reasons() {
    let reasons = ["NORMAL_DRAIN", "REVOCATION", "EXPIRY", "PEER_FAILURE", "STORAGE_FAILURE", "OBSERVATION_FAILURE",
        "RECONCILIATION_REQUIRED"];
    for reason in reasons {
        let parsed = CloseReason::from_wire(reason).unwrap_or_else(|| panic!("{reason}"));
        assert_eq!(parsed.wire(), reason);
        let mut client = opened();
        let request = client.close_generation(parsed).expect("CLOSE_GENERATION");
        let value = json::parse(std::str::from_utf8(&request).expect("UTF-8")).expect("JSON");
        assert_eq!(text(member(&value, "payload"), "reason"), reason);
    }
    assert_eq!(CloseReason::from_wire("ACTION_IN_FLIGHT"), None);
}
