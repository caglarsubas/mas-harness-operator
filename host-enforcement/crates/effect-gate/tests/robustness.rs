//! No panics on any input: seeded pseudo-random event sequences (valid and mutated frames as values and as bytes,
//! garbage datagrams, connection and upstream events on arbitrary names, injections, restarts) never panic, every
//! output and snapshot encodes, and an event the gate refuses leaves its state unchanged.

mod support;

use effect_gate::{Config, Event, FrameInput, Gate, UpstreamResponse};
use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::FRAME_VERSION;
use support::*;

const VECTORS: &str = include_str!("../../../contracts/i05-v3/vectors.json");

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

#[test]
fn random_event_sequences_never_panic() {
    let vectors = load(VECTORS);
    let configs = field(&vectors, "configs");
    // Payloads and heads harvested from the contract transcripts, so many random frames are well formed.
    let mut payloads: Vec<(Value, Value)> = Vec::new();
    let mut requests: Vec<Value> = Vec::new();
    for row in rows(&vectors, "transcripts") {
        for event in rows(row, "events") {
            match text(event, "type") {
                "FRAME" => payloads.push((field(event, "operation").clone(), field(event, "payload").clone())),
                "REQUEST" => requests.push(event.clone()),
                _ => {}
            }
        }
    }
    let conns = ["c1", "c2", "c3", "", "c1"];
    let mut rng = Rng(0x0DDB_1A5E_5BAD_5EED);
    let mut refused = 0usize;
    for round in 0..400 {
        let name = ["ACTIVE", "INSPECTING", "LATER"][round % 3];
        let config_value = field(configs, name);
        let (converted, kernel) = effect_gate::fake_kernel::convert_v3_config(config_value).expect("v4's conversion");
        let observer = Box::new(effect_gate::KernelObserver::new(kernel));
        let mut gate = Gate::new(Config::from_value(&converted).expect("config")).expect("gate").with_observer(observer);
        for _ in 0..rng.below(80) {
            let conn = conns[rng.below(conns.len())].to_string();
            let event = match rng.below(16) {
                0..=5 => {
                    let (operation, payload) = payloads[rng.below(payloads.len())].clone();
                    let mut envelope = Object::new();
                    envelope.insert(JStr::new("schemaVersion"), Value::str(FRAME_VERSION));
                    envelope.insert(JStr::new("generation"), field(config_value, "generation").clone());
                    envelope.insert(JStr::new("challenge"), field(config_value, "brokerChallenge").clone());
                    let sequence = if rng.below(10) == 0 { rng.below(5) as i64 } else { gate.next_sequence() };
                    envelope.insert(JStr::new("sequence"), Value::int(sequence));
                    envelope.insert(JStr::new("previousDigest"), Value::str(gate.last_digest()));
                    envelope.insert(JStr::new("direction"), Value::str("BROKER_TO_GATE"));
                    envelope.insert(JStr::new("operation"), operation);
                    envelope.insert(JStr::new("payload"), payload);
                    let frame = Value::Object(envelope);
                    Event::Frame(match rng.below(4) {
                        0 => FrameInput::Value(frame),
                        1 => FrameInput::NotBytes,
                        2 => {
                            let mut raw = json::canonical(&frame).unwrap_or_default();
                            if !raw.is_empty() {
                                let position = rng.below(raw.len());
                                raw[position] = (rng.next() & 0xFF) as u8;
                            }
                            FrameInput::Bytes(raw)
                        }
                        _ => FrameInput::Bytes(json::canonical(&frame).unwrap_or_default()),
                    })
                }
                6 => Event::Backlog { conn },
                7 => Event::Accept { conn },
                8 => {
                    let request = &requests[rng.below(requests.len())];
                    Event::Request {
                        conn,
                        certificate_digest: text(request, "certificateDigest").to_string(),
                        head: text(request, "head").to_string(),
                        body_digest: field(request, "bodyDigest").as_str().map(str::to_string),
                    }
                }
                9 => Event::UpstreamResponse {
                    conn,
                    response: UpstreamResponse {
                        http_status: [201, 200, 404, 500, 408, 999, -1, i64::MAX][rng.below(8)],
                        body_digest: "sha256:".to_string() + &"8".repeat(64),
                        uid: [None, Some("u".to_string()), Some("\n".to_string())][rng.below(3)].clone(),
                        resource_version: [None, Some("41".to_string())][rng.below(2)].clone(),
                    },
                },
                10 => [Event::UpstreamLost { conn: conn.clone() }, Event::UpstreamTimeout { conn }][rng.below(2)].clone(),
                11 => [Event::StorageFailNext { torn: rng.below(2) == 0 }, Event::MarkerFailNext,
                       Event::StorageFailAfter { after: rng.below(4) as u64 }][rng.below(3)].clone(),
                12 => Event::DrainRequest,
                13 => Event::Expire,
                14 => [Event::ChannelLost, Event::SecondChannel, Event::PeerChanged][rng.below(3)].clone(),
                _ => Event::GateRestart,
            };
            let before = gate.snapshot();
            match gate.handle(event) {
                Ok(output) => {
                    let _ = output.to_doc().canonical();
                }
                Err(_) => {
                    refused += 1;
                    assert_eq!(gate.snapshot(), before, "a refused event changed the gate");
                }
            }
        }
        let _ = gate.snapshot().canonical();
        let _ = gate.journal_digest();
    }
    assert!(refused > 0, "the sequences reach events outside the preconditions");
}
