//! PolicyGate never panics (HE-002B): seeded pseudo-random sequences of writer events (valid, mutated, garbage and
//! non-byte frames, connections, losses, peer changes, upstream outcomes inside and outside R15's patterns for any
//! write ID) mixed with I05 events, injections and restarts. Every output encodes, every framed response the gate sends
//! is a valid frame of its channel, and an event the gate refuses leaves the snapshot unchanged.

mod policy_support;
mod support;

use effect_gate::{Event, FrameInput, PolicyEvent, PolicyGate, PolicyOutputKind, UpstreamOutcome, UpstreamResponse};
use i05_protocol::json::{self, Value};
use i05_protocol::{decode_frame, Datagram};
use policy_support::*;
use support::*;

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

fn frame_variant(rng: &mut Rng, frame: Value) -> FrameInput {
    match rng.below(5) {
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
        3 => FrameInput::Bytes((0..rng.below(40)).map(|_| (rng.next() & 0xFF) as u8).collect()),
        _ => FrameInput::Bytes(json::canonical(&frame).unwrap_or_default()),
    }
}

#[test]
fn random_policy_event_sequences_never_panic() {
    let vectors = load(I07_VECTORS);
    let kinds = load(KINDS);
    let configs = field(&vectors, "configs");
    let broker_schema = i05_protocol::i05_v3_schema().expect("I05 schema");
    let writer_schema = i05_protocol::i07_v3_schema().expect("I07 schema");
    // Operations and payloads harvested from the contract transcripts, so many random frames are well formed.
    let (mut writer_payloads, mut broker_payloads, mut base_events) = (Vec::new(), Vec::new(), Vec::new());
    for row in rows(&vectors, "transcripts") {
        for event in rows(row, "events") {
            match text(event, "type") {
                "W_FRAME" => writer_payloads.push(event.clone()),
                "FRAME" => broker_payloads.push(event.clone()),
                "BACKLOG" | "ACCEPT" | "REQUEST" | "UPSTREAM_RESPONSE" | "STORAGE_FAIL_NEXT" | "STORAGE_FAIL_AFTER" | "DRAIN_REQUEST"
                | "CHANNEL_LOST" => base_events.push(event.clone()),
                _ => {}
            }
        }
    }
    let challenges = ["9".repeat(64), "8".repeat(64)];
    let digests = ["sha256:".to_string() + &"8".repeat(64), "sha256:XYZ".to_string()];
    let mut rng = Rng(0x5EED_0F_1A57_C0DE);
    let (mut refused, mut framed) = (0usize, 0usize);
    for round in 0..300 {
        let config = field(configs, ["ACTIVE", "INSPECTING"][round % 2]);
        let mut gate = PolicyGate::new(config, &kinds).expect("PolicyGate");
        let mut challenge = Value::str(&challenges[0]);
        for _ in 0..rng.below(60) {
            let event = match rng.below(16) {
                0..=4 => {
                    let template = &writer_payloads[rng.below(writer_payloads.len())];
                    let sequence = if rng.below(12) == 0 { rng.below(6) as i64 } else { gate.writer_next_sequence() };
                    // The template's own mutations (a vector's deviations) apply as in the replay.
                    let frame = writer_frame(&challenge, sequence, gate.writer_last_digest(), template);
                    PolicyEvent::WFrame(frame_variant(&mut rng, frame))
                }
                5 => {
                    let text = &challenges[rng.below(2)];
                    challenge = Value::str(text);
                    PolicyEvent::WConnect { challenge: text.clone() }
                }
                6 => [PolicyEvent::WChannelLost, PolicyEvent::WPeerChanged][rng.below(2)].clone(),
                7 | 8 => PolicyEvent::WUpstream {
                    write_id: [0u16, 1, 2, 3, 256, u16::MAX][rng.below(6)],
                    outcome: match rng.below(4) {
                        0 => UpstreamOutcome::Lost,
                        1 => UpstreamOutcome::Timeout,
                        _ => UpstreamOutcome::Response(UpstreamResponse {
                            http_status: [200, 201, 202, 204, 404, 408, 409, 503, 99, 600, i64::MIN][rng.below(11)],
                            body_digest: digests[rng.below(2)].clone(),
                            uid: [None, Some("u-1".to_string()), Some("u_1".to_string())][rng.below(3)].clone(),
                            resource_version: [None, Some("42".to_string()), Some("4.2".to_string())][rng.below(3)].clone(),
                        }),
                    },
                },
                9 | 10 => {
                    let template = &broker_payloads[rng.below(broker_payloads.len())];
                    let base = gate.gate();
                    let frame = broker_frame(config, base.next_sequence(), base.last_digest(), template);
                    PolicyEvent::Base(Event::Frame(frame_variant(&mut rng, frame)))
                }
                11 | 12 => PolicyEvent::Base(base_event(&base_events[rng.below(base_events.len())], "robustness")),
                13 => PolicyEvent::Base([Event::Expire, Event::PeerChanged, Event::SecondChannel,
                                         Event::StorageFailNext { torn: true }, Event::MarkerFailNext][rng.below(5)].clone()),
                14 => PolicyEvent::Base(Event::StorageFailAfter { after: rng.below(4) as u64 }),
                _ => PolicyEvent::Base(Event::GateRestart),
            };
            let before = gate.snapshot();
            match gate.handle(event) {
                Ok(output) => {
                    let _ = output.to_doc().canonical();
                    if let Some(frame) = &output.response_frame {
                        let schema = if matches!(output.kind, PolicyOutputKind::Base(_)) { &broker_schema } else { &writer_schema };
                        assert!(decode_frame(Datagram::Bytes(frame), schema).is_ok(), "a sent response is a valid frame");
                        framed += 1;
                    }
                    if let PolicyOutputKind::Base(base) = &output.kind {
                        if let Some(frame) = &base.response_frame {
                            assert!(decode_frame(Datagram::Bytes(frame), &broker_schema).is_ok());
                        }
                    }
                }
                Err(_) => {
                    refused += 1;
                    assert_eq!(gate.snapshot(), before, "a refused event changed the gate");
                }
            }
        }
        let snapshot = gate.snapshot().to_value();
        let writes = snapshot.get("writes").and_then(Value::as_object).map_or(0, |writes| writes.len());
        assert!(writes <= 256);
        let _ = gate.gate().journal_digest();
    }
    assert!(refused > 0, "the sequences reach events outside the preconditions");
    assert!(framed > 0, "the sequences reach framed writer responses");
}
