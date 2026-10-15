//! HE-003C: the upstream port with the real model (DESIGN §2, §7; MODEL_DEFINED R59-R66). In the whole loop
//! (`tls_support`'s fake `Os`, the real `PolicyGate`, HE-003B's I04 port and the upstream port over the fake
//! `ConnectNet`): a forwarded GET reaches the scripted apiserver as exactly the client's request bytes and its answer
//! is relayed to the I04 client and journalled with its identity; the 900-second bound fed as the TIMEOUT through
//! `due`; the seal closing the exchange with nothing fed; the registrations following the phases. With the
//! `PolicyGate` alone: an I07 write started from `forwarded_write` in `sync`, its answer fed back as the write's
//! outcome, and a session end aborting it.

mod tls_support;
mod upstream_support;

use std::collections::BTreeMap;
use std::time::Duration;

use effect_gate::net::Connecting;
use effect_gate::substrate::{I05_CONN_TOKEN, I05_LISTENER_TOKEN};
use effect_gate::{Classification, ExpectedPeers, FrameInput, Lifetimes, LoopExit, Owner, PeerCredentials, PolicyEvent,
                  PolicyGate, PolicyOutputKind, Port, ProcIdentity, Readiness, Received, Substrate, WRITER_FRAME_VERSION};
use gate_tls::{render_response, Exchange, I04Server, SharedExchange, UpstreamClient, ALPN_HTTP11, UPSTREAM_BOUND};
use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::{sha256, FRAME_VERSION};

use tls_support::*;
use upstream_support::*;

const I05_VECTORS: &str = include_str!("../../../contracts/i05-v3/vectors.json");
const I07_VECTORS: &str = include_str!("../../../contracts/i07-v3/vectors.json");
const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BROKER_CHALLENGE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const WRITER_CHALLENGE: &str = "9999999999999999999999999999999999999999999999999999999999999999";
const VECTOR_CERTIFICATE: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const END: i64 = 1_900_000_000 + 3600;
const GET: &[u8] = b"GET /api/v1/namespaces/planeon-qual/pods/probe-pod HTTP/1.1\r\nHost: 198.51.100.7:6443\r\n\
                     Accept: application/json\r\n\r\n";
const POD: &[u8] = br#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"probe-pod","namespace":"planeon-qual","uid":"11111111-aaaa-4bbb-8ccc-000000000001","resourceVersion":"42"}}"#;

fn parse(text: &str) -> Value {
    json::parse(text).expect("vector file parses")
}

fn text(value: &Value) -> String {
    String::from_utf8_lossy(&json::canonical(value).expect("canonical")).into_owned()
}

fn object(members: Vec<(&str, Value)>) -> Value {
    let mut object = Object::new();
    for (key, value) in members {
        object.insert(JStr::new(key), value);
    }
    Value::Object(object)
}

/// The I07 ACTIVE configuration (apiserverAuthority 127.0.0.1:6443), with run-one's certificate digest set to the
/// test I04 client leaf's.
fn policy_gate(pki: &Pki) -> PolicyGate {
    let config = parse(I07_VECTORS).get("configs").and_then(|configs| configs.get("ACTIVE")).cloned().expect("ACTIVE");
    let ours = text(&config).replace(VECTOR_CERTIFICATE, &sha256::prefixed(&pki.client));
    PolicyGate::new(&parse(&ours), &parse(KINDS)).expect("the configuration builds a PolicyGate")
}

fn t01(operation: &str, nth: usize) -> Value {
    let vectors = parse(I05_VECTORS);
    let transcript = vectors
        .get("transcripts")
        .and_then(Value::as_array)
        .and_then(|rows| rows.iter().find(|row| row.get("id").and_then(Value::as_str) == Some("T01")))
        .cloned()
        .expect("T01");
    transcript
        .get("events")
        .and_then(Value::as_array)
        .map(|events| {
            events
                .iter()
                .filter(|event| {
                    event.get("type").and_then(Value::as_str) == Some("FRAME")
                        && event.get("operation").and_then(Value::as_str) == Some(operation)
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .and_then(|frames| frames.get(nth).cloned())
        .and_then(|event| event.get("payload").cloned())
        .expect("a T01 payload")
}

fn delivered(label: &str) -> Vec<u8> {
    let mut bytes = label.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

fn broker() -> (PeerCredentials, ProcIdentity) {
    let label = delivered(effect_gate::peers::BROKER_LABEL);
    let mut cgroup = effect_gate::peers::BROKER_CGROUP.as_bytes().to_vec();
    cgroup.push(b'\n');
    (PeerCredentials { pid: 4100, uid: 0, gid: 0, label: label.clone() },
     ProcIdentity { start_time: 900001, cgroup, label })
}

fn message(level: i32, kind: i32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&((16 + payload.len()) as u64).to_le_bytes());
    bytes.extend_from_slice(&level.to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(payload);
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }
    bytes
}

fn broker_control() -> Vec<u8> {
    let credentials = [4100i32.to_le_bytes(), 0u32.to_le_bytes(), 0u32.to_le_bytes()].concat();
    [message(1, 2, &credentials), message(1, 3, &delivered(effect_gate::peers::BROKER_LABEL))].concat()
}

fn token(owner: Owner, value: u64) -> u64 {
    owner.token(value).expect("a 56-bit value")
}

type Loop = Substrate<LoopOs, I04Server<FakeNet>, UpstreamClient<FakeConnect>>;

struct World {
    pki: Pki,
    upstream: UpstreamPki,
    lab: SharedLoop,
    net: SharedNet,
    connect: SharedConnect,
    exchange: SharedExchange,
    substrate: Loop,
}

fn world() -> World {
    let pki = pki();
    let upstream = upstream_pki();
    let gate = policy_gate(&pki);
    // HE-003D's hand-off (D2-5): the address R16 parsed once.
    let address = gate.apiserver_address();
    assert_eq!(address, APISERVER);
    let lab = loop_lab(broker());
    let net = net_lab();
    let connect = connect_lab();
    let exchange = Exchange::shared();
    let i04 = I04Server::new(FakeNet(net.clone()), production(&pki), exchange.clone());
    let port = UpstreamClient::new(FakeConnect { lab: connect.clone(), clock: net.clone() }, address,
                                   effect_config(&upstream, &upstream.serving_ca),
                                   writer_config(&upstream, &upstream.serving_ca), exchange.clone());
    let os = LoopOs { lab: lab.clone(), net: net.clone() };
    let lifetimes = Lifetimes::new(BTreeMap::from([("run-one".to_string(), END)]));
    let substrate = Substrate::new(gate, os, i04, port, ExpectedPeers::r10(), lifetimes).expect("the substrate starts");
    World { pki, upstream, lab, net, connect, exchange, substrate }
}

impl World {
    fn wake(&mut self, ready: Vec<(u64, Readiness)>) -> Result<(), LoopExit> {
        self.lab.borrow_mut().wakes.push_back(ready);
        self.substrate.turn()
    }

    fn broker(&mut self, operation: &str, payload: Value) -> String {
        let base = self.substrate.gate().gate();
        let frame = object(vec![
            ("schemaVersion", Value::str(FRAME_VERSION)),
            ("generation", Value::str(GENERATION)),
            ("challenge", Value::str(BROKER_CHALLENGE)),
            ("sequence", Value::int(base.next_sequence())),
            ("previousDigest", Value::str(base.last_digest())),
            ("direction", Value::str("BROKER_TO_GATE")),
            ("operation", Value::str(operation)),
            ("payload", payload),
        ]);
        let bytes = json::canonical(&frame).expect("canonical");
        let sent = self.lab.borrow().sent.len();
        self.lab.borrow_mut().inbox.push_back(Received::Datagram { bytes, truncated: false, control: broker_control(),
                                                                   control_truncated: false });
        self.wake(vec![(I05_CONN_TOKEN, readable())]).expect("the broker frame's wake");
        let lab = self.lab.borrow();
        lab.sent.get(sent).map(|answer| String::from_utf8_lossy(answer).into_owned()).unwrap_or_default()
    }

    /// The broker connected, run-one bound and GET probe-pod armed as action 1.
    fn armed(&mut self) {
        self.wake(vec![(I05_LISTENER_TOKEN, readable())]).expect("the broker's accept");
        self.broker("GENERATION_STATUS", object(Vec::new()));
        let bind = text(&t01("BIND_EXECUTION", 0)).replace(VECTOR_CERTIFICATE, &sha256::prefixed(&self.pki.client));
        assert!(self.broker("BIND_EXECUTION", parse(&bind)).contains("\"result\":\"OK\""));
        let arm = parse(&text(&t01("ARM_ACTION", 1)).replace("\"actionId\":2", "\"actionId\":1"));
        assert!(self.broker("ARM_ACTION", arm).contains("\"result\":\"OK\""));
    }

    /// An I04 client's GET, consumed and forwarded: its client.
    fn forwarded(&mut self) -> Peer {
        let source = self.net.borrow_mut().connect();
        self.wake(vec![(token(Owner::I04, 0), readable())]).expect("the I04 accept wake");
        let mut peer = Peer::new(source, client_config(&self.pki, Some(self.pki.client.clone()), &[ALPN_HTTP11]));
        for _ in 0..6 {
            peer.push(&self.net);
            self.wake(vec![(token(Owner::I04, source), readable())]).expect("a handshake wake");
            peer.pull(&self.net);
            if !peer.tls.is_handshaking() && !peer.tls.wants_write() {
                break;
            }
        }
        peer.write(&self.net, GET);
        self.wake(vec![(token(Owner::I04, source), readable())]).expect("the request wake");
        assert!(self.substrate.upstream().is_open(), "the Forward armed the upstream exchange");
        peer
    }

    /// The upstream connect at the next (zero-timeout) wake, then the handshake with the scripted apiserver through
    /// upstream wakes, until it holds the request.
    fn upstream_handshake(&mut self) -> Apiserver {
        self.connect.borrow_mut().connects.push_back(Ok(Connecting::Connected));
        self.wake(Vec::new()).expect("the start deadline's wake");
        let source = self.connect.borrow().last();
        let mut apiserver = Apiserver::new(source, apiserver_config(&self.upstream));
        for _ in 0..6 {
            apiserver.pump(&self.connect);
            self.wake(vec![(token(Owner::Upstream, source), Readiness { readable: true, writable: true,
                                                                        ..Readiness::default() })])
                .expect("an upstream wake");
        }
        apiserver.pump(&self.connect);
        apiserver
    }

    fn journal_tail(&self) -> String {
        let journal = self.substrate.gate().gate().snapshot().to_value().get("journal").cloned().expect("a journal");
        journal.as_array().and_then(|records| records.last()).map(text).unwrap_or_default()
    }
}

#[test]
fn a_forwarded_get_reaches_the_apiserver_exactly_and_its_answer_is_relayed_and_journalled() {
    let mut world = world();
    world.armed();
    let mut peer = world.forwarded();
    let mut apiserver = world.upstream_handshake();
    assert_eq!(apiserver.received, GET.to_vec(), "exactly the I04 client's bytes, Host included");
    assert_eq!(apiserver.peer_leaf(), Some(world.upstream.effect.clone()));
    apiserver.respond(&world.connect, &http("200 OK", POD));
    world.wake(vec![(token(Owner::Upstream, apiserver.source), readable())]).expect("the answer's wake");
    peer.pull(&world.net);
    assert_eq!(peer.received, render_response(200, POD).expect("rendered"), "relayed, re-rendered");
    let terminal = world.journal_tail();
    assert!(terminal.contains("TERMINAL") && terminal.contains("DELIVERED_RESULT") && terminal.contains("\"42\"")
            && terminal.contains("11111111-aaaa-4bbb-8ccc-000000000001") && terminal.contains(&sha256::prefixed(POD)),
            "{terminal}");
    assert!(!world.substrate.upstream().is_open() && world.substrate.upstream().next_deadline().is_none());
    assert!(world.exchange.borrow().request().is_none() && !world.exchange.borrow().has_response());
    // The registrations followed the phases: the upstream source added once, then modified, never deleted.
    let polls: Vec<PollCall> = world.lab.borrow().polls.iter().filter(|poll| poll.owner == Owner::Upstream).cloned().collect();
    assert_eq!(polls.iter().filter(|poll| poll.kind == "add").count(), 1, "{polls:?}");
    assert!(polls.iter().all(|poll| poll.kind != "delete" && poll.source == apiserver.source), "{polls:?}");
    assert!(polls[0].interest.is_some_and(|interest| interest.readable), "{polls:?}");
}

#[test]
fn the_900_second_bound_is_fed_as_the_timeout_through_due() {
    let mut world = world();
    world.armed();
    let mut peer = world.forwarded();
    let apiserver = world.upstream_handshake();
    world.net.borrow_mut().advance(UPSTREAM_BOUND - Duration::from_secs(1));
    world.wake(Vec::new()).expect("a wake before the bound");
    assert!(world.substrate.upstream().is_open());
    world.net.borrow_mut().advance(Duration::from_secs(1));
    world.wake(Vec::new()).expect("the bound's wake");
    assert!(!world.substrate.upstream().is_open());
    assert!(world.connect.borrow().lines[&apiserver.source].closed);
    let terminal = world.journal_tail();
    assert!(terminal.contains("TERMINAL") && terminal.contains("IO_AMBIGUOUS"), "{terminal}");
    assert_eq!(world.substrate.gate().gate().state().as_str(), "HELD");
    peer.pull(&world.net);
    assert!(peer.received.is_empty(), "nothing relayed");
    assert!(world.net.borrow().wires.get(&peer.source).is_some_and(|wire| wire.closed));
}

#[test]
fn the_seal_closes_the_exchange_and_nothing_is_fed() {
    let mut world = world();
    world.armed();
    let _peer = world.forwarded();
    let apiserver = world.upstream_handshake();
    let journal_before = world.substrate.gate().gate().journal().len();
    let outcome = parse(&text(&t01("ACTION_OUTCOME", 1)).replace("\"actionId\":2", "\"actionId\":1"));
    let answer = world.broker("ACTION_OUTCOME", outcome);
    assert!(answer.contains("IO_AMBIGUOUS"), "{answer}");
    assert!(!world.substrate.upstream().is_open(), "the seal closed the exchange");
    assert!(world.connect.borrow().lines[&apiserver.source].closed);
    let journal_after = world.substrate.gate().gate().journal().len();
    world.net.borrow_mut().advance(UPSTREAM_BOUND);
    world.wake(vec![(token(Owner::Upstream, apiserver.source), readable())]).expect("later wakes feed nothing");
    assert_eq!(world.substrate.gate().gate().journal().len(), journal_after, "no TIMEOUT or late record");
    assert!(journal_after > journal_before);
}

// ------------------------------------------------------------------------------------------ I07 with the PolicyGate

fn writer_frame(gate: &PolicyGate, operation: &str, payload: Value) -> PolicyEvent {
    PolicyEvent::WFrame(FrameInput::Value(object(vec![
        ("schemaVersion", Value::str(WRITER_FRAME_VERSION)),
        ("challenge", Value::str(WRITER_CHALLENGE)),
        ("sequence", Value::int(gate.writer_next_sequence())),
        ("previousDigest", Value::str(gate.writer_last_digest())),
        ("direction", Value::str("WRITER_TO_GATE")),
        ("operation", Value::str(operation)),
        ("payload", payload),
    ])))
}

/// A writer session with an open maintenance and write 1 (CREATE planeon-role) forwarded.
fn forwarded_write(pki: &Pki) -> PolicyGate {
    let mut gate = policy_gate(pki);
    gate.handle(PolicyEvent::WConnect { challenge: WRITER_CHALLENGE.into() }).expect("connect");
    let status = writer_frame(&gate, "MAINTENANCE_STATUS", object(Vec::new()));
    gate.handle(status).expect("status");
    let begin = writer_frame(&gate, "WRITE_BEGIN", object(vec![("expectedGeneration", Value::str(GENERATION))]));
    gate.handle(begin).expect("begin");
    let write = writer_frame(&gate, "WRITE_OBJECT", parse(ROLE_CREATE));
    assert_eq!(gate.handle(write).expect("write").kind, PolicyOutputKind::Forwarded(1));
    gate
}

#[test]
fn an_i07_write_starts_from_forwarded_write_and_its_answer_is_the_writes_outcome() {
    let pki = pki();
    let mut gate = forwarded_write(&pki);
    let mut rig = upstream_support::rig();
    let (_, rendered_write) = gate.forwarded_write().expect("the forwarded write");
    let mut request = rendered_write.head.as_bytes().to_vec();
    request.extend_from_slice(&rendered_write.body);
    rig.port.sync(&gate);
    assert!(rig.port.is_open(), "started in sync");
    assert_eq!(rig.port.next_deadline(), Some(rig.now()));
    let (mut apiserver, events) = rig.handshake();
    assert!(events.is_empty());
    assert_eq!(apiserver.received, request, "exactly the rendered request");
    assert_eq!(apiserver.peer_leaf(), Some(rig.pki.writer.clone()), "the writer identity");
    let role = br#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"planeon-role","namespace":"planeon-qual","uid":"u-2","resourceVersion":"43"},"rules":[]}"#;
    let events = rig.answer(&mut apiserver, &http("201 Created", role));
    let [event] = <[PolicyEvent; 1]>::try_from(events).expect("one event");
    let output = gate.handle(event).expect("the model takes the outcome");
    match &output.kind {
        PolicyOutputKind::Upstream { classification, response: Some(payload) } => {
            assert_eq!(*classification, Classification::DeliveredResult);
            let canonical = String::from_utf8_lossy(&payload.canonical()).into_owned();
            assert!(canonical.contains("\"observedUid\":\"u-2\"") && canonical.contains("\"observedResourceVersion\":\"43\"")
                    && canonical.contains(&sha256::prefixed(role)), "{canonical}");
        }
        other => panic!("a relayed write outcome, not {other:?}"),
    }
    rig.port.sync(&gate);
    assert!(!rig.port.is_open() && rig.port.failure().is_none(), "a finished write is not started again");
}

#[test]
fn a_session_end_aborts_the_write_and_nothing_is_fed() {
    let pki = pki();
    let mut gate = forwarded_write(&pki);
    let mut rig = upstream_support::rig();
    rig.port.sync(&gate);
    rig.connect(Ok(Connecting::InProgress));
    let source = rig.lab.borrow().last();
    let output = gate.handle(PolicyEvent::WChannelLost).expect("the writer's channel is lost");
    assert!(matches!(output.kind, PolicyOutputKind::SessionEnd { .. }));
    rig.port.sync(&gate);
    assert!(!rig.port.is_open() && rig.closed(source));
    assert!(rig.port.due(rig.now() + Duration::from_secs(10)).is_empty());
    assert_eq!(rig.port.failure(), None);
}
