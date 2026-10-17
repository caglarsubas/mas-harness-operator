//! HE-003B: the I04 port in the whole loop (DESIGN §7, §9; MODEL_DEFINED R43-R57): gate-tls's own fake `Os` (HE-003A's
//! is in effect-gate's test tree), the real `PolicyGate`, the I04 port over a fake `StreamNet` with rustls test
//! clients, and a fake upstream port that stages through `stage_response`. ARM's flush with connections opened before
//! it and one still in the kernel's queue; a stamped request forwarded and relayed, the journalled TERMINAL equal to
//! the relayed response; C5; STAMP_NONE; CERTIFICATE_MISMATCH; REQUEST_MISMATCH; the expiry fed before a request; a
//! restarted gate; a drain that fails before the frame; batches of accepts, registration and interests.

mod tls_support;

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use std::time::Instant;

use effect_gate::substrate::{I05_CONN_TOKEN, I05_LISTENER_TOKEN};
use effect_gate::{Event, ExpectedPeers, GateView, Lifetimes, LoopExit, OutputKind, Owner, PeerCredentials,
                  PolicyEvent, PolicyGate, PolicyOutput, PolicyOutputKind, Port, ProcIdentity, Readiness, Received,
                  Registry, Substrate, UpstreamPort};
use gate_tls::{render_response, Exchange, I04Server, SharedExchange, ALPN_HTTP11, DRAIN_LIMIT};
use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::{sha256, FRAME_VERSION};

use tls_support::*;

const I05_VECTORS: &str = include_str!("../../../contracts/i05-v3/vectors.json");
const I07_VECTORS: &str = include_str!("../../../contracts/i07-v3/vectors.json");
const KINDS: &str = include_str!("../../../contracts/i07-v3/policy-kinds.json");
const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BROKER_CHALLENGE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const VECTOR_CERTIFICATE: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
/// Run-one's lifetime end (s); the fake `Os`'s realtime clock starts at 1,900,000,000 s.
const END: i64 = 1_900_000_000 + 3600;
const GET: &[u8] = b"GET /api/v1/namespaces/planeon-qual/pods/probe-pod HTTP/1.1\r\nHost: 198.51.100.7:6443\r\n\
                     Accept: application/json\r\n\r\n";

fn parse(text: &str) -> Value {
    json::parse(text).expect("vector file parses")
}

fn text(value: &Value) -> String {
    String::from_utf8_lossy(&json::canonical(value).expect("canonical")).into_owned()
}

/// The I07 ACTIVE configuration, with run-one's certificate digest set to the test client leaf's (R47).
fn gate(pki: &Pki) -> PolicyGate {
    let config = parse(I07_VECTORS).get("configs").and_then(|configs| configs.get("ACTIVE")).cloned().expect("ACTIVE");
    let ours = text(&config).replace(VECTOR_CERTIFICATE, &sha256::prefixed(&pki.client));
    let (converted, kernel) = effect_gate::fake_kernel::convert_v3_config(&parse(&ours)).expect("v4's conversion");
    let gate = PolicyGate::new(&converted, &parse(KINDS)).expect("the configuration builds a PolicyGate");
    gate.with_observer(Box::new(effect_gate::KernelObserver::new(kernel)))
}

fn object(members: Vec<(&str, Value)>) -> Value {
    let mut object = Object::new();
    for (key, value) in members {
        object.insert(JStr::new(key), value);
    }
    Value::Object(object)
}

/// The payload of the n-th FRAME with `operation` in I05 v3 transcript T01.
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

/// ARM_ACTION of a GET of probe-pod as action 1 (T01's second ARM, renumbered: the template does not name the action).
fn arm_get() -> Value {
    parse(&text(&t01("ARM_ACTION", 1)).replace("\"actionId\":2", "\"actionId\":1"))
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

fn readable() -> Readiness {
    Readiness { readable: true, ..Readiness::default() }
}

/// The fake upstream port: it takes the confirmed request on `Forward` and returns the events the test staged.
struct StagingUpstream {
    exchange: SharedExchange,
    queue: Rc<RefCell<VecDeque<PolicyEvent>>>,
    taken: Rc<RefCell<Vec<(String, String)>>>,
}

impl Port for StagingUpstream {
    fn register(&mut self, _registry: &mut Registry<'_>) -> Result<(), LoopExit> {
        Ok(())
    }

    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    fn due(&mut self, _now: Instant) -> Vec<PolicyEvent> {
        Vec::new()
    }

    fn ready(&mut self, _value: u64, _readiness: Readiness) -> Vec<PolicyEvent> {
        self.queue.borrow_mut().drain(..).collect()
    }

    fn apply(&mut self, output: &PolicyOutput) {
        if let PolicyOutputKind::Base(base) = &output.kind
            && let OutputKind::Forward { action_id } = base.kind
            && let Some(request) = self.exchange.borrow_mut().take_request(action_id)
        {
            self.taken.borrow_mut().push((request.conn, request.head));
        }
    }

    fn sync(&mut self, _view: &dyn GateView) {}
}

impl UpstreamPort for StagingUpstream {}

type Loop = Substrate<LoopOs, I04Server<FakeNet>, StagingUpstream>;

struct World {
    pki: Pki,
    lab: SharedLoop,
    net: SharedNet,
    exchange: SharedExchange,
    upstream: Rc<RefCell<VecDeque<PolicyEvent>>>,
    taken: Rc<RefCell<Vec<(String, String)>>>,
    substrate: Loop,
}

fn lifetimes() -> Lifetimes {
    Lifetimes::new(BTreeMap::from([("run-one".to_string(), END)]))
}

fn world_with(pki: Pki, gate: PolicyGate, port: Option<(SharedNet, I04Server<FakeNet>, SharedExchange)>)
              -> Result<World, LoopExit> {
    let lab = loop_lab(broker());
    let (net, port, exchange) = port.unwrap_or_else(|| {
        let net = net_lab();
        let exchange = Exchange::shared();
        let port = I04Server::new(FakeNet(net.clone()), production(&pki), exchange.clone());
        (net, port, exchange)
    });
    let upstream = Rc::new(RefCell::new(VecDeque::new()));
    let taken = Rc::new(RefCell::new(Vec::new()));
    let fake = StagingUpstream { exchange: exchange.clone(), queue: upstream.clone(), taken: taken.clone() };
    let os = LoopOs { lab: lab.clone(), net: net.clone() };
    let substrate = Substrate::new(gate, os, port, fake, ExpectedPeers::r10(), lifetimes())?;
    Ok(World { pki, lab, net, exchange, upstream, taken, substrate })
}

fn world() -> World {
    let pki = pki();
    let gate = gate(&pki);
    world_with(pki, gate, None).expect("the substrate starts")
}

fn i04(value: u64) -> u64 {
    Owner::I04.token(value).expect("a 56-bit value")
}

impl World {
    fn wake(&mut self, ready: Vec<(u64, Readiness)>) -> Result<(), LoopExit> {
        self.lab.borrow_mut().wakes.push_back(ready);
        self.substrate.turn()
    }

    fn frame(&self, operation: &str, payload: Value) -> Vec<u8> {
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
        json::canonical(&frame).expect("canonical")
    }

    /// The broker's next frame; the answer it got.
    fn broker(&mut self, operation: &str, payload: Value) -> Result<String, LoopExit> {
        let bytes = self.frame(operation, payload);
        let sent = self.lab.borrow().sent.len();
        self.lab.borrow_mut().inbox.push_back(Received::Datagram { bytes, truncated: false, control: broker_control(),
                                                                   control_truncated: false });
        self.wake(vec![(I05_CONN_TOKEN, readable())])?;
        let lab = self.lab.borrow();
        Ok(lab.sent.get(sent).map(|answer| String::from_utf8_lossy(answer).into_owned()).unwrap_or_default())
    }

    /// The broker connected, its channel opened and run-one bound.
    fn bound(&mut self) {
        self.wake(vec![(I05_LISTENER_TOKEN, readable())]).expect("the broker's accept");
        self.broker("GENERATION_STATUS", object(Vec::new())).expect("the channel opens");
        // BIND carries the run's certificate digest too: the test client leaf's.
        let bind = text(&t01("BIND_EXECUTION", 0)).replace(VECTOR_CERTIFICATE, &sha256::prefixed(&self.pki.client));
        let answer = self.broker("BIND_EXECUTION", parse(&bind)).expect("BIND");
        assert!(answer.contains("\"result\":\"OK\""), "{answer}");
    }

    fn arm(&mut self) -> String {
        self.broker("ARM_ACTION", arm_get()).expect("ARM")
    }

    /// A queued I04 connection, accepted at a listener wake.
    fn connect(&mut self) -> u64 {
        let source = self.net.borrow_mut().connect();
        self.wake(vec![(i04(0), readable())]).expect("the I04 accept wake");
        source
    }

    /// A finished handshake on `source` with the client leaf `leaf`.
    fn handshake(&mut self, source: u64, leaf: Vec<u8>) -> Peer {
        let mut peer = Peer::new(source, client_config(&self.pki, Some(leaf), &[ALPN_HTTP11]));
        for _ in 0..6 {
            peer.push(&self.net);
            self.wake(vec![(i04(source), readable())]).expect("a handshake wake");
            peer.pull(&self.net);
            if !peer.tls.is_handshaking() && !peer.tls.wants_write() {
                break;
            }
        }
        peer
    }

    fn send(&mut self, peer: &mut Peer, bytes: &[u8]) -> Result<(), LoopExit> {
        peer.write(&self.net, bytes);
        self.wake(vec![(i04(peer.source), readable())])
    }

    fn snapshot(&self) -> Value {
        self.substrate.gate().gate().snapshot().to_value()
    }

    fn closed(&self, source: u64) -> bool {
        self.net.borrow().wires.get(&source).is_some_and(|wire| wire.closed)
    }

    fn journal_tail(&self) -> String {
        let journal = self.snapshot().get("journal").cloned().expect("a journal");
        journal.as_array().and_then(|records| records.last()).map(text).unwrap_or_default()
    }
}

#[test]
fn arm_flushes_the_connections_opened_before_it_and_the_queued_one() {
    let mut world = world();
    world.bound();
    let first = world.connect();
    let second = world.connect();
    let queued = world.net.borrow_mut().connect(); // in the kernel's queue when the ARM frame arrives
    world.arm();
    let snapshot = world.snapshot();
    assert_eq!(snapshot.get("actions").and_then(|actions| actions.get("1")).and_then(|action| action.get("status"))
                   .map(text), Some("\"ARMED\"".to_string()));
    assert_eq!(text(snapshot.get("counters").and_then(|counters| counters.get("flushClosures")).expect("counter")), "3");
    for source in [first, second, queued] {
        assert!(world.closed(source), "i04-{source} is flushed");
        assert_eq!(snapshot.get("connections").and_then(|connections| connections.get(&format!("i04-{source}")))
                       .map(text), Some("\"CLOSED\"".to_string()));
    }
}

#[test]
fn a_stamped_request_is_forwarded_relayed_and_journalled_as_relayed() {
    let mut world = world();
    world.bound();
    world.arm();
    let source = world.connect();
    let mut peer = world.handshake(source, world.pki.client.clone());
    world.send(&mut peer, GET).expect("the request wake");
    let name = format!("i04-{source}");
    assert_eq!(world.taken.borrow().clone(), vec![(name.clone(), String::from_utf8_lossy(GET).into_owned())],
               "forwarded: the upstream port took the confirmed request");
    let body = br#"{"kind":"Pod","metadata":{"name":"probe-pod","uid":"11111111-aaaa-4bbb-8ccc-000000000001"}}"#.to_vec();
    let event = world.exchange.borrow_mut()
        .stage_response(&name, 200, body.clone(), Some("11111111-aaaa-4bbb-8ccc-000000000001".into()), Some("42".into()))
        .expect("staged");
    world.upstream.borrow_mut().push_back(event);
    world.wake(vec![(Owner::Upstream.token(1).expect("a token"), readable())]).expect("the upstream wake");
    peer.pull(&world.net);
    assert_eq!(peer.received, render_response(200, &body).expect("rendered"));
    let terminal = world.journal_tail();
    assert!(terminal.contains("TERMINAL") && terminal.contains("200") && terminal.contains(&sha256::prefixed(&body)),
            "{terminal}");
}

#[test]
fn consumption_closes_the_other_connection_stamped_with_the_action() {
    let mut world = world();
    world.bound();
    world.arm();
    let first = world.connect();
    let second = world.connect();
    let mut peer = world.handshake(first, world.pki.client.clone());
    world.send(&mut peer, GET).expect("the request wake");
    assert!(!world.substrate.gate().connection_open(&format!("i04-{second}")));
    assert!(world.closed(second), "C5");
    assert!(!world.closed(first));
}

#[test]
fn a_connection_accepted_while_nothing_is_armed_is_refused_stamp_none() {
    let mut world = world();
    world.bound();
    let source = world.connect();
    let mut peer = world.handshake(source, world.pki.client.clone());
    world.send(&mut peer, GET).expect("the request wake");
    assert!(world.closed(source));
    let snapshot = world.snapshot();
    assert_eq!(text(snapshot.get("counters").and_then(|counters| counters.get("correlationRefusals")).expect("counter")),
               "1");
    peer.pull(&world.net);
    assert!(peer.closed_by_server() && peer.received.is_empty(), "close_notify and no HTTP byte");
}

#[test]
fn a_different_ca_valid_certificate_and_an_added_header_are_refused() {
    let mut world = world();
    world.bound();
    world.arm();
    let other = client_leaf(&world.pki, &Spec::leaf(20, "planeon test ca", "planeon other", CLIENT_AUTH, San::Uri(RUN_URI)));
    let source = world.connect();
    let mut peer = world.handshake(source, other);
    world.send(&mut peer, GET).expect("the request wake");
    assert!(world.closed(source));
    let refusals = |world: &World| {
        text(world.snapshot().get("counters").and_then(|counters| counters.get("correlationRefusals")).expect("counter"))
    };
    assert_eq!(refusals(&world), "1", "CERTIFICATE_MISMATCH is counted");
    let source = world.connect();
    let mut peer = world.handshake(source, world.pki.client.clone());
    let mut added = GET[..GET.len() - 2].to_vec();
    added.extend_from_slice(b"X-Extra: 1\r\n\r\n");
    world.send(&mut peer, &added).expect("the request wake");
    assert!(world.closed(source));
    assert_eq!(refusals(&world), "2", "REQUEST_MISMATCH is counted");
}

#[test]
fn an_expiry_fed_before_the_request_closes_the_fed_connection_once() {
    let mut world = world();
    world.bound();
    world.arm();
    let source = world.connect();
    let mut peer = world.handshake(source, world.pki.client.clone());
    // The realtime clock reaches run-one's end between the wake's own check and the check before the request.
    world.lab.borrow_mut().expire_after = Some((2, END * 1000));
    world.send(&mut peer, GET).expect("the request wake");
    assert!(world.closed(source));
    let sends = world.net.borrow().calls.iter().filter(|call| call.starts_with(&format!("send {source} "))).count();
    peer.pull(&world.net);
    assert!(peer.closed_by_server() && peer.received.is_empty());
    let connections = world.snapshot().get("connections").cloned().expect("connections");
    assert_eq!(connections.get(&format!("i04-{source}")).map(text), Some("\"CLOSED\"".to_string()));
    assert!(world.exchange.borrow().request().is_none(), "the staged request is dropped");
    assert!(world.taken.borrow().is_empty(), "never forwarded");
    assert!(world.journal_tail().contains("DENIED") || world.journal_tail().contains("EXPIRED"), "{}", world.journal_tail());
    assert!(sends >= 1);
}

#[test]
fn a_restarted_gate_refuses_the_first_request_and_carries_no_connection() {
    let pki = pki();
    let mut gate = gate(&pki);
    // The in-memory restart (GATE_RESTART, deny-first): no channel, stamps or connections survive.
    let restart = gate.handle(PolicyEvent::Base(Event::GateRestart)).expect("restart");
    assert!(matches!(restart.kind, PolicyOutputKind::Restart { .. } | PolicyOutputKind::Base(_)));
    let mut world = world_with(pki, gate, None).expect("the substrate starts");
    assert!(world.substrate.i04().held().is_empty(), "a new process starts with an empty stream table");
    let source = world.connect();
    let mut peer = world.handshake(source, world.pki.client.clone());
    world.send(&mut peer, GET).expect("the request wake");
    assert!(world.closed(source));
    assert!(world.taken.borrow().is_empty());
}

#[test]
fn a_drain_that_fails_before_the_arm_frame_stops_the_loop() {
    let mut world = world();
    world.bound();
    for _ in 0..(DRAIN_LIMIT + 2) {
        world.net.borrow_mut().queue.push_back(effect_gate::Accepted::Skip);
    }
    let exit = world.broker("ARM_ACTION", arm_get());
    assert_eq!(exit, Err(LoopExit::Port(Owner::I04, "the pre-frame drain passed 1,024 accepts")));
    let snapshot = world.snapshot();
    assert_eq!(snapshot.get("actions").map(text), Some("{}".to_string()), "the ARM frame was never fed");
}

#[test]
fn a_batch_of_accepts_stays_open_and_registration_follows_the_phases() {
    let mut world = world();
    world.bound();
    world.arm();
    let sources: Vec<u64> = (0..3).map(|_| world.net.borrow_mut().connect()).collect();
    world.wake(vec![(i04(0), readable())]).expect("one listener wake");
    for source in &sources {
        assert!(world.substrate.gate().connection_open(&format!("i04-{source}")), "kept open through every sync");
        assert!(!world.closed(*source));
    }
    let polls = world.lab.borrow().polls.clone();
    assert!(polls.iter().any(|poll| poll.kind == "add" && poll.source == LISTENER.0));
    for source in &sources {
        assert!(polls.iter().any(|poll| poll.kind == "add" && poll.source == *source
                                 && poll.interest.is_some_and(|interest| interest.readable)));
    }
    // After the request is fed, readable interest is dropped.
    let mut peer = world.handshake(sources[0], world.pki.client.clone());
    world.send(&mut peer, GET).expect("the request wake");
    let polls = world.lab.borrow().polls.clone();
    assert!(polls.iter().any(|poll| poll.kind == "modify" && poll.source == sources[0]
                             && poll.interest.is_some_and(|interest| !interest.readable)), "{polls:?}");
}

#[test]
fn register_stops_the_loop_on_a_connection_left_unconfirmed() {
    let pki = pki();
    let gate = gate(&pki);
    let net = net_lab();
    let exchange = Exchange::shared();
    let mut port = I04Server::new(FakeNet(net.clone()), production(&pki), exchange.clone());
    net.borrow_mut().connect();
    assert_eq!(port.ready(0, readable()).len(), 2, "accepted, its Accept never fed");
    let exit = world_with(pki, gate, Some((net, port, exchange))).err();
    assert_eq!(exit, Some(LoopExit::Port(Owner::I04, "an accepted I04 connection was never confirmed by the model")));
}
