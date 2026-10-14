//! Fakes for the HE-003A substrate tests (DESIGN §9): a scripted `Os` (accept queues, peers with their credentials,
//! process identity and pidfd, per-connection inboxes and sent datagrams, scripted wakes with the monotonic and
//! realtime clocks), and scripted I04 and upstream ports. Everything they see goes into one shared lab, with a trace of
//! the calls in order, so the tests can check what the loop did, in which order, and what the model answered.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use std::time::{Duration, Instant};

use effect_gate::journal::journal_doc;
use effect_gate::substrate::{I05_CONN_TOKEN, I05_LISTENER_TOKEN, I05_PIDFD_TOKEN, I07_CONN_TOKEN, I07_LISTENER_TOKEN,
                             I07_PIDFD_TOKEN};
use effect_gate::{ConnId, ExpectedPeers, FileStores, GateView, I04Port, Interest, Lifetimes, Listen, LoopExit, Os,
                  OsFailure, Owner, PeerCredentials, PolicyEvent, PolicyGate, PolicyOutput, Port, PortPoll, ProcIdentity,
                  Readiness, Received, Registry, SourceId, StoreDir, Substrate, UpstreamPort, Watch,
                  WRITER_FRAME_VERSION};
use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::FRAME_VERSION;

pub const I05_VECTORS: &str = include_str!("../../../../contracts/i05-v3/vectors.json");
pub const I07_VECTORS: &str = include_str!("../../../../contracts/i07-v3/vectors.json");
pub const KINDS: &str = include_str!("../../../../contracts/i07-v3/policy-kinds.json");

pub const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const BROKER_CHALLENGE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
pub const WRITER_CHALLENGE: &str = "9999999999999999999999999999999999999999999999999999999999999999";

pub const BROKER_PID: i32 = 4100;
pub const WRITER_PID: i32 = 5100;
pub const BROKER_START: u64 = 900001;
pub const WRITER_START: u64 = 777;
pub const BROKER_LEAF: &[u8] = b"0::/planeon.slice/planeon-capacity-broker.service/broker\n";
pub const WORKER_LEAF: &[u8] = b"0::/planeon.slice/planeon-capacity-broker.service/probe-worker\n";
pub const ADMIN_SCOPE: &[u8] = b"0::/user.slice/user-0.slice/session-1.scope\n";

/// A label as the kernel delivers it: with its NUL.
pub fn delivered(label: &str) -> Vec<u8> {
    let mut bytes = label.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

pub fn broker_label() -> Vec<u8> {
    delivered(effect_gate::peers::BROKER_LABEL)
}

pub fn writer_label() -> Vec<u8> {
    delivered(effect_gate::peers::WRITER_LABEL)
}

/// What the fake kernel says about one connection's peer.
#[derive(Clone, Debug)]
pub struct FakePeer {
    pub credentials: Option<PeerCredentials>,
    pub open_proc: bool,
    pub identity: Option<ProcIdentity>,
    pub exited: bool,
}

pub fn broker_peer() -> FakePeer {
    FakePeer {
        credentials: Some(PeerCredentials { pid: BROKER_PID, uid: 0, gid: 0, label: broker_label() }),
        open_proc: true,
        identity: Some(ProcIdentity { start_time: BROKER_START, cgroup: BROKER_LEAF.to_vec(), label: broker_label() }),
        exited: false,
    }
}

pub fn writer_peer() -> FakePeer {
    FakePeer {
        credentials: Some(PeerCredentials { pid: WRITER_PID, uid: 0, gid: 0, label: writer_label() }),
        open_proc: true,
        identity: Some(ProcIdentity { start_time: WRITER_START, cgroup: ADMIN_SCOPE.to_vec(), label: writer_label() }),
        exited: false,
    }
}

/// One control message as the kernel lays it out (64-bit `cmsg_len`, level, type, payload, padding to 8).
pub fn message(level: i32, kind: i32, payload: &[u8]) -> Vec<u8> {
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

pub fn credentials_message(pid: i32, uid: u32, gid: u32) -> Vec<u8> {
    let payload = [pid.to_le_bytes(), uid.to_le_bytes(), gid.to_le_bytes()].concat();
    message(1, 2, &payload)
}

pub fn security_message(label: &[u8]) -> Vec<u8> {
    message(1, 3, label)
}

/// The control bytes of a datagram from `pid`/`uid`/`gid` with socket label `label`.
pub fn control(pid: i32, uid: u32, gid: u32, label: &[u8]) -> Vec<u8> {
    [credentials_message(pid, uid, gid), security_message(label)].concat()
}

pub fn broker_control() -> Vec<u8> {
    control(BROKER_PID, 0, 0, &broker_label())
}

pub fn writer_control() -> Vec<u8> {
    control(WRITER_PID, 0, 0, &writer_label())
}

pub fn datagram(bytes: Vec<u8>, control: Vec<u8>) -> Received {
    Received::Datagram { bytes, truncated: false, control, control_truncated: false }
}

pub fn readable() -> Readiness {
    Readiness { readable: true, ..Readiness::default() }
}

/// One connection of the fake kernel.
#[derive(Debug)]
pub struct FakeConn {
    pub side: Listen,
    pub peer: FakePeer,
    pub inbox: VecDeque<Received>,
    pub sent: Vec<Vec<u8>>,
    pub send_ok: bool,
    pub closed: bool,
    pub capacities: Vec<usize>,
}

/// One scripted wait: how far the clocks move during it and what it reports.
#[derive(Clone, Debug, Default)]
pub struct Wake {
    pub advance: Duration,
    pub realtime_step: i64,
    pub ready: Vec<(u64, Readiness)>,
}

/// A port's script.
#[derive(Default)]
pub struct PortScript {
    pub deadline: Option<Duration>,
    pub due: VecDeque<Vec<PolicyEvent>>,
    pub ready: VecDeque<Vec<PolicyEvent>>,
    pub backlog: VecDeque<Vec<PolicyEvent>>,
    pub realtime_on_ready: Option<i64>,
    pub stall_on_backlog: Option<Duration>,
    pub register: VecDeque<(SourceId, u64)>,
    pub outputs: Vec<String>,
    pub synced: Vec<Option<u16>>,
    pub open_checked: Vec<(String, bool)>,
    pub check_open: Option<String>,
}

/// Everything the fakes share.
pub struct Lab {
    pub base: Instant,
    pub mono: Duration,
    pub realtime: Option<i64>,
    pub accepts: BTreeMap<Listen, VecDeque<Result<FakePeer, OsFailure>>>,
    pub conns: BTreeMap<u64, FakeConn>,
    pub next_conn: u64,
    pub wakes: VecDeque<Wake>,
    pub waits: Vec<i32>,
    pub wait_fails: bool,
    pub watch_fails: bool,
    pub watches: Vec<(Watch, u64)>,
    pub trace: Vec<String>,
    pub stall_on_read: Option<Duration>,
    pub realtime_on_recv: Option<i64>,
    pub port_sources: BTreeMap<SourceId, (Owner, u64)>,
    pub i04: PortScript,
    pub upstream: PortScript,
}

pub type Shared = Rc<RefCell<Lab>>;

pub fn lab() -> Shared {
    Rc::new(RefCell::new(Lab {
        base: Instant::now(),
        mono: Duration::ZERO,
        realtime: Some(1_900_000_000_000),
        accepts: BTreeMap::new(),
        conns: BTreeMap::new(),
        next_conn: 1,
        wakes: VecDeque::new(),
        waits: Vec::new(),
        wait_fails: false,
        watch_fails: false,
        watches: Vec::new(),
        trace: Vec::new(),
        stall_on_read: None,
        realtime_on_recv: None,
        port_sources: BTreeMap::new(),
        i04: PortScript::default(),
        upstream: PortScript::default(),
    }))
}

/// The scripted `Os`.
pub struct FakeOs(pub Shared);

impl PortPoll for FakeOs {
    fn port_add(&mut self, owner: Owner, source: SourceId, token: u64, _interest: Interest) -> bool {
        let mut lab = self.0.borrow_mut();
        lab.trace.push(format!("port_add {owner:?} {} {token:#x}", source.0));
        if lab.port_sources.contains_key(&source) {
            return false;
        }
        lab.port_sources.insert(source, (owner, token));
        true
    }

    fn port_modify(&mut self, owner: Owner, source: SourceId, token: u64, _interest: Interest) -> bool {
        let mut lab = self.0.borrow_mut();
        match lab.port_sources.get_mut(&source) {
            Some(entry) if entry.0 == owner => {
                entry.1 = token;
                true
            }
            _ => false,
        }
    }

    fn port_delete(&mut self, owner: Owner, source: SourceId) -> bool {
        let mut lab = self.0.borrow_mut();
        match lab.port_sources.get(&source) {
            Some(entry) if entry.0 == owner => {
                lab.port_sources.remove(&source);
                true
            }
            _ => false,
        }
    }
}

impl Os for FakeOs {
    fn accept(&mut self, listener: Listen) -> Result<Option<ConnId>, OsFailure> {
        let mut lab = self.0.borrow_mut();
        let next = lab.accepts.get_mut(&listener).and_then(VecDeque::pop_front);
        match next {
            None => Ok(None),
            Some(Err(failure)) => Err(failure),
            Some(Ok(peer)) => {
                let number = lab.next_conn;
                lab.next_conn += 1;
                lab.conns.insert(number, FakeConn {
                    side: listener,
                    peer,
                    inbox: VecDeque::new(),
                    sent: Vec::new(),
                    send_ok: true,
                    closed: false,
                    capacities: Vec::new(),
                });
                lab.trace.push(format!("accept {listener:?} #{number}"));
                Ok(Some(ConnId(number)))
            }
        }
    }

    fn peer(&mut self, conn: ConnId) -> Option<PeerCredentials> {
        let mut lab = self.0.borrow_mut();
        lab.trace.push(format!("peer #{}", conn.0));
        lab.conns.get(&conn.0)?.peer.credentials.clone()
    }

    fn open_proc(&mut self, conn: ConnId, pid: i32) -> bool {
        let mut lab = self.0.borrow_mut();
        lab.trace.push(format!("open_proc #{} {pid}", conn.0));
        lab.conns.get(&conn.0).is_some_and(|fake| fake.peer.open_proc)
    }

    fn read_proc(&mut self, conn: ConnId) -> Option<ProcIdentity> {
        let mut lab = self.0.borrow_mut();
        lab.trace.push(format!("read_proc #{}", conn.0));
        if let Some(stall) = lab.stall_on_read.take() {
            lab.mono += stall;
        }
        lab.conns.get(&conn.0)?.peer.identity.clone()
    }

    fn peer_exited(&mut self, conn: ConnId) -> bool {
        let mut lab = self.0.borrow_mut();
        lab.trace.push(format!("exited #{}", conn.0));
        lab.conns.get(&conn.0).is_none_or(|fake| fake.peer.exited)
    }

    fn recv(&mut self, conn: ConnId, control_capacity: usize) -> Received {
        let mut lab = self.0.borrow_mut();
        lab.trace.push(format!("recv #{}", conn.0));
        let realtime = lab.realtime_on_recv;
        let Some(fake) = lab.conns.get_mut(&conn.0) else { return Received::Error(9) };
        fake.capacities.push(control_capacity);
        let received = fake.inbox.pop_front().unwrap_or(Received::WouldBlock);
        if matches!(received, Received::Datagram { .. }) && realtime.is_some() {
            lab.realtime = realtime;
            lab.realtime_on_recv = None;
        }
        received
    }

    fn send(&mut self, conn: ConnId, bytes: &[u8]) -> bool {
        let mut lab = self.0.borrow_mut();
        lab.trace.push(format!("send #{}", conn.0));
        match lab.conns.get_mut(&conn.0) {
            Some(fake) if fake.send_ok && !fake.closed => {
                fake.sent.push(bytes.to_vec());
                true
            }
            _ => false,
        }
    }

    fn close(&mut self, conn: ConnId) {
        // Closing a connection already closed does nothing (`Os::close`; HE-003A PR review round 1, R1-6).
        let mut lab = self.0.borrow_mut();
        if let Some(fake) = lab.conns.get_mut(&conn.0) {
            if !fake.closed {
                fake.closed = true;
                lab.trace.push(format!("close #{}", conn.0));
            }
        }
    }

    fn watch(&mut self, watch: Watch, token: u64) -> bool {
        let mut lab = self.0.borrow_mut();
        lab.trace.push(format!("watch {watch:?} {token}"));
        lab.watches.push((watch, token));
        !lab.watch_fails
    }

    fn wait(&mut self, timeout_ms: i32) -> Option<Vec<(u64, Readiness)>> {
        let mut lab = self.0.borrow_mut();
        lab.waits.push(timeout_ms);
        lab.trace.push(format!("wait {timeout_ms}"));
        if lab.wait_fails {
            return None;
        }
        let wake = lab.wakes.pop_front().unwrap_or_default();
        lab.mono += wake.advance;
        lab.realtime = lab.realtime.map(|now| now + wake.realtime_step);
        Some(wake.ready)
    }

    fn monotonic(&self) -> Instant {
        let lab = self.0.borrow();
        lab.base + lab.mono
    }

    fn realtime_ms(&self) -> Option<i64> {
        self.0.borrow().realtime
    }
}

fn record(lab: &Shared, which: Owner, output: &PolicyOutput) {
    let text = String::from_utf8_lossy(&output.to_doc().canonical()).into_owned();
    let mut lab = lab.borrow_mut();
    match which {
        Owner::I04 => lab.i04.outputs.push(text),
        Owner::Upstream => lab.upstream.outputs.push(text),
    }
}

fn script(lab: &mut Lab, which: Owner) -> &mut PortScript {
    match which {
        Owner::I04 => &mut lab.i04,
        Owner::Upstream => &mut lab.upstream,
    }
}

fn register(lab: &Shared, which: Owner, registry: &mut Registry<'_>) -> Result<(), LoopExit> {
    let queued: Vec<(SourceId, u64)> = script(&mut lab.borrow_mut(), which).register.drain(..).collect();
    for (source, value) in queued {
        registry.add(source, value, Interest { readable: true, writable: false })?;
    }
    Ok(())
}

fn next_deadline(lab: &Shared, which: Owner) -> Option<Instant> {
    let mut lab = lab.borrow_mut();
    let base = lab.base;
    script(&mut lab, which).deadline.map(|deadline| base + deadline)
}

fn due(lab: &Shared, which: Owner) -> Vec<PolicyEvent> {
    let mut lab = lab.borrow_mut();
    lab.trace.push(format!("due {which:?}"));
    let port = script(&mut lab, which);
    port.deadline = None;
    port.due.pop_front().unwrap_or_default()
}

fn ready(lab: &Shared, which: Owner, value: u64) -> Vec<PolicyEvent> {
    let mut lab = lab.borrow_mut();
    lab.trace.push(format!("ready {which:?} {value}"));
    if let Some(realtime) = script(&mut lab, which).realtime_on_ready.take() {
        lab.realtime = Some(realtime);
    }
    script(&mut lab, which).ready.pop_front().unwrap_or_default()
}

fn sync(lab: &Shared, which: Owner, view: &dyn GateView) {
    let mut lab = lab.borrow_mut();
    let port = script(&mut lab, which);
    port.synced.push(view.pending_write());
    if let Some(conn) = port.check_open.clone() {
        port.open_checked.push((conn.clone(), view.connection_open(&conn)));
    }
}

/// The scripted I04 port.
pub struct FakeI04(pub Shared);

impl Port for FakeI04 {
    fn register(&mut self, registry: &mut Registry<'_>) -> Result<(), LoopExit> {
        register(&self.0, Owner::I04, registry)
    }

    fn next_deadline(&self) -> Option<Instant> {
        next_deadline(&self.0, Owner::I04)
    }

    fn due(&mut self, _now: Instant) -> Vec<PolicyEvent> {
        due(&self.0, Owner::I04)
    }

    fn ready(&mut self, value: u64, _readiness: Readiness) -> Vec<PolicyEvent> {
        ready(&self.0, Owner::I04, value)
    }

    fn apply(&mut self, output: &PolicyOutput) {
        record(&self.0, Owner::I04, output);
    }

    fn sync(&mut self, view: &dyn GateView) {
        sync(&self.0, Owner::I04, view);
    }
}

impl I04Port for FakeI04 {
    fn drain_backlog(&mut self) -> Vec<PolicyEvent> {
        let mut lab = self.0.borrow_mut();
        lab.trace.push("drain".to_string());
        if let Some(stall) = lab.i04.stall_on_backlog.take() {
            lab.mono += stall;
        }
        lab.i04.backlog.pop_front().unwrap_or_default()
    }
}

/// The scripted upstream port.
pub struct FakeUpstream(pub Shared);

impl Port for FakeUpstream {
    fn register(&mut self, registry: &mut Registry<'_>) -> Result<(), LoopExit> {
        register(&self.0, Owner::Upstream, registry)
    }

    fn next_deadline(&self) -> Option<Instant> {
        next_deadline(&self.0, Owner::Upstream)
    }

    fn due(&mut self, _now: Instant) -> Vec<PolicyEvent> {
        due(&self.0, Owner::Upstream)
    }

    fn ready(&mut self, value: u64, _readiness: Readiness) -> Vec<PolicyEvent> {
        ready(&self.0, Owner::Upstream, value)
    }

    fn apply(&mut self, output: &PolicyOutput) {
        record(&self.0, Owner::Upstream, output);
    }

    fn sync(&mut self, view: &dyn GateView) {
        sync(&self.0, Owner::Upstream, view);
    }
}

impl UpstreamPort for FakeUpstream {}

// ------------------------------------------------------------------------------------------ the model and its frames

pub fn parse(text: &str) -> Value {
    json::parse(text).expect("vector file parses")
}

/// The I07 ACTIVE configuration (with `policyWriter`) and the policy-kind table.
pub fn config() -> Value {
    parse(I07_VECTORS).get("configs").and_then(|configs| configs.get("ACTIVE")).cloned().expect("ACTIVE")
}

pub fn kinds() -> Value {
    parse(KINDS)
}

pub fn new_gate() -> PolicyGate {
    PolicyGate::new(&config(), &kinds()).expect("the ACTIVE configuration builds a PolicyGate")
}

pub fn object(members: Vec<(&str, Value)>) -> Value {
    let mut object = Object::new();
    for (key, value) in members {
        object.insert(JStr::new(key), value);
    }
    Value::Object(object)
}

pub fn empty() -> Value {
    object(Vec::new())
}

/// WRITE_BEGIN's payload for this generation.
pub fn begin_payload() -> Value {
    object(vec![("expectedGeneration", Value::str(GENERATION))])
}

/// The payload of the first FRAME event with `operation` in I05 v3 transcript T01 (and, for ARM_ACTION, `actionId`).
pub fn t01(operation: &str) -> Value {
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
        .and_then(|events| {
            events.iter().find(|event| {
                event.get("type").and_then(Value::as_str) == Some("FRAME")
                    && event.get("operation").and_then(Value::as_str) == Some(operation)
            })
        })
        .and_then(|event| event.get("payload"))
        .cloned()
        .expect("a T01 payload")
}

/// The I05 vector events of T01 after the frames (BACKLOG, ACCEPT, REQUEST, UPSTREAM_RESPONSE of action 1).
pub fn t01_events() -> Vec<Value> {
    let vectors = parse(I05_VECTORS);
    let transcript = vectors
        .get("transcripts")
        .and_then(Value::as_array)
        .and_then(|rows| rows.iter().find(|row| row.get("id").and_then(Value::as_str) == Some("T01")))
        .cloned()
        .expect("T01");
    transcript.get("events").and_then(Value::as_array).map(<[Value]>::to_vec).expect("events")
}

/// The broker frame a correct broker sends next.
pub fn broker_frame(gate: &PolicyGate, operation: &str, payload: Value) -> Vec<u8> {
    let base = gate.gate();
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

/// The writer frame a correct writer sends next.
pub fn writer_frame(gate: &PolicyGate, operation: &str, payload: Value) -> Vec<u8> {
    let frame = object(vec![
        ("schemaVersion", Value::str(WRITER_FRAME_VERSION)),
        ("challenge", Value::str(WRITER_CHALLENGE)),
        ("sequence", Value::int(gate.writer_next_sequence())),
        ("previousDigest", Value::str(gate.writer_last_digest())),
        ("direction", Value::str("WRITER_TO_GATE")),
        ("operation", Value::str(operation)),
        ("payload", payload),
    ]);
    json::canonical(&frame).expect("canonical")
}

pub fn role_create(write_id: i64) -> Value {
    parse(&format!(
        "{{\"writeId\":{write_id},\"operation\":\"CREATE\",\"resource\":{{\"group\":\"rbac.authorization.k8s.io\",\
         \"version\":\"v1\",\"resource\":\"roles\"}},\"namespace\":\"planeon-qual\",\"name\":\"planeon-role\",\
         \"object\":{{\"apiVersion\":\"rbac.authorization.k8s.io/v1\",\"kind\":\"Role\",\"metadata\":\
         {{\"name\":\"planeon-role\",\"namespace\":\"planeon-qual\"}},\"rules\":[]}},\"prior\":null}}"
    ))
}

// ------------------------------------------------------------------------------------------ file stores

/// Fresh journal and marker directories for one case under cargo's `CARGO_TARGET_TMPDIR`.
pub fn place(case: &str) -> (String, String) {
    let root = format!("{}/he003a/{case}", env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::remove_dir_all(&root);
    let (journal, marker) = (format!("{root}/journal"), format!("{root}/marker"));
    std::fs::create_dir_all(&journal).expect("journal directory");
    std::fs::create_dir_all(&marker).expect("marker directory");
    (journal, marker)
}

/// The test device probe: the two directories share the build host's device, so they report 1 and 2.
pub fn devices(which: StoreDir, _: &gate_sys::Dir) -> std::io::Result<u64> {
    Ok(match which {
        StoreDir::Journal => 1,
        StoreDir::Marker => 2,
    })
}

pub fn stores(journal: &str, marker: &str) -> FileStores {
    FileStores::open(journal, marker, GENERATION, &devices, None).expect("the stores open")
}

// ------------------------------------------------------------------------------------------ the bench

pub type Loop = Substrate<FakeOs, FakeI04, FakeUpstream>;

/// A substrate over a gate with the fakes, and the lab they share.
pub struct Bench {
    pub lab: Shared,
    pub substrate: Loop,
}

impl Bench {
    pub fn new(gate: PolicyGate, lifetimes: Lifetimes) -> Bench {
        Bench::with(gate, lifetimes, lab())
    }

    pub fn with(gate: PolicyGate, lifetimes: Lifetimes, lab: Shared) -> Bench {
        let substrate = Substrate::new(gate, FakeOs(lab.clone()), FakeI04(lab.clone()), FakeUpstream(lab.clone()),
                                       ExpectedPeers::r10(), lifetimes)
            .expect("the substrate starts");
        Bench { lab, substrate }
    }

    pub fn fresh() -> Bench {
        Bench::new(new_gate(), Lifetimes::default())
    }

    pub fn gate(&self) -> &PolicyGate {
        self.substrate.gate()
    }

    /// One wake reporting `ready`, the clocks unchanged.
    pub fn wake(&mut self, ready: Vec<(u64, Readiness)>) -> Result<(), LoopExit> {
        self.wake_with(Wake { ready, ..Wake::default() })
    }

    pub fn wake_with(&mut self, wake: Wake) -> Result<(), LoopExit> {
        self.lab.borrow_mut().wakes.push_back(wake);
        self.substrate.turn()
    }

    /// Queues a connection with `peer` on a listener and wakes the listener; the new connection's number.
    pub fn connect(&mut self, side: Listen, peer: FakePeer) -> u64 {
        let number = {
            let mut lab = self.lab.borrow_mut();
            lab.accepts.entry(side).or_default().push_back(Ok(peer));
            lab.next_conn
        };
        let token = match side {
            Listen::I05 => I05_LISTENER_TOKEN,
            Listen::I07 => I07_LISTENER_TOKEN,
        };
        self.wake(vec![(token, readable())]).expect("the accept wake");
        number
    }

    /// Queues `received` on connection `conn` and wakes its channel's connection token.
    pub fn receive(&mut self, conn: u64, received: Received) -> Result<(), LoopExit> {
        let side = {
            let mut lab = self.lab.borrow_mut();
            let fake = lab.conns.get_mut(&conn).expect("a fake connection");
            fake.inbox.push_back(received);
            fake.side
        };
        let token = match side {
            Listen::I05 => I05_CONN_TOKEN,
            Listen::I07 => I07_CONN_TOKEN,
        };
        self.wake(vec![(token, readable())])
    }

    /// The broker's next frame with `operation` and `payload`, with the broker's control bytes.
    pub fn broker_says(&mut self, conn: u64, operation: &str, payload: Value) -> Result<(), LoopExit> {
        let bytes = broker_frame(self.gate(), operation, payload);
        self.receive(conn, datagram(bytes, broker_control()))
    }

    /// The writer's next frame with `operation` and `payload`, with the writer's control bytes.
    pub fn writer_says(&mut self, conn: u64, operation: &str, payload: Value) -> Result<(), LoopExit> {
        let bytes = writer_frame(self.gate(), operation, payload);
        self.receive(conn, datagram(bytes, writer_control()))
    }

    /// A pidfd wake for a channel.
    pub fn pidfd(&mut self, side: Listen) -> Result<(), LoopExit> {
        let token = match side {
            Listen::I05 => I05_PIDFD_TOKEN,
            Listen::I07 => I07_PIDFD_TOKEN,
        };
        self.wake(vec![(token, readable())])
    }

    /// A held broker connection whose GENERATION_STATUS opened the channel.
    pub fn open_broker(&mut self) -> u64 {
        let conn = self.connect(Listen::I05, broker_peer());
        self.broker_says(conn, "GENERATION_STATUS", empty()).expect("the opening frame");
        assert_eq!(self.sent(conn).len(), 1, "the opening frame is answered");
        conn
    }

    /// A held writer connection with an opened session (MAINTENANCE_STATUS answered).
    pub fn open_writer(&mut self) -> u64 {
        let conn = self.connect(Listen::I07, writer_peer());
        self.writer_says(conn, "MAINTENANCE_STATUS", empty()).expect("the opening writer frame");
        assert_eq!(self.sent(conn).len(), 1, "the opening writer frame is answered");
        conn
    }

    pub fn sent(&self, conn: u64) -> Vec<Vec<u8>> {
        self.lab.borrow().conns.get(&conn).map(|fake| fake.sent.clone()).unwrap_or_default()
    }

    pub fn closed(&self, conn: u64) -> bool {
        self.lab.borrow().conns.get(&conn).is_some_and(|fake| fake.closed)
    }

    pub fn set_peer(&mut self, conn: u64, change: impl FnOnce(&mut FakePeer)) {
        let mut lab = self.lab.borrow_mut();
        change(&mut lab.conns.get_mut(&conn).expect("a fake connection").peer);
    }

    pub fn fail_sends(&mut self, conn: u64) {
        self.lab.borrow_mut().conns.get_mut(&conn).expect("a fake connection").send_ok = false;
    }

    /// Every output either port saw, as canonical JSON text (the I04 port's copy).
    pub fn outputs(&self) -> Vec<String> {
        self.lab.borrow().i04.outputs.clone()
    }

    pub fn last_output(&self) -> String {
        self.outputs().last().cloned().unwrap_or_default()
    }

    /// The journal's records as canonical JSON text.
    pub fn journal(&self) -> Vec<String> {
        let doc = journal_doc(self.gate().gate().journal()).to_value();
        let text = |record: &Value| String::from_utf8_lossy(&json::canonical(record).expect("record")).into_owned();
        doc.as_array().map(|records| records.iter().map(text).collect()).unwrap_or_default()
    }

    pub fn last_record(&self) -> String {
        self.journal().last().cloned().unwrap_or_default()
    }

    pub fn trace(&self) -> Vec<String> {
        self.lab.borrow().trace.clone()
    }

    pub fn clear_trace(&mut self) {
        self.lab.borrow_mut().trace.clear();
    }

    pub fn state(&self) -> &'static str {
        self.gate().gate().state().as_str()
    }
}
