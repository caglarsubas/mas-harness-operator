//! HE-004-I01a DESIGN-I01A sections 5, 6, 7 and 15 (MODEL_DEFINED's HE-004-I01a section): the I01 service over a fake
//! `PeerOps` that answers each operation as scripted and logs every call. Labels are kernel-shaped: SO_PEERSEC,
//! SCM_SECURITY and `attr/current` carry their trailing NUL, the record's label none.
//! - The server identity is the enrolled record's SERVER row (an OBSERVED positive and a LABEL_BOUND one).
//! - Custody runs in its order; an OBSERVED server's `exe` is read and must equal `interpreterPath`; a LABEL_BOUND
//!   server makes no `peer_exe` call; every custody failure closes, the named label negatives among them (one byte off,
//!   a NUL where both should carry it, a doubled NUL, an empty label).
//! - Each message: SCM_CREDENTIALS and SCM_SECURITY against the accept's (exactly), the process unchanged before and after
//!   the read, the receive's other outcomes, and the request checks; a request that does not name the service's
//!   binding closes at the gate, and since HE-004-I01B2 (B3-9 (a), I2D-7) the service holds a `from_config` test binding;
//!   since HE-004-I01B5 (Q-11 (a)) a request naming it waits pending for its answer, nothing sent.
//! - HE-004-I01B5 (DESIGN-I01B5 rev 5 section 4): the wall reading in milliseconds; the exchange deadline in the idle
//!   bound's place while a request is pending; a second datagram while one is pending closes `Pipelined`; no round, a
//!   failed round, a round started before the receipt or a view of another phase is not ready and closes `NotServed` at
//!   the exchange deadline; a ready request whose view is unusable or not current closes `NotServed`, and one whose
//!   process changed `Changed`, each with nothing sent. The answered cases are `observer_i01_send.rs`'s.
//! - The window: a start before `validFrom` (no latch), the `expiresAt - 3 s` cut and its latch, a clock stepped back, no
//!   clock; the idle and outer bounds.
//! - The listener: its two reasons to leave the wait (a session, a backoff), the backoff's deadline, faults, the twelfth
//!   fault in a row fatal and an accept clearing the count; a peer's watch failure.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use i05_protocol::json::{self, Value};
use i05_protocol::sha256;
use planeon_observer::capture_schema::CaptureSchema;
use planeon_observer::client::{AcceptResult, Availability, CaptureGate, ExeLink, Passed, PeerCreds, PeerId, PeerOps, PeerOutcome,
                               PeerPlan, PeerReady, PeerRecv, PeerSent, PeerService, PeerWatch, ProcIdentity, Ready, Round,
                               SnapshotView, LISTENER_BACKOFF};
use planeon_observer::enrolled::{record_form, Enrolled, RecordBytes, ServerClass, ServerIdentity};
use planeon_observer::i01_request::{I01Binding, RequestRefusal, ZERO_DIGEST};
use planeon_observer::i01_service::{Closed, I01Service, I01_EXCHANGE_DEADLINE, IDLE_BOUND, OUTER_BOUND};
use planeon_observer::kernel_text;

const VECTORS: &str = include_str!("../../../contracts/native-profile-v4/vectors.json");
const LABEL: &str = "system_u:system_r:planeon_server_t:s0";
const INTERPRETER: &str = "/opt/planeon/python/3.12.14/bin/python3.12";
const CGROUP_REL: &str = "planeon.slice/planeon-proxy-server.service";
const CGROUP: &[u8] = b"0::/planeon.slice/planeon-proxy-server.service\n";
const VALID_FROM: u64 = 1_000_000;
const EXPIRES_AT: u64 = 1_000_600;
/// The wire's wall reading, in milliseconds since HE-004-I01B5.
const WALL: Option<u64> = Some(1_000_100_000);
const READY: Ready = Ready { readable: true, writable: false, error: false, hangup: false };
const PEER: PeerId = PeerId(1);

/// A label as the kernel delivers it: its bytes and one trailing NUL.
fn kernel(label: &str) -> Vec<u8> {
    [label.as_bytes(), b"\0".as_slice()].concat()
}

fn server(class: ServerClass) -> ServerIdentity {
    ServerIdentity { uid: 0, gid: 0, process_label: LABEL.to_string(), cgroup_rel: CGROUP_REL.to_string(), class,
                     interpreter: INTERPRETER.to_string(), valid_from: VALID_FROM, expires_at: EXPIRES_AT }
}

fn process() -> ProcIdentity {
    ProcIdentity { start_time: 4_242, cgroup: CGROUP.to_vec(), label: kernel(LABEL) }
}

/// The scripted peer side: each operation's answer (queues first, then the default), every call, and the closes.
struct FakePeer {
    accepts: VecDeque<AcceptResult>,
    creds: Result<PeerCreds, i32>,
    proc_open: Result<(), i32>,
    alive: VecDeque<bool>,
    reads: VecDeque<Result<ProcIdentity, i32>>,
    read: Result<ProcIdentity, i32>,
    exe: Result<ExeLink, i32>,
    recvs: VecDeque<(Vec<u8>, PeerRecv)>,
    calls: Vec<&'static str>,
    closed: Vec<PeerId>,
    /// HE-004-I01B5: the bytes handed to `peer_send`, and its answer.
    sent: Vec<Vec<u8>>,
    send: PeerSent,
}

impl FakePeer {
    fn good() -> FakePeer {
        FakePeer {
            accepts: VecDeque::from([AcceptResult::Peer(PEER)]),
            creds: Ok(PeerCreds { pid: 812, uid: 0, gid: 0, label: kernel(LABEL) }),
            proc_open: Ok(()),
            alive: VecDeque::new(),
            reads: VecDeque::new(),
            read: Ok(process()),
            exe: Ok(ExeLink(INTERPRETER.as_bytes().to_vec())),
            recvs: VecDeque::new(),
            calls: Vec::new(),
            closed: Vec::new(),
            sent: Vec::new(),
            send: PeerSent::Sent,
        }
    }
}

impl PeerOps for FakePeer {
    fn accept_peer(&mut self) -> AcceptResult {
        self.calls.push("accept");
        self.accepts.pop_front().unwrap_or(AcceptResult::Nothing)
    }

    fn peer_creds(&mut self, _peer: PeerId) -> Result<PeerCreds, i32> {
        self.calls.push("creds");
        self.creds.clone()
    }

    fn peer_proc_open(&mut self, _peer: PeerId) -> Result<(), i32> {
        self.calls.push("proc_open");
        self.proc_open
    }

    fn peer_proc_read(&mut self, _peer: PeerId) -> Result<ProcIdentity, i32> {
        self.calls.push("proc_read");
        let queued = self.reads.pop_front();
        queued.unwrap_or_else(|| self.read.clone())
    }

    fn peer_exe(&mut self, _peer: PeerId) -> Result<ExeLink, i32> {
        self.calls.push("exe");
        self.exe.clone()
    }

    fn peer_alive(&mut self, _peer: PeerId) -> bool {
        self.calls.push("alive");
        self.alive.pop_front().unwrap_or(true)
    }

    fn peer_recv(&mut self, _peer: PeerId, buffer: &mut [u8]) -> PeerRecv {
        self.calls.push("recv");
        let Some((bytes, answer)) = self.recvs.pop_front() else { return PeerRecv::WouldBlock };
        buffer[..bytes.len()].copy_from_slice(&bytes);
        answer
    }

    fn peer_close(&mut self, peer: PeerId) {
        self.calls.push("close");
        self.closed.push(peer);
    }

    fn peer_send(&mut self, _peer: PeerId, bytes: &[u8]) -> PeerSent {
        self.calls.push("send");
        self.sent.push(bytes.to_vec());
        self.send
    }
}

/// A canonical first request naming `digest` and the nonce `run-1`.
fn request_naming(digest: &str) -> Vec<u8> {
    format!("{{\"bindingDigest\":\"{digest}\",\"challenge\":\"{}\",\"operation\":\"OBSERVE_POLICY\",\
             \"previousObservationDigest\":\"{ZERO_DIGEST}\",\"runNonce\":\"run-1\",\
             \"schemaVersion\":\"planeon.internal.policy-observation-request/v1\",\"sequence\":1}}", "2".repeat(64))
        .into_bytes()
}

/// A canonical first request naming a binding no test document gives (its digest is all ones).
fn first_request() -> Vec<u8> {
    request_naming(&format!("sha256:{}", "1".repeat(64)))
}

/// The service's binding (HE-004-I01B2, B3-9 (a), I2D-7): `I01Binding::from_config` over a test binding document whose
/// `scope.runNonce` is `run-1`.
fn test_binding() -> I01Binding {
    let document = json::parse("{\"schemaVersion\":\"planeon.internal.policy-observation-binding/v1\",\
                                \"scope\":{\"runNonce\":\"run-1\",\"tenantId\":\"unit-tenant\"}}")
        .expect("a test binding document");
    I01Binding::from_config(&document).expect("the test document has a digest and a nonce")
}

/// A datagram of `bytes` with the accept's credentials and label, as the kernel delivers them.
fn datagram(bytes: &[u8]) -> (Vec<u8>, PeerRecv) {
    (bytes.to_vec(), PeerRecv::Data { length: bytes.len(), pid: 812, uid: 0, gid: 0, security: kernel(LABEL) })
}

/// A service and its fake after one accept at `WALL`.
fn accepted(class: ServerClass, change: impl FnOnce(&mut FakePeer)) -> (I01Service, FakePeer, Instant) {
    let mut service = I01Service::new(server(class), test_binding());
    let mut ops = FakePeer::good();
    change(&mut ops);
    let now = Instant::now();
    assert_eq!(service.serve_peer_step(&mut ops, WALL, now, PeerReady::Listener(READY)), PeerOutcome::Served);
    (service, ops, now)
}

fn enrolled(index: usize) -> Enrolled {
    let vectors = json::parse(VECTORS).expect("the vendored vectors parse");
    let record = vectors.get("positive").and_then(Value::as_array).expect("positives")[index].get("record").expect("a record").clone();
    let bytes = json::canonical(&record).expect("a canonical encoding");
    let value = record_form(&bytes).expect("a canonical record");
    let (_, schema) = CaptureSchema::embedded().expect("the embedded schema");
    let now = kernel_text::utc_seconds("2026-09-08T00:00:00Z");
    Enrolled::new(RecordBytes { pin: sha256::prefixed(&bytes), bytes, value }, &schema, now).expect("the positive enrolls")
}

#[test]
fn the_server_identity_is_the_record_s_server_row() {
    let from = kernel_text::utc_seconds("2026-09-08T00:00:00Z").expect("UTC");
    assert_eq!(enrolled(0).server_identity(), Ok(ServerIdentity { valid_from: from, expires_at: from + 600,
                                                                    ..server(ServerClass::Observed) }));
    // The positive whose SERVER capabilities hold CAP_NET_BIND_SERVICE is LABEL_BOUND.
    assert_eq!(enrolled(4).server_identity().map(|identity| identity.class), Ok(ServerClass::LabelBound));
    assert_eq!((IDLE_BOUND, OUTER_BOUND), (Duration::from_secs(2), Duration::from_secs(900)));
}

#[test]
fn an_observed_server_passes_custody_in_order_and_its_session_is_watched() {
    let (service, ops, now) = accepted(ServerClass::Observed, |_| {});
    assert!(service.session_open());
    assert_eq!(ops.calls, ["accept", "creds", "proc_open", "alive", "proc_read", "exe"]);
    assert_eq!(service.peer_plan(now), PeerPlan { watch: PeerWatch { listener: false, peer: Some(PEER) },
                                                  deadline: Some(now + IDLE_BOUND) });
    // A SO_PEERSEC without its NUL still matches the record's label (one trailing NUL is stripped when present).
    let (service, _, _) = accepted(ServerClass::Observed, |ops| ops.creds = Ok(PeerCreds { pid: 812, uid: 0, gid: 0,
                                                                                           label: LABEL.as_bytes().to_vec() }));
    assert!(service.session_open());
}

#[test]
fn a_label_bound_server_makes_no_exe_call() {
    let (service, ops, _) = accepted(ServerClass::LabelBound, |ops| ops.exe = Err(13));
    assert!(service.session_open(), "the failing exe read is never made");
    assert_eq!(ops.calls, ["accept", "creds", "proc_open", "alive", "proc_read"]);
    assert!(!ops.calls.contains(&"exe"));
}

#[test]
fn every_custody_failure_closes() {
    let cases: Vec<(ServerClass, Box<dyn Fn(&mut FakePeer)>)> = vec![
        (ServerClass::Observed, Box::new(|ops| ops.creds = Err(107))),
        (ServerClass::Observed, Box::new(|ops| ops.creds = Ok(PeerCreds { pid: 812, uid: 1, gid: 0, label: kernel(LABEL) }))),
        (ServerClass::Observed, Box::new(|ops| ops.creds = Ok(PeerCreds { pid: 812, uid: 0, gid: 1, label: kernel(LABEL) }))),
        (ServerClass::Observed, Box::new(|ops| ops.creds = Ok(PeerCreds { pid: 0, uid: 0, gid: 0, label: kernel(LABEL) }))),
        // The named label negatives: one byte off, a doubled NUL, an empty label.
        (ServerClass::Observed, Box::new(|ops| ops.creds = Ok(PeerCreds { pid: 812, uid: 0, gid: 0,
                                                                          label: kernel("system_u:system_r:planeon_server_t:s1") }))),
        (ServerClass::Observed, Box::new(|ops| ops.creds = Ok(PeerCreds { pid: 812, uid: 0, gid: 0,
                                                                          label: [kernel(LABEL), vec![0]].concat() }))),
        (ServerClass::Observed, Box::new(|ops| ops.creds = Ok(PeerCreds { pid: 812, uid: 0, gid: 0, label: Vec::new() }))),
        (ServerClass::Observed, Box::new(|ops| ops.proc_open = Err(3))),
        (ServerClass::Observed, Box::new(|ops| ops.alive = VecDeque::from([false]))),
        (ServerClass::Observed, Box::new(|ops| ops.read = Err(3))),
        (ServerClass::Observed, Box::new(|ops| ops.read = Ok(ProcIdentity { cgroup: b"0::/planeon.slice/other.service\n".to_vec(), ..process() }))),
        (ServerClass::Observed, Box::new(|ops| ops.read = Ok(ProcIdentity { cgroup: [CGROUP, b"1:name=x:/\n".as_slice()].concat(), ..process() }))),
        (ServerClass::Observed, Box::new(|ops| ops.read = Ok(ProcIdentity { label: kernel("system_u:system_r:planeon_worker_t:s0"), ..process() }))),
        (ServerClass::Observed, Box::new(|ops| ops.read = Ok(ProcIdentity { label: [kernel(LABEL), vec![0]].concat(), ..process() }))),
        // The exe rule: a deleted image, another path, a failed read.
        (ServerClass::Observed, Box::new(|ops| ops.exe = Ok(ExeLink([INTERPRETER, " (deleted)"].concat().into_bytes())))),
        (ServerClass::Observed, Box::new(|ops| ops.exe = Ok(ExeLink(b"/usr/bin/python3".to_vec())))),
        (ServerClass::Observed, Box::new(|ops| ops.exe = Err(13))),
        (ServerClass::LabelBound, Box::new(|ops| ops.creds = Ok(PeerCreds { pid: 812, uid: 0, gid: 0, label: Vec::new() }))),
        (ServerClass::LabelBound, Box::new(|ops| ops.alive = VecDeque::from([false]))),
    ];
    for (index, (class, change)) in cases.iter().enumerate() {
        let (service, ops, _) = accepted(*class, |ops| change(ops));
        assert!(!service.session_open(), "case {index}");
        assert_eq!(service.last_closed(), Some(Closed::Custody), "case {index}");
        assert_eq!(ops.closed, [PEER], "case {index}");
    }
}

#[test]
fn a_request_is_read_with_its_message_custody_and_closes_at_a_binding_it_does_not_name() {
    let (mut service, mut ops, now) = accepted(ServerClass::Observed, |_| {});
    ops.calls.clear();
    ops.recvs.push_back(datagram(&first_request()));
    assert_eq!(service.serve_peer_step(&mut ops, WALL, now, PeerReady::Peer(PEER, READY)), PeerOutcome::Served);
    assert_eq!(ops.calls, ["alive", "proc_read", "recv", "alive", "proc_read", "close"]);
    assert_eq!(service.last_closed(), Some(Closed::Request(RequestRefusal::Binding)));
    assert!(!service.session_open());
    // HE-004-I01B2 (I2D-7), its NotAnswered case rewritten for HE-004-I01B5 (Q-11 (a)): a request naming the service's
    // binding (its digest and nonce) passes the checks and the gate and waits for its answer, pending with its receipt,
    // with the same calls and no close; nothing is sent.
    let (mut service, mut ops, now) = accepted(ServerClass::Observed, |_| {});
    ops.calls.clear();
    ops.recvs.push_back(datagram(&request_naming(test_binding().signed_digest())));
    assert_eq!(service.serve_peer_step(&mut ops, WALL, now, PeerReady::Peer(PEER, READY)), PeerOutcome::Served);
    assert_eq!(ops.calls, ["alive", "proc_read", "recv", "alive", "proc_read"]);
    assert_eq!((service.last_closed(), service.session_open(), service.peer_pending()), (None, true, Some(now)));
    assert!(ops.closed.is_empty() && ops.sent.is_empty());
    // Nothing queued keeps the session; a step for another peer is not this session's.
    let (mut service, mut ops, now) = accepted(ServerClass::Observed, |_| {});
    service.serve_peer_step(&mut ops, WALL, now, PeerReady::Peer(PEER, READY));
    service.serve_peer_step(&mut ops, WALL, now, PeerReady::Peer(PeerId(9), READY));
    assert!(service.session_open());
}

#[test]
fn each_message_must_carry_the_accept_s_credentials_and_label_exactly() {
    let request = first_request();
    let length = request.len();
    let data = |pid: i32, uid: u32, gid: u32, security: Vec<u8>| (request.clone(), PeerRecv::Data { length, pid, uid, gid, security });
    // SCM_SECURITY is compared with SO_PEERSEC's bytes exactly: one byte off, without its NUL, a doubled NUL.
    for (index, message) in [data(813, 0, 0, kernel(LABEL)), data(812, 1, 0, kernel(LABEL)), data(812, 0, 1, kernel(LABEL)),
                             data(812, 0, 0, kernel("system_u:system_r:planeon_server_t:s1")),
                             data(812, 0, 0, LABEL.as_bytes().to_vec()), data(812, 0, 0, [kernel(LABEL), vec![0]].concat())]
        .into_iter()
        .enumerate()
    {
        let (mut service, mut ops, now) = accepted(ServerClass::Observed, |_| {});
        ops.recvs.push_back(message);
        service.serve_peer_step(&mut ops, WALL, now, PeerReady::Peer(PEER, READY));
        assert_eq!(service.last_closed(), Some(Closed::Credentials), "case {index}");
    }
    // A SO_PEERSEC without its NUL (accepted at the accept) against the kernel's SCM_SECURITY, which carries it.
    let (mut service, mut ops, now) = accepted(ServerClass::Observed, |ops| {
        ops.creds = Ok(PeerCreds { pid: 812, uid: 0, gid: 0, label: LABEL.as_bytes().to_vec() })
    });
    ops.recvs.push_back(datagram(&request));
    service.serve_peer_step(&mut ops, WALL, now, PeerReady::Peer(PEER, READY));
    assert_eq!(service.last_closed(), Some(Closed::Credentials));
    // The receive's other outcomes: cut short, other ancillary data (a passed descriptor among them), the end, an error.
    for answer in [PeerRecv::Truncated, PeerRecv::Ancillary, PeerRecv::Eof, PeerRecv::Failed(104)] {
        let (mut service, mut ops, now) = accepted(ServerClass::Observed, |_| {});
        ops.recvs.push_back((Vec::new(), answer.clone()));
        service.serve_peer_step(&mut ops, WALL, now, PeerReady::Peer(PEER, READY));
        assert_eq!(service.last_closed(), Some(Closed::Receive), "{answer:?}");
    }
}

#[test]
fn the_process_must_stay_the_accepted_one_before_and_after_each_read() {
    let changed = [ProcIdentity { start_time: 4_243, ..process() },
                   ProcIdentity { cgroup: b"0::/planeon.slice/other.service\n".to_vec(), ..process() },
                   ProcIdentity { label: kernel("system_u:system_r:planeon_worker_t:s0"), ..process() }];
    for identity in &changed {
        // Before the read.
        let (mut service, mut ops, now) = accepted(ServerClass::Observed, |_| {});
        ops.reads.push_back(Ok(identity.clone()));
        ops.recvs.push_back(datagram(&first_request()));
        service.serve_peer_step(&mut ops, WALL, now, PeerReady::Peer(PEER, READY));
        assert_eq!(service.last_closed(), Some(Closed::Changed));
        assert_eq!(ops.recvs.len(), 1, "nothing was read");
        // After the read.
        let (mut service, mut ops, now) = accepted(ServerClass::Observed, |_| {});
        ops.reads.extend([Ok(process()), Ok(identity.clone())]);
        ops.recvs.push_back(datagram(&first_request()));
        service.serve_peer_step(&mut ops, WALL, now, PeerReady::Peer(PEER, READY));
        assert_eq!(service.last_closed(), Some(Closed::Changed));
    }
    // The pidfd showing an exit, before the read.
    let (mut service, mut ops, now) = accepted(ServerClass::Observed, |_| {});
    ops.alive.push_back(false);
    service.serve_peer_step(&mut ops, WALL, now, PeerReady::Peer(PEER, READY));
    assert_eq!(service.last_closed(), Some(Closed::Changed));
}

#[test]
fn a_refused_request_closes_with_its_step() {
    for (bytes, refusal) in [(vec![b'{'; 16_385], RequestRefusal::Size), (b"{\"a\": 1}".to_vec(), RequestRefusal::Canonical),
                             (b"{\"a\":1}".to_vec(), RequestRefusal::Schema("a request holds exactly its seven members"))] {
        let (mut service, mut ops, now) = accepted(ServerClass::Observed, |_| {});
        ops.recvs.push_back(datagram(&bytes));
        service.serve_peer_step(&mut ops, WALL, now, PeerReady::Peer(PEER, READY));
        assert_eq!(service.last_closed(), Some(Closed::Request(refusal)));
    }
}

#[test]
fn the_record_s_window_bounds_every_session() {
    // Before validFrom: closed, no latch; a later accept inside the window opens a session.
    let mut service = I01Service::new(server(ServerClass::Observed), test_binding());
    let mut ops = FakePeer::good();
    ops.accepts.push_back(AcceptResult::Peer(PeerId(2)));
    let now = Instant::now();
    service.serve_peer_step(&mut ops, Some((VALID_FROM - 1) * 1_000), now, PeerReady::Listener(READY));
    assert_eq!((service.last_closed(), service.latched(), service.session_open()), (Some(Closed::Window), false, false));
    service.serve_peer_step(&mut ops, Some(VALID_FROM * 1_000), now, PeerReady::Listener(READY));
    assert!(service.session_open());
    // No wall clock: closed without a latch.
    let mut service = I01Service::new(server(ServerClass::Observed), test_binding());
    let mut ops = FakePeer::good();
    service.serve_peer_step(&mut ops, None, now, PeerReady::Listener(READY));
    assert_eq!((service.last_closed(), service.latched()), (Some(Closed::Window), false));
    // From expiresAt - 3 s: closed and latched; a clock stepped back stays latched.
    let mut service = I01Service::new(server(ServerClass::Observed), test_binding());
    let mut ops = FakePeer::good();
    ops.accepts.push_back(AcceptResult::Peer(PeerId(2)));
    service.serve_peer_step(&mut ops, Some((EXPIRES_AT - 3) * 1_000), now, PeerReady::Listener(READY));
    assert_eq!((service.last_closed(), service.latched()), (Some(Closed::Window), true));
    service.serve_peer_step(&mut ops, WALL, now, PeerReady::Listener(READY));
    assert_eq!((service.last_closed(), service.latched(), service.session_open()), (Some(Closed::Window), true, false));
    assert_eq!(service.accepted(), 2);
    // One second earlier is still inside.
    let (service, _, _) = accepted(ServerClass::Observed, |_| {});
    assert!(service.session_open());
    let mut inside = I01Service::new(server(ServerClass::Observed), test_binding());
    inside.serve_peer_step(&mut FakePeer::good(), Some((EXPIRES_AT - 4) * 1_000), now, PeerReady::Listener(READY));
    assert!(inside.session_open() && !inside.latched());
    // An open session is cut at the next deadline call or read once the cut comes, and the latch holds.
    let (mut service, mut ops, now) = accepted(ServerClass::Observed, |_| {});
    service.serve_peer_deadlines(&mut ops, Some((EXPIRES_AT - 3) * 1_000), now);
    assert_eq!((service.last_closed(), service.latched(), service.session_open()), (Some(Closed::Window), true, false));
    let (mut service, mut ops, now) = accepted(ServerClass::Observed, |_| {});
    ops.recvs.push_back(datagram(&first_request()));
    service.serve_peer_step(&mut ops, Some(EXPIRES_AT * 1_000), now, PeerReady::Peer(PEER, READY));
    assert_eq!((service.last_closed(), service.latched()), (Some(Closed::Window), true));
    assert_eq!(ops.recvs.len(), 1, "nothing was read");
}

#[test]
fn the_idle_and_outer_bounds_cut_a_session() {
    let (mut service, mut ops, now) = accepted(ServerClass::Observed, |_| {});
    service.serve_peer_deadlines(&mut ops, WALL, now + IDLE_BOUND - Duration::from_millis(1));
    assert!(service.session_open());
    service.serve_peer_deadlines(&mut ops, WALL, now + IDLE_BOUND);
    assert_eq!((service.last_closed(), service.session_open()), (Some(Closed::Bound), false));
    let (mut service, mut ops, now) = accepted(ServerClass::Observed, |_| {});
    service.serve_peer_deadlines(&mut ops, WALL, now + OUTER_BOUND);
    assert_eq!(service.last_closed(), Some(Closed::Bound));
}

#[test]
fn the_listener_leaves_the_wait_for_a_session_or_a_backoff_and_faults_escalate() {
    let mut service = I01Service::new(server(ServerClass::Observed), test_binding());
    let now = Instant::now();
    assert_eq!(service.peer_plan(now), PeerPlan { watch: PeerWatch { listener: true, peer: None }, deadline: None });
    // A fault: EPOLLERR, a failed watch or an accept error takes the listener out of the wait for 5 s.
    let mut ops = FakePeer::good();
    let error = Ready { readable: false, writable: false, error: true, hangup: false };
    assert_eq!(service.serve_peer_step(&mut ops, WALL, now, PeerReady::Listener(error)), PeerOutcome::Served);
    assert_eq!(service.peer_plan(now), PeerPlan { watch: PeerWatch { listener: false, peer: None },
                                                  deadline: Some(now + LISTENER_BACKOFF) });
    // While backing off a listener readiness accepts nothing; at the deadline the listener returns.
    service.serve_peer_step(&mut ops, WALL, now, PeerReady::Listener(READY));
    assert!(ops.calls.is_empty());
    service.serve_peer_deadlines(&mut ops, WALL, now + LISTENER_BACKOFF);
    assert!(service.peer_plan(now).watch.listener);
    // Eleven more faults in a row (ten, then the eleventh after an accept error) leave it running; the twelfth is fatal.
    let mut at = now + LISTENER_BACKOFF;
    for count in 2..=11u32 {
        let ready = if count % 2 == 0 { PeerReady::ListenerFault } else { PeerReady::Listener(Ready { hangup: true, ..READY }) };
        assert_eq!(service.serve_peer_step(&mut ops, WALL, at, ready), PeerOutcome::Served, "fault {count}");
        at += LISTENER_BACKOFF;
        service.serve_peer_deadlines(&mut ops, WALL, at);
    }
    assert_eq!(service.faults(), 11);
    let mut failing = FakePeer::good();
    failing.accepts = VecDeque::from([AcceptResult::Fault(24)]);
    assert_eq!(service.serve_peer_step(&mut failing, WALL, at, PeerReady::Listener(READY)), PeerOutcome::ListenerFailed);
    // An accept between faults clears the count; the session then keeps the listener out of the wait.
    let mut service = I01Service::new(server(ServerClass::Observed), test_binding());
    let mut ops = FakePeer::good();
    for _ in 0..11 {
        service.serve_peer_step(&mut ops, WALL, now, PeerReady::ListenerFault);
        service.serve_peer_deadlines(&mut ops, WALL, now + LISTENER_BACKOFF);
    }
    assert_eq!(service.faults(), 11);
    service.serve_peer_step(&mut ops, WALL, now, PeerReady::Listener(READY));
    assert_eq!((service.faults(), service.session_open()), (0, true));
    assert_eq!(service.peer_plan(now).watch, PeerWatch { listener: false, peer: Some(PEER) });
    // A failed watch of the session's peer closes it (never status 95).
    service.serve_peer_step(&mut ops, WALL, now, PeerReady::PeerFault(PEER));
    assert_eq!((service.last_closed(), service.session_open()), (Some(Closed::Watch), false));
    assert!(service.peer_plan(now).watch.listener);
}

// ------------------------------------------------------------------------------------------------ HE-004-I01B5

/// The text of a snapshot view these tests leave unusable (derive's result is the answer file's).
const VIEW_REFUSAL: &str = "a view the tests leave unusable";

/// The epoch's three pushes: the snapshot view of `phase` (unusable), an availability of `availability_phase` with
/// `round`, established and fresh unless `established` says otherwise, and a capture set.
fn views(service: &mut I01Service, phase: u64, availability_phase: u64, round: Option<Round>, established: bool, at: Instant) {
    service.peer_snapshot_view(SnapshotView { phase, mark: 7, fresh_stamp: at, derived: Err(VIEW_REFUSAL) });
    service.peer_availability(Availability { phase: availability_phase, established, fresh: true, round });
    service.peer_capture_view(CaptureGate { scheduled: Some(at), set_started_ms: 0, slots: Vec::new(),
                                            record_digest: String::new(), expired: false });
}

fn passed_at(started: Instant) -> Option<Round> {
    Some(Round::Passed(Passed { started, mark: 7, stamp: started }))
}

/// A session whose request naming the binding passed `after` its accept and waits pending.
fn pending(after: Duration) -> (I01Service, FakePeer, Instant, Instant) {
    let (mut service, mut ops, now) = accepted(ServerClass::Observed, |_| {});
    ops.recvs.push_back(datagram(&request_naming(test_binding().signed_digest())));
    let received = now + after;
    service.serve_peer_step(&mut ops, WALL, received, PeerReady::Peer(PEER, READY));
    assert_eq!((service.peer_pending(), service.session_open()), (Some(received), true));
    (service, ops, now, received)
}

#[test]
fn the_exchange_deadline_replaces_the_idle_bound_while_a_request_is_pending() {
    assert_eq!(I01_EXCHANGE_DEADLINE, Duration::from_secs(2));
    let (mut service, mut ops, now, received) = pending(Duration::from_millis(500));
    // The plan's deadline is the receipt plus 2 s, not the accept's idle bound.
    assert_eq!(service.peer_plan(received).deadline, Some(received + I01_EXCHANGE_DEADLINE));
    // At the accept's idle bound, the receipt plus 1.5 s, the session stays open.
    assert_eq!(now + IDLE_BOUND, received + Duration::from_millis(1_500));
    service.serve_peer_deadlines(&mut ops, WALL, now + IDLE_BOUND);
    assert!(service.session_open());
    // At the receipt plus 2 s it closes, not served, nothing sent.
    service.serve_peer_deadlines(&mut ops, WALL, received + I01_EXCHANGE_DEADLINE);
    assert_eq!((service.last_closed(), service.session_open()), (Some(Closed::NotServed), false));
    assert!(ops.sent.is_empty());
}

#[test]
fn a_second_datagram_while_a_request_is_pending_closes_pipelined() {
    for second in [request_naming(test_binding().signed_digest()), first_request()] {
        let (mut service, mut ops, _, received) = pending(Duration::from_millis(100));
        ops.recvs.push_back(datagram(&second));
        service.serve_peer_step(&mut ops, WALL, received + Duration::from_millis(10), PeerReady::Peer(PEER, READY));
        assert_eq!((service.last_closed(), service.session_open()), (Some(Closed::Pipelined), false));
        assert!(ops.sent.is_empty());
    }
}

#[test]
fn no_round_a_failed_round_an_earlier_round_or_another_phase_is_not_ready() {
    // No round; a failed round; a round started 1 ms before the receipt; a passed round in another phase than the view's.
    for index in 0..4 {
        let (mut service, mut ops, _, received) = pending(Duration::from_millis(100));
        let (round, availability_phase) = match index {
            0 => (None, 1),
            1 => (Some(Round::Failed), 1),
            2 => (passed_at(received - Duration::from_millis(1)), 1),
            _ => (passed_at(received), 2),
        };
        views(&mut service, 1, availability_phase, round, true, received);
        // Not ready: the plan keeps the exchange deadline, and a deadline call before it answers nothing.
        assert_eq!(service.peer_plan(received).deadline, Some(received + I01_EXCHANGE_DEADLINE), "case {index}");
        service.serve_peer_deadlines(&mut ops, WALL, received + Duration::from_millis(100));
        assert!(service.session_open(), "case {index}");
        service.serve_peer_deadlines(&mut ops, WALL, received + I01_EXCHANGE_DEADLINE);
        assert_eq!(service.last_closed(), Some(Closed::NotServed), "case {index}");
        assert!(ops.sent.is_empty(), "case {index}");
    }
}

#[test]
fn a_ready_request_with_an_unusable_or_stale_view_or_a_changed_process_closes_with_nothing_sent() {
    // derive's refusal, and an availability whose streams are not established: ready, then not served.
    for established in [true, false] {
        let (mut service, mut ops, _, received) = pending(Duration::from_millis(100));
        views(&mut service, 1, 1, passed_at(received), established, received);
        let at = received + Duration::from_millis(100);
        assert_eq!(service.peer_plan(at).deadline, Some(at), "ready: the plan wakes at once");
        service.serve_peer_deadlines(&mut ops, WALL, at);
        assert_eq!((service.last_closed(), service.session_open()), (Some(Closed::NotServed), false));
        assert!(ops.sent.is_empty() && !ops.calls.contains(&"send"));
    }
    // The process changed between the request and its answer (I5D-15): Changed.
    let (mut service, mut ops, _, received) = pending(Duration::from_millis(100));
    views(&mut service, 1, 1, passed_at(received), true, received);
    ops.alive.push_back(false);
    service.serve_peer_deadlines(&mut ops, WALL, received + Duration::from_millis(100));
    assert_eq!(service.last_closed(), Some(Closed::Changed));
    assert!(ops.sent.is_empty());
}
