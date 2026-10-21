//! HE-004-I01a DESIGN-I01A sections 4, 5 and 15 (MODEL_DEFINED's HE-004-I01a section): the client's one wire wait with
//! an I01 service attached, over a scripted wire and a recording service. Without a service the wait watches no I01
//! descriptor and keeps its deadline; with one it watches what the service names and ends no later than the service's
//! earliest deadline; each ready I01 descriptor of a wake is one `serve_peer_step` and the deadlines one call per wake;
//! a fatal listener step ends the wait, which the client names. Then the listener's backoff (5 s, the twelfth fault in
//! a row fatal, an accept clearing the count) and the datagram's control rule (exactly one SCM_CREDENTIALS and one
//! SCM_SECURITY; a passed descriptor, a missing or repeated message, another level or a cut-short buffer refused).
//! Unit U4: the HE-004C rig's healthy epoch with the I01 service attached (as `observe::run` attaches it) and no peer
//! ends as without it.

mod b1_rbac_support;
mod b1_support;
mod c_support;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::{Duration, Instant};

use c_support::{observer_tls, shared_pki, Rig};
use gate_sys::inet::{InetAddress, IpLiteral};
use planeon_observer::client::{AcceptResult, Client, ConnId, Connecting, ExeLink, Interest, ListenerBackoff, PeerCreds, PeerId,
                               PeerOps, PeerOutcome, PeerPlan, PeerReady, PeerRecv, PeerService, PeerWatch, PollError,
                               ProcIdentity, Ready, Transfer, Wire, Woken, LISTENER_BACKOFF, LISTENER_FAULT_LIMIT};
use planeon_observer::enrolled::{ServerClass, ServerIdentity};
use planeon_observer::i01_service::I01Service;
use planeon_observer::observe::ObserverExit;

const ADDRESS: InetAddress = InetAddress { ip: IpLiteral::V4([127, 0, 0, 1]), port: 6443 };

fn secs(count: u64) -> Duration {
    Duration::from_secs(count)
}

/// The scripted wire's state: a fake clock, each wait's I01 watch and deadline, the wakes it answers, the accepts.
struct Script {
    base: Instant,
    elapsed: Duration,
    waits: Vec<(PeerWatch, Duration)>,
    wakes: VecDeque<Woken>,
    accepts: u32,
}

#[derive(Clone)]
struct ScriptWire(Rc<RefCell<Script>>);

impl ScriptWire {
    fn new() -> ScriptWire {
        ScriptWire(Rc::new(RefCell::new(Script { base: Instant::now(), elapsed: Duration::ZERO, waits: Vec::new(),
                                                  wakes: VecDeque::new(), accepts: 0 })))
    }

    fn base(&self) -> Instant {
        self.0.borrow().base
    }
}

impl Wire for ScriptWire {
    fn connect(&mut self, _address: &InetAddress) -> Result<(ConnId, Connecting), i32> {
        Err(111)
    }

    fn connect_result(&mut self, _conn: ConnId) -> Result<(), i32> {
        Err(9)
    }

    fn recv(&mut self, _conn: ConnId, _buffer: &mut [u8]) -> Transfer {
        Transfer::Failed(9)
    }

    fn send(&mut self, _conn: ConnId, _bytes: &[u8]) -> Transfer {
        Transfer::Failed(9)
    }

    fn shutdown_write(&mut self, _conn: ConnId) -> bool {
        false
    }

    fn close(&mut self, _conn: ConnId) {}

    fn wait(&mut self, _interests: &[(ConnId, Interest)], peers: PeerWatch, until: Instant) -> Result<Woken, PollError> {
        let mut script = self.0.borrow_mut();
        let at = until.saturating_duration_since(script.base);
        script.waits.push((peers, at));
        script.elapsed = script.elapsed.max(at);
        Ok(script.wakes.pop_front().unwrap_or_default())
    }

    fn now(&self) -> Instant {
        let script = self.0.borrow();
        script.base + script.elapsed
    }

    fn wall_seconds(&self) -> Option<u64> {
        Some(1_000 + self.0.borrow().elapsed.as_secs())
    }
}

impl PeerOps for ScriptWire {
    fn accept_peer(&mut self) -> AcceptResult {
        self.0.borrow_mut().accepts += 1;
        AcceptResult::Nothing
    }

    fn peer_creds(&mut self, _peer: PeerId) -> Result<PeerCreds, i32> {
        Err(9)
    }

    fn peer_proc_open(&mut self, _peer: PeerId) -> Result<(), i32> {
        Err(9)
    }

    fn peer_proc_read(&mut self, _peer: PeerId) -> Result<ProcIdentity, i32> {
        Err(9)
    }

    fn peer_exe(&mut self, _peer: PeerId) -> Result<ExeLink, i32> {
        Err(9)
    }

    fn peer_alive(&mut self, _peer: PeerId) -> bool {
        false
    }

    fn peer_recv(&mut self, _peer: PeerId, _buffer: &mut [u8]) -> PeerRecv {
        PeerRecv::Failed(9)
    }

    fn peer_close(&mut self, _peer: PeerId) {}
}

/// What the recording service saw: each step with its wall second, and the deadline calls.
#[derive(Default)]
struct Calls {
    steps: Vec<(PeerReady, Option<u64>)>,
    deadlines: u32,
}

/// A service that names `watch`, wants a wake `every` after each plan (if any), records its calls, touches the wire's
/// peer operations once per step, and fails fatally at step `fail_at` (1-based).
struct Recorder {
    calls: Rc<RefCell<Calls>>,
    watch: PeerWatch,
    every: Option<Duration>,
    fail_at: Option<usize>,
}

impl PeerService for Recorder {
    fn peer_plan(&self, now: Instant) -> PeerPlan {
        PeerPlan { watch: self.watch, deadline: self.every.map(|every| now + every) }
    }

    fn serve_peer_step(&mut self, ops: &mut dyn PeerOps, wall: Option<u64>, _now: Instant, ready: PeerReady) -> PeerOutcome {
        let _ = ops.accept_peer();
        let mut calls = self.calls.borrow_mut();
        calls.steps.push((ready, wall));
        if self.fail_at == Some(calls.steps.len()) { PeerOutcome::ListenerFailed } else { PeerOutcome::Served }
    }

    fn serve_peer_deadlines(&mut self, _ops: &mut dyn PeerOps, _wall: Option<u64>, _now: Instant) {
        self.calls.borrow_mut().deadlines += 1;
    }
}

fn new_client(wire: &ScriptWire) -> Client<ScriptWire> {
    let pki = shared_pki();
    Client::new(wire.clone(), observer_tls(&pki, &pki.serving_ca), ADDRESS, "127.0.0.1:6443")
}

fn attach(client: &mut Client<ScriptWire>, watch: PeerWatch, every: Option<Duration>, fail_at: Option<usize>)
          -> Rc<RefCell<Calls>> {
    let calls = Rc::new(RefCell::new(Calls::default()));
    client.serve_peers(Box::new(Recorder { calls: calls.clone(), watch, every, fail_at }));
    calls
}

const READABLE: Ready = Ready { readable: true, writable: false, error: false, hangup: false };

#[test]
fn without_a_service_the_wait_watches_no_i01_descriptor_and_keeps_its_deadline() {
    let wire = ScriptWire::new();
    let mut client = new_client(&wire);
    client.pause(wire.base() + secs(3)).expect("no failure");
    assert_eq!(wire.0.borrow().waits, [(PeerWatch::default(), secs(3))]);
    assert!(!client.listener_failed());
}

#[test]
fn the_service_names_its_descriptors_and_shortens_the_wait_to_its_deadline() {
    let wire = ScriptWire::new();
    let mut client = new_client(&wire);
    let watch = PeerWatch { listener: true, peer: Some(PeerId(4)) };
    let calls = attach(&mut client, watch, Some(secs(2)), None);
    client.pause(wire.base() + secs(5)).expect("no failure");
    // Each wait ends at the earlier of the pause's end and the service's deadline (2 s after each plan).
    assert_eq!(wire.0.borrow().waits, [(watch, secs(2)), (watch, secs(4)), (watch, secs(5))]);
    assert_eq!(calls.borrow().deadlines, 3, "the deadlines are served once per wake");
    assert!(calls.borrow().steps.is_empty(), "no descriptor was ready");
    // A later deadline than the pause's end leaves the pause's.
    let wire = ScriptWire::new();
    let mut client = new_client(&wire);
    attach(&mut client, watch, Some(secs(30)), None);
    client.pause(wire.base() + secs(5)).expect("no failure");
    assert_eq!(wire.0.borrow().waits, [(watch, secs(5))]);
}

#[test]
fn each_ready_i01_descriptor_is_one_step_and_the_deadlines_one_call_per_wake() {
    let wire = ScriptWire::new();
    let hung = Ready { readable: false, writable: false, error: false, hangup: true };
    wire.0.borrow_mut().wakes.push_back(Woken {
        conns: Vec::new(),
        listener: Some(READABLE),
        peers: vec![(PeerId(1), READABLE), (PeerId(2), hung)],
        listener_fault: false,
        peer_faults: vec![PeerId(3)],
    });
    let mut client = new_client(&wire);
    let calls = attach(&mut client, PeerWatch { listener: true, peer: Some(PeerId(1)) }, None, None);
    client.pause(wire.base() + secs(1)).expect("no failure");
    let wall = Some(1_001);
    assert_eq!(calls.borrow().steps, [(PeerReady::Listener(READABLE), wall), (PeerReady::Peer(PeerId(1), READABLE), wall),
                                      (PeerReady::Peer(PeerId(2), hung), wall), (PeerReady::PeerFault(PeerId(3)), wall)]);
    assert_eq!(calls.borrow().deadlines, 1);
    assert_eq!(wire.0.borrow().accepts, 4, "the service received the wire's peer operations at each step");
    // A failed watch of the listener is its fault, in place of its readiness.
    let wire = ScriptWire::new();
    wire.0.borrow_mut().wakes.push_back(Woken { listener: Some(READABLE), listener_fault: true, ..Woken::default() });
    let mut client = new_client(&wire);
    let calls = attach(&mut client, PeerWatch { listener: true, peer: None }, None, None);
    client.pause(wire.base() + secs(1)).expect("no failure");
    assert_eq!(calls.borrow().steps, [(PeerReady::ListenerFault, Some(1_001))]);
}

#[test]
fn a_fatal_listener_step_ends_the_wait_and_the_client_names_it() {
    let wire = ScriptWire::new();
    wire.0.borrow_mut().wakes.push_back(Woken { listener: Some(READABLE), ..Woken::default() });
    let mut client = new_client(&wire);
    let calls = attach(&mut client, PeerWatch { listener: true, peer: None }, None, Some(1));
    assert!(client.pause(wire.base() + secs(1)).is_err());
    assert!(client.listener_failed());
    assert_eq!(calls.borrow().deadlines, 0, "the wait ended at the fatal step");
    // A poller failure is not the listener's.
    let wire = ScriptWire::new();
    let client = new_client(&wire);
    assert!(!client.listener_failed());
}

#[test]
fn the_listener_backs_off_five_seconds_and_the_twelfth_fault_in_a_row_is_fatal() {
    assert_eq!((LISTENER_BACKOFF, LISTENER_FAULT_LIMIT), (secs(5), 12));
    let base = Instant::now();
    let mut backoff = ListenerBackoff::default();
    assert_eq!((backoff.until(), backoff.faults()), (None, 0));
    for count in 1..LISTENER_FAULT_LIMIT {
        let at = base + secs(u64::from(count) * 5);
        assert!(!backoff.fault(at), "fault {count} is not fatal");
        assert_eq!(backoff.until(), Some(at + LISTENER_BACKOFF));
        backoff.settle(at + secs(4));
        assert!(backoff.until().is_some(), "still backing off 4 s after the fault");
        backoff.settle(at + LISTENER_BACKOFF);
        assert_eq!(backoff.until(), None, "the re-add deadline has come");
    }
    assert_eq!(backoff.faults(), 11);
    assert!(backoff.fault(base + secs(60)), "the twelfth fault in a row is fatal");
    // An accept between faults starts the count again.
    let mut backoff = ListenerBackoff::default();
    for _ in 0..11 {
        assert!(!backoff.fault(base));
    }
    backoff.accepted();
    assert_eq!(backoff.faults(), 0);
    for _ in 0..11 {
        assert!(!backoff.fault(base));
    }
    assert!(backoff.fault(base));
}

/// One control message as the kernel lays it out on both 64-bit targets: a 64-bit length, the level, the type, the
/// payload, padded to 8 bytes.
fn message(level: i32, kind: i32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = ((16 + payload.len()) as u64).to_le_bytes().to_vec();
    bytes.extend_from_slice(&level.to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(payload);
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }
    bytes
}

fn credentials(pid: i32, uid: u32, gid: u32) -> Vec<u8> {
    let mut bytes = pid.to_le_bytes().to_vec();
    bytes.extend_from_slice(&uid.to_le_bytes());
    bytes.extend_from_slice(&gid.to_le_bytes());
    message(1, 2, &bytes)
}

fn security(label: &[u8]) -> Vec<u8> {
    message(1, 3, label)
}

#[test]
fn a_datagram_carries_exactly_one_credentials_and_one_security_message() {
    let label = b"system_u:system_r:planeon_server_t:s0\0";
    let good = [credentials(812, 0, 0), security(label)].concat();
    assert_eq!(PeerRecv::datagram(40, false, &good, false),
               PeerRecv::Data { length: 40, pid: 812, uid: 0, gid: 0, security: label.to_vec() });
    // The other order is the same delivery.
    let swapped = [security(label), credentials(812, 0, 0)].concat();
    assert!(matches!(PeerRecv::datagram(40, false, &swapped, false), PeerRecv::Data { pid: 812, .. }));
    // A datagram longer than the buffer.
    assert_eq!(PeerRecv::datagram(16_385, true, &good, false), PeerRecv::Truncated);
    let descriptor = message(1, 1, &7i32.to_le_bytes());
    for (control, cut) in [(good.clone(), true), (credentials(812, 0, 0), false), (security(label), false),
                           ([good.clone(), credentials(812, 0, 0)].concat(), false),
                           ([good.clone(), security(label)].concat(), false), ([good.clone(), descriptor.clone()].concat(), false),
                           ([descriptor, security(label)].concat(), false),
                           ([credentials(812, 0, 0), message(41, 3, label)].concat(), false), (Vec::new(), false),
                           (good[..20].to_vec(), false)] {
        assert_eq!(PeerRecv::datagram(40, false, &control, cut), PeerRecv::Ancillary, "{control:?} {cut}");
    }
}

#[test]
fn a_healthy_epoch_with_the_i01_service_and_no_peer_ends_as_without_it() {
    let server = ServerIdentity { uid: 0, gid: 0, process_label: "system_u:system_r:planeon_server_t:s0".to_string(),
                                  cgroup_rel: "planeon.slice/planeon-proxy-server.service".to_string(),
                                  class: ServerClass::Observed, interpreter: "/opt/planeon/python/3.12.14/bin/python3.12".to_string(),
                                  valid_from: 0, expires_at: u64::MAX / 2 };
    let rig = Rig::new();
    let mut epoch = rig.epoch().with_peer_service(Box::new(I01Service::new(server)));
    assert_eq!(epoch.run(), ObserverExit::ConfigExpired);
    assert!(!epoch.client().listener_failed());
}
