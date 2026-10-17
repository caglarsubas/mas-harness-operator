//! HE-003A: the channel substrate over a scripted `Os` and scripted ports (DESIGN §9). One channel per generation and
//! the refusals of later connections; the expected peers at accept and the custody rules on every frame; datagrams;
//! both output tables; the order of a wake; the expiry clock; the 2-second answer bound; the I07 session; send
//! failures; registration and the loop's exits. The Linux `Os` and the kernel's side of each rule are T04's.

mod substrate_support;
mod support;

use std::collections::BTreeMap;
use std::time::Duration;

use effect_gate::substrate::{I05_CONN_TOKEN, I05_LISTENER_TOKEN, I05_PIDFD_TOKEN};
use effect_gate::{ChannelState, ConnId, Event, Lifetimes, Listen, LoopExit, OsFailure, Owner, PolicyEvent, PolicyGate,
                  Received, SourceId, UpstreamOutcome, UpstreamResponse};
use i05_protocol::json::Value;
use i05_protocol::sha256;

use substrate_support::*;

const EXECUTION: &str = "1111111111111111111111111111111111111111111111111111111111111111";
/// The fake realtime clock starts at 1,900,000,000 s since the epoch.
const NOW: i64 = 1_900_000_000;

fn lifetimes(end: i64) -> Lifetimes {
    Lifetimes::new(BTreeMap::from([("run-one".to_string(), end)]))
}

fn begin() -> Value {
    object(vec![("expectedGeneration", Value::str(GENERATION))])
}

fn port_token(owner: Owner, value: u64) -> u64 {
    owner.token(value).expect("a 56-bit value")
}

/// The I05 vector event of T01 with this type (the first one), as the gate's typed event.
fn t01_event(kind: &str) -> Event {
    let event = t01_events()
        .into_iter()
        .find(|event| event.get("type").and_then(Value::as_str) == Some(kind))
        .expect("a T01 event");
    support::base_event(&event, kind)
}

fn upstream_response(status: i64) -> UpstreamResponse {
    UpstreamResponse { http_status: status, body_digest: format!("sha256:{}", "8".repeat(64)), uid: None,
                       resource_version: None }
}

fn position(trace: &[String], wanted: &str, after: usize) -> usize {
    trace.iter().skip(after).position(|line| line == wanted).map(|at| at + after)
        .unwrap_or_else(|| panic!("{wanted} after {after} in {trace:?}"))
}

// ------------------------------------------------------------------------------------------ channels

#[test]
fn one_channel_per_generation() {
    let mut bench = Bench::fresh();
    let first = bench.connect(Listen::I05, broker_peer());
    assert_eq!(bench.substrate.held(Listen::I05), Some(ConnId(first)), "a qualified broker is held, pending");
    assert_eq!(bench.gate().channel_state(), ChannelState::Unopened);
    let journal = bench.journal();
    // A second connection while the first is pending: closed without feeding the model; nothing is journalled.
    let second = bench.connect(Listen::I05, broker_peer());
    assert!(bench.closed(second) && !bench.closed(first));
    assert_eq!(bench.journal(), journal);
    assert!(bench.outputs().is_empty(), "the model was not fed");
    // The first frame opens the channel and its exact response frame is sent.
    bench.broker_says(first, "GENERATION_STATUS", empty()).expect("a wake");
    let sent = bench.sent(first);
    assert_eq!(sent.len(), 1);
    assert_eq!(sha256::prefixed(&sent[0]), bench.gate().gate().last_digest());
    assert_eq!(bench.gate().channel_state(), ChannelState::Open);
    // While open: CHANNEL_EXISTS, and the new connection is closed.
    let third = bench.connect(Listen::I05, broker_peer());
    assert!(bench.closed(third) && !bench.closed(first));
    assert_eq!(bench.last_output(), r#"{"refusedChannel":"CHANNEL_EXISTS"}"#);
    // The channel is lost while ACTIVE: fatal PEER_LOST.
    bench.receive(first, Received::Eof).expect("a wake");
    assert!(bench.closed(first));
    assert_eq!(bench.last_output(), r#"{"fatal":"PEER_LOST"}"#);
    assert_eq!(bench.state(), "HELD");
    // After the close: GENERATION_CHANNEL_USED.
    let fourth = bench.connect(Listen::I05, broker_peer());
    assert!(bench.closed(fourth));
    assert_eq!(bench.last_output(), r#"{"refusedChannel":"GENERATION_CHANNEL_USED"}"#);
    assert_eq!(bench.substrate.held(Listen::I05), None);
}

#[test]
fn after_a_process_restart_a_passed_expiry_is_fed_first_and_no_connection_is_accepted() {
    let (journal, marker) = place("substrate-restart");
    let (converted, kernel) = effect_gate::fake_kernel::convert_v3_config(&config()).expect("v4's conversion");
    {
        let gate = PolicyGate::create(&converted, &kinds(), stores(&journal, &marker)).expect("a new generation")
            .with_observer(Box::new(effect_gate::KernelObserver::new(kernel)));
        let mut bench = Bench::new(gate, lifetimes(NOW + 3600));
        let conn = bench.open_broker();
        bench.broker_says(conn, "BIND_EXECUTION", t01("BIND_EXECUTION")).expect("a wake");
    }
    let (gate, _) = PolicyGate::open(&converted, &kinds(), stores(&journal, &marker)).expect("the restart");
    assert_eq!(gate.channel_state(), ChannelState::Closed);
    // The run's lifetime ended while the gate was down: EXPIRE at the first wake, which does not wait.
    let mut bench = Bench::new(gate, lifetimes(NOW - 1));
    bench.wake(vec![]).expect("a wake");
    assert_eq!(bench.lab.borrow().waits.first(), Some(&0));
    let records = bench.journal();
    assert!(records[records.len() - 2].starts_with(r#"["RESTARTED","#), "{records:?}");
    assert_eq!(records[records.len() - 1], format!(r#"["EXPIRED","{EXECUTION}"]"#));
    // Deny-first: the generation's channel is used, so the first connection after the restart is refused.
    let conn = bench.connect(Listen::I05, broker_peer());
    assert!(bench.closed(conn));
    assert_eq!(bench.last_output(), r#"{"refusedChannel":"GENERATION_CHANNEL_USED"}"#);
}

#[test]
fn a_connection_that_ends_before_its_first_frame_uses_the_channel() {
    let mut bench = Bench::fresh();
    let conn = bench.connect(Listen::I05, broker_peer());
    bench.receive(conn, Received::Eof).expect("a wake");
    assert!(bench.closed(conn));
    assert_eq!(bench.last_output(), r#"{"channelEnd":"UNUSED"}"#);
    assert_eq!(bench.last_record(), r#"["CHANNEL_ENDED","BEFORE_FIRST_FRAME"]"#);
    assert_eq!((bench.gate().channel_state(), bench.state()), (ChannelState::Closed, "ACTIVE"));
    let later = bench.connect(Listen::I05, broker_peer());
    assert!(bench.closed(later));
    assert_eq!(bench.last_output(), r#"{"refusedChannel":"GENERATION_CHANNEL_USED"}"#);
}

// ------------------------------------------------------------------------------------------ expected peers

#[test]
fn a_qualified_broker_keeps_its_identity_and_its_control_buffer() {
    let mut bench = Bench::fresh();
    let conn = bench.open_broker();
    let identity = bench.substrate.identity(Listen::I05).expect("an identity").clone();
    assert_eq!((identity.pid(), identity.uid(), identity.gid()), (BROKER_PID, 0, 0));
    assert_eq!((identity.socket_label(), identity.process_label()), (&broker_label()[..], &broker_label()[..]));
    assert_eq!((identity.start_time(), identity.cgroup()), (BROKER_START, BROKER_LEAF));
    // CMSG_SPACE(12) + CMSG_SPACE(38) for the 38-byte label.
    assert!(bench.lab.borrow().conns[&conn].capacities.iter().all(|capacity| *capacity == 88));
    // The order of the qualification: credentials, the process directory, its read, then the pidfd.
    let trace = bench.trace();
    let peer = position(&trace, &format!("peer #{conn}"), 0);
    let open = position(&trace, &format!("open_proc #{conn} {BROKER_PID}"), peer);
    let read = position(&trace, &format!("read_proc #{conn}"), open);
    position(&trace, &format!("exited #{conn}"), read);
}

/// The ways a broker fails qualification at accept.
fn unqualified_brokers() -> Vec<(&'static str, FakePeer)> {
    let worker = delivered("system_u:system_r:planeon_worker_t:s0");
    let mut cases = Vec::new();
    let mut peer = broker_peer();
    peer.identity.as_mut().expect("identity").label = worker.clone();
    cases.push(("process label", peer));
    let mut peer = broker_peer();
    peer.credentials.as_mut().expect("credentials").label = worker;
    cases.push(("socket label", peer));
    let mut peer = broker_peer();
    peer.credentials.as_mut().expect("credentials").uid = 1000;
    cases.push(("uid", peer));
    let mut peer = broker_peer();
    peer.credentials.as_mut().expect("credentials").gid = 1000;
    cases.push(("gid", peer));
    let mut peer = broker_peer();
    peer.identity.as_mut().expect("identity").cgroup = WORKER_LEAF.to_vec();
    cases.push(("cgroup (a broker child in the probe-worker leaf)", peer));
    let mut peer = broker_peer();
    peer.credentials = None;
    cases.push(("a reaped peer (SO_PEERPIDFD fails)", peer));
    let mut peer = broker_peer();
    peer.open_proc = false;
    cases.push(("the process directory does not open", peer));
    let mut peer = broker_peer();
    peer.identity = None;
    cases.push(("the process directory does not read", peer));
    let mut peer = broker_peer();
    peer.exited = true;
    cases.push(("the pidfd fired after the open", peer));
    let mut peer = broker_peer();
    peer.credentials.as_mut().expect("credentials").pid = 0;
    cases.push(("pid 0", peer));
    cases
}

#[test]
fn each_mismatch_at_accept_is_a_deviation_before_the_first_frame() {
    for (case, peer) in unqualified_brokers() {
        let mut bench = Bench::fresh();
        let conn = bench.connect(Listen::I05, peer);
        assert!(bench.closed(conn), "{case}");
        assert_eq!(bench.substrate.held(Listen::I05), None, "{case}");
        // PeerChanged (the model answers nothing) then ChannelLost (Q-HE3A-4 (a)).
        assert_eq!(bench.outputs(), vec!["{}".to_string(), r#"{"channelEnd":"UNUSED"}"#.to_string()], "{case}");
        assert_eq!(bench.last_record(), r#"["CHANNEL_ENDED","BEFORE_FIRST_FRAME"]"#, "{case}");
        assert_eq!((bench.gate().channel_state(), bench.state()), (ChannelState::Closed, "ACTIVE"), "{case}");
        // No later connection is accepted for this generation.
        let later = bench.connect(Listen::I05, broker_peer());
        assert!(bench.closed(later), "{case}");
    }
}

#[test]
fn a_deviation_on_the_first_frame_is_before_the_first_frame() {
    let mut bench = Bench::fresh();
    let conn = bench.connect(Listen::I05, broker_peer());
    let frame = broker_frame(bench.gate(), "GENERATION_STATUS", empty());
    bench.receive(conn, datagram(frame, control(BROKER_PID + 1, 0, 0, &broker_label()))).expect("a wake");
    assert!(bench.closed(conn));
    assert!(bench.sent(conn).is_empty());
    assert_eq!(bench.outputs(), vec!["{}".to_string(), r#"{"channelEnd":"UNUSED"}"#.to_string()]);
    assert_eq!(bench.last_record(), r#"["CHANNEL_ENDED","BEFORE_FIRST_FRAME"]"#);
    assert_eq!(bench.state(), "ACTIVE", "the model does not hold the generation (MODEL_DEFINED)");
}

// ------------------------------------------------------------------------------------------ custody

type Change = fn(&mut FakePeer);

fn unchanged(_: &mut FakePeer) {}

fn exec_into_worker(peer: &mut FakePeer) {
    if let Some(identity) = peer.identity.as_mut() {
        identity.label = delivered("system_u:system_r:planeon_worker_t:s0");
    }
}

fn restarted(peer: &mut FakePeer) {
    if let Some(identity) = peer.identity.as_mut() {
        identity.start_time += 1;
    }
}

fn moved(peer: &mut FakePeer) {
    if let Some(identity) = peer.identity.as_mut() {
        identity.cgroup = WORKER_LEAF.to_vec();
    }
}

fn exited(peer: &mut FakePeer) {
    peer.exited = true;
}

fn reaped(peer: &mut FakePeer) {
    peer.identity = None;
    peer.exited = true;
}

/// The ways a frame after the first fails custody: its control bytes (the broker's when `None`), MSG_CTRUNC, and a
/// change of the peer process.
fn custody_failures() -> Vec<(&'static str, Option<Vec<u8>>, bool, Change)> {
    let worker = delivered("system_u:system_r:planeon_worker_t:s0");
    let creds = credentials_message(BROKER_PID, 0, 0);
    let label = security_message(&broker_label());
    let mut bad_length = [creds.clone(), label.clone()].concat();
    bad_length[0] = 15;
    let mut cases: Vec<(&'static str, Option<Vec<u8>>, bool, Change)> = Vec::new();
    cases.push(("credentials pid", Some(control(BROKER_PID + 1, 0, 0, &broker_label())), false, unchanged));
    cases.push(("credentials uid", Some(control(BROKER_PID, 1, 0, &broker_label())), false, unchanged));
    cases.push(("credentials gid", Some(control(BROKER_PID, 0, 1, &broker_label())), false, unchanged));
    cases.push(("socket label", Some(control(BROKER_PID, 0, 0, &worker)), false, unchanged));
    cases.push(("socket label without its NUL",
                Some(control(BROKER_PID, 0, 0, effect_gate::peers::BROKER_LABEL.as_bytes())), false, unchanged));
    cases.push(("process label (an exec that kept the descriptor)", None, false, exec_into_worker));
    cases.push(("start time", None, false, restarted));
    cases.push(("cgroup", None, false, moved));
    cases.push(("pidfd exit with the connection alive", None, false, exited));
    cases.push(("a frame from a reaped sender", Some(control(0, 0, 0, &broker_label())), false, reaped));
    cases.push(("MSG_CTRUNC (an SCM_RIGHTS after the two)", None, true, unchanged));
    cases.push(("no security message", Some(creds.clone()), false, unchanged));
    cases.push(("no credentials message", Some(label.clone()), false, unchanged));
    cases.push(("repeated credentials", Some([creds.clone(), creds.clone(), label.clone()].concat()), false, unchanged));
    cases.push(("an SCM_RIGHTS message", Some([creds.clone(), label.clone(), message(1, 1, &[7, 0, 0, 0])].concat()),
                false, unchanged));
    cases.push(("a foreign level", Some([creds, message(0, 3, &broker_label())].concat()), false, unchanged));
    cases.push(("a bad cmsg_len", Some(bad_length), false, unchanged));
    cases
}

#[test]
fn custody_checks_every_rule_on_every_frame() {
    for (case, control_bytes, truncated, change) in custody_failures() {
        let mut bench = Bench::fresh();
        let conn = bench.open_broker();
        bench.set_peer(conn, change);
        let frame = broker_frame(bench.gate(), "GENERATION_STATUS", empty());
        let received = Received::Datagram {
            bytes: frame,
            truncated: false,
            control: control_bytes.unwrap_or_else(broker_control),
            control_truncated: truncated,
        };
        bench.receive(conn, received).expect("a wake");
        assert_eq!(bench.last_output(), r#"{"fatal":"PEER_CHANGED"}"#, "{case}");
        assert_eq!(bench.last_record(), r#"["INVALIDATED","PEER_CHANGED","HELD"]"#, "{case}");
        assert_eq!(bench.state(), "HELD", "{case}");
        assert!(bench.closed(conn), "{case}");
        assert_eq!(bench.sent(conn).len(), 1, "{case}: the frame is not answered");
    }
}

#[test]
fn a_pidfd_that_fires_with_the_connection_alive_is_a_deviation() {
    let mut bench = Bench::fresh();
    let conn = bench.open_broker();
    bench.set_peer(conn, |peer| peer.exited = true);
    bench.pidfd(Listen::I05).expect("a wake");
    assert_eq!(bench.last_output(), r#"{"fatal":"PEER_CHANGED"}"#);
    assert!(bench.closed(conn));
    // Its datagrams are read first.
    let trace = bench.trace();
    let read = position(&trace, &format!("recv #{conn}"), 0);
    position(&trace, &format!("close #{conn}"), read);
}

#[test]
fn an_exit_after_an_orderly_end_is_the_channel_end() {
    let mut bench = Bench::fresh();
    let conn = bench.open_broker();
    bench.broker_says(conn, "CLOSE_GENERATION", object(vec![("reason", Value::str("NORMAL_DRAIN"))])).expect("a wake");
    assert_eq!(bench.state(), "CLOSED");
    // The broker exits; its end of file is read before the pidfd counts as a deviation.
    bench.set_peer(conn, |peer| peer.exited = true);
    bench.lab.borrow_mut().conns.get_mut(&conn).expect("conn").inbox.push_back(Received::Eof);
    bench.pidfd(Listen::I05).expect("a wake");
    assert_eq!(bench.last_output(), r#"{"channelEnd":"ORDERLY"}"#);
    assert_eq!(bench.last_record(), r#"["CHANNEL_ENDED","ORDERLY"]"#);
    assert_eq!(bench.state(), "CLOSED");
}

#[test]
fn an_exit_the_pidfd_probe_reports_at_a_frame_is_a_deviation() {
    // `Os::peer_exited` reports an exit and a failed probe alike (one bool), so no fake can return a ppoll error: the
    // mapping of a failed ppoll, POLLERR and POLLNVAL to an exit is gate-sys's `PidFd::exited` (Linux only), and T04's
    // to prove (HE-003A PR review round 1, R1-3 (e)). Here: whatever the probe reports as an exit is a deviation, even
    // when every earlier custody rule passed, and it is the frame's last custody step.
    let mut bench = Bench::fresh();
    let conn = bench.open_broker();
    bench.set_peer(conn, |peer| peer.exited = true);
    bench.clear_trace();
    bench.broker_says(conn, "GENERATION_STATUS", empty()).expect("a wake");
    assert_eq!(bench.last_output(), r#"{"fatal":"PEER_CHANGED"}"#);
    assert_eq!(bench.sent(conn).len(), 1, "the frame is not answered");
    let trace = bench.trace();
    let read = position(&trace, &format!("recv #{conn}"), 0);
    let directory = position(&trace, &format!("read_proc #{conn}"), read);
    let probe = position(&trace, &format!("exited #{conn}"), directory);
    position(&trace, &format!("close #{conn}"), probe);
}

// ------------------------------------------------------------------------------------------ I07 peers and sessions

#[test]
fn an_unqualified_writer_is_closed_unfed_and_a_later_writer_gets_a_session() {
    let mut bench = Bench::fresh();
    let journal = bench.journal();
    let mut impostor = writer_peer();
    impostor.identity.as_mut().expect("identity").label = broker_label();
    let first = bench.connect(Listen::I07, impostor);
    assert!(bench.closed(first));
    assert!(bench.outputs().is_empty(), "no WConnect was fed");
    assert_eq!(bench.journal(), journal);
    assert!(!bench.gate().session_held());
    let second = bench.connect(Listen::I07, writer_peer());
    assert_eq!(bench.last_output(), r#"{"session":"CONNECTED"}"#);
    assert_eq!(bench.substrate.held(Listen::I07), Some(ConnId(second)));
    // The writer's gid and cgroup are recorded at accept.
    let identity = bench.substrate.identity(Listen::I07).expect("an identity");
    assert_eq!((identity.gid(), identity.cgroup()), (0, ADMIN_SCOPE));
}

#[test]
fn one_writer_session_at_a_time() {
    let mut bench = Bench::fresh();
    let first = bench.open_writer();
    let second = bench.connect(Listen::I07, writer_peer());
    assert_eq!(bench.last_output(), r#"{"refusedSession":"SESSION_EXISTS"}"#);
    assert!(bench.closed(second) && !bench.closed(first));
}

#[test]
fn a_writer_deviation_is_w_peer_changed_and_sessions_are_not_per_generation() {
    let mut bench = Bench::fresh();
    let conn = bench.open_writer();
    let frame = writer_frame(bench.gate(), "MAINTENANCE_STATUS", empty());
    bench.receive(conn, datagram(frame, control(WRITER_PID, 0, 1, &writer_label()))).expect("a wake");
    assert_eq!(bench.last_output(), r#"{"fatal":"PEER_CHANGED","maintenance":"NONE","sessionEnd":"FATAL"}"#);
    let journal = bench.journal();
    assert!(journal.contains(&r#"["INVALIDATED","WRITER_PEER_DEVIATION","HELD"]"#.to_string()));
    assert_eq!(journal.last().map(String::as_str), Some(r#"["WRITER_SESSION_ENDED","FATAL"]"#));
    assert!(bench.closed(conn) && !bench.gate().session_held());
    assert_eq!(bench.state(), "HELD");
    // A later qualified writer gets a session.
    let later = bench.connect(Listen::I07, writer_peer());
    assert_eq!(bench.substrate.held(Listen::I07), Some(ConnId(later)));
}

#[test]
fn each_writer_mismatch_at_accept_closes_it_unfed_and_its_gid_and_cgroup_are_recorded() {
    // HE-003A PR review round 1, R1-3 (b): the writer's uid is expected (0), as are its labels and a live pidfd.
    let mut cases = Vec::new();
    let mut peer = writer_peer();
    peer.credentials.as_mut().expect("credentials").uid = 1000;
    cases.push(("uid", peer));
    let mut peer = writer_peer();
    peer.credentials.as_mut().expect("credentials").label = broker_label();
    cases.push(("socket label", peer));
    let mut peer = writer_peer();
    peer.exited = true;
    cases.push(("the pidfd fired after the open", peer));
    for (case, peer) in cases {
        let mut bench = Bench::fresh();
        let journal = bench.journal();
        let conn = bench.connect(Listen::I07, peer);
        assert!(bench.closed(conn), "{case}");
        assert!(bench.outputs().is_empty(), "{case}: no WConnect was fed");
        assert_eq!(bench.journal(), journal, "{case}");
        assert!(!bench.gate().session_held() && bench.substrate.held(Listen::I07).is_none(), "{case}");
    }
    // The writer's gid and cgroup are not expected: a writer with another gid in another cgroup qualifies, and both
    // are recorded at accept.
    let mut bench = Bench::fresh();
    let mut peer = writer_peer();
    peer.credentials.as_mut().expect("credentials").gid = 1000;
    peer.identity.as_mut().expect("identity").cgroup = WORKER_LEAF.to_vec();
    let conn = bench.connect(Listen::I07, peer);
    assert_eq!(bench.last_output(), r#"{"session":"CONNECTED"}"#);
    assert_eq!(bench.substrate.held(Listen::I07), Some(ConnId(conn)));
    let identity = bench.substrate.identity(Listen::I07).expect("an identity");
    assert_eq!((identity.gid(), identity.cgroup()), (1000, WORKER_LEAF));
}

#[test]
fn writer_custody_compares_the_cgroup_recorded_at_accept_on_every_frame() {
    // HE-003A PR review round 1, R1-3 (a): the writer's cgroup is the one recorded at accept, not a pinned one.
    let session_seven: &[u8] = b"0::/user.slice/user-0.slice/session-7.scope\n";
    let mut bench = Bench::fresh();
    let mut peer = writer_peer();
    peer.identity.as_mut().expect("identity").cgroup = session_seven.to_vec();
    let conn = bench.connect(Listen::I07, peer);
    assert_eq!(bench.substrate.identity(Listen::I07).map(|identity| identity.cgroup()), Some(session_seven));
    bench.writer_says(conn, "MAINTENANCE_STATUS", empty()).expect("a wake");
    assert_eq!(bench.sent(conn).len(), 1, "a frame from the recorded cgroup passes custody");
    // The writer moves to another cgroup (here the admin scope the other tests record): its next frame is a deviation.
    bench.set_peer(conn, |peer| {
        if let Some(identity) = peer.identity.as_mut() {
            identity.cgroup = ADMIN_SCOPE.to_vec();
        }
    });
    bench.writer_says(conn, "MAINTENANCE_STATUS", empty()).expect("a wake");
    assert_eq!(bench.last_output(), r#"{"fatal":"PEER_CHANGED","maintenance":"NONE","sessionEnd":"FATAL"}"#);
    assert!(bench.journal().contains(&r#"["INVALIDATED","WRITER_PEER_DEVIATION","HELD"]"#.to_string()));
    assert!(bench.closed(conn) && !bench.gate().session_held());
    assert_eq!(bench.sent(conn).len(), 1, "the frame is not answered");
}

#[test]
fn writer_custody_checks_the_start_time_the_process_label_and_the_pidfd_on_every_frame() {
    for (case, change) in [("start time", restarted as Change), ("process label (an exec that kept the descriptor)",
                                                                  exec_into_worker), ("pidfd exit", exited)] {
        let mut bench = Bench::fresh();
        let conn = bench.open_writer();
        bench.set_peer(conn, change);
        bench.writer_says(conn, "MAINTENANCE_STATUS", empty()).expect("a wake");
        assert_eq!(bench.last_output(), r#"{"fatal":"PEER_CHANGED","maintenance":"NONE","sessionEnd":"FATAL"}"#,
                   "{case}");
        assert!(bench.journal().contains(&r#"["INVALIDATED","WRITER_PEER_DEVIATION","HELD"]"#.to_string()), "{case}");
        assert!(bench.closed(conn) && !bench.gate().session_held(), "{case}");
        assert_eq!(bench.sent(conn).len(), 1, "{case}: the frame is not answered");
    }
}

#[test]
fn forwarded_writes_go_to_the_upstream_port_and_a_session_end_closes() {
    let mut bench = Bench::fresh();
    let conn = bench.open_writer();
    bench.writer_says(conn, "WRITE_BEGIN", begin()).expect("a wake");
    bench.writer_says(conn, "WRITE_OBJECT", role_create(1)).expect("a wake");
    assert_eq!(bench.lab.borrow().upstream.outputs.last().map(String::as_str), Some(r#"{"forwarded":1}"#));
    assert_eq!(bench.sent(conn).len(), 2, "the forwarded write is answered later");
    assert_eq!(bench.gate().pending_write(), Some(1));
    assert_eq!(bench.lab.borrow().upstream.synced.last(), Some(&Some(1)), "sync sees the pending write");
    // The writer goes away: the session ends, the write is aborted, the connection is closed.
    bench.receive(conn, Received::Eof).expect("a wake");
    assert!(bench.last_output().contains(r#""sessionEnd":"ENDED""#));
    assert!(bench.closed(conn) && !bench.gate().session_held());
    assert_eq!(bench.gate().pending_write(), None);
}

#[test]
fn an_upstream_answer_reaches_the_writer() {
    let mut bench = Bench::fresh();
    let conn = bench.open_writer();
    bench.writer_says(conn, "WRITE_BEGIN", begin()).expect("a wake");
    bench.writer_says(conn, "WRITE_OBJECT", role_create(1)).expect("a wake");
    let outcome = UpstreamOutcome::Response(upstream_response(201));
    bench.lab.borrow_mut().upstream.ready.push_back(vec![PolicyEvent::WUpstream { write_id: 1, outcome }]);
    bench.wake(vec![(port_token(Owner::Upstream, 3), readable())]).expect("a wake");
    assert!(bench.last_output().starts_with(r#"{"classification":"DELIVERED_RESULT","relayed":true"#));
    assert_eq!(bench.sent(conn).len(), 3);
    assert!(!bench.closed(conn));
}

// ------------------------------------------------------------------------------------------ datagrams

#[test]
fn datagrams_oversize_zero_length_eof_and_reset() {
    let mut bench = Bench::fresh();
    let conn = bench.open_broker();
    let received = Received::Datagram { bytes: vec![b' '; 20000], truncated: true, control: broker_control(),
                                        control_truncated: false };
    bench.receive(conn, received).expect("a wake");
    assert_eq!(bench.last_output(), r#"{"fatal":"F02_INVALID_FRAME"}"#, "the first 16,385 bytes are refused for size");
    assert!(bench.closed(conn));

    let mut bench = Bench::fresh();
    let conn = bench.open_broker();
    bench.receive(conn, datagram(Vec::new(), broker_control())).expect("a wake");
    let output = bench.last_output();
    assert!(output.starts_with(r#"{"fatal":"F0"#) && output.ends_with(r#"_INVALID_FRAME"}"#), "a frame: {output}");

    for end in [Received::Eof, Received::Error(104)] {
        let mut bench = Bench::fresh();
        let conn = bench.open_broker();
        bench.receive(conn, end.clone()).expect("a wake");
        assert_eq!(bench.last_output(), r#"{"fatal":"PEER_LOST"}"#, "{end:?}");
        assert!(bench.closed(conn));
    }
}

// ------------------------------------------------------------------------------------------ outputs

#[test]
fn the_i05_ports_rows_reach_both_ports_and_nothing_goes_on_the_i05_wire() {
    let mut bench = Bench::new(new_gate(), lifetimes(NOW + 3600));
    let conn = bench.open_broker();
    bench.broker_says(conn, "BIND_EXECUTION", t01("BIND_EXECUTION")).expect("a wake");
    bench.broker_says(conn, "ARM_ACTION", t01("ARM_ACTION")).expect("a wake");
    let answered = bench.sent(conn).len();
    {
        let mut lab = bench.lab.borrow_mut();
        lab.i04.check_open = Some("c1".to_string());
        lab.i04.ready.push_back(vec![PolicyEvent::Base(t01_event("BACKLOG")), PolicyEvent::Base(t01_event("ACCEPT")),
                                     PolicyEvent::Base(t01_event("REQUEST"))]);
        lab.upstream.ready.push_back(vec![PolicyEvent::Base(t01_event("UPSTREAM_RESPONSE")),
                                          PolicyEvent::Base(t01_event("UPSTREAM_RESPONSE"))]);
        lab.i04.ready.push_back(vec![PolicyEvent::Base(Event::Backlog { conn: "c2".to_string() }),
                                     PolicyEvent::Base(Event::Accept { conn: "c2".to_string() }),
                                     PolicyEvent::Base(Event::Request { conn: "c2".to_string(),
                                                                        certificate_digest: String::new(),
                                                                        head: String::new(), body_digest: None })]);
    }
    bench.wake(vec![(port_token(Owner::I04, 1), readable())]).expect("a wake");
    bench.wake(vec![(port_token(Owner::Upstream, 1), readable())]).expect("a wake");
    bench.wake(vec![(port_token(Owner::I04, 1), readable())]).expect("a wake");
    let outputs = bench.outputs();
    let tail: Vec<&str> = outputs[outputs.len() - 8..].iter().map(String::as_str).collect();
    assert_eq!(tail, vec![
        "{}",
        &format!(r#"{{"stamp":{{"actionId":1,"executionId":"{EXECUTION}"}}}}"#),
        r#"{"actionId":1,"decision":"FORWARD"}"#,
        r#"{"classification":"DELIVERED_RESULT","relayed":true}"#,
        r#"{"lateUpstream":"NOT_RELAYED"}"#,
        "{}",
        r#"{"stamp":null}"#,
        r#"{"decision":"CLOSE","reason":"STAMP_NONE"}"#,
    ]);
    let lab = bench.lab.borrow();
    assert_eq!(lab.i04.outputs, lab.upstream.outputs, "every output goes to both ports");
    assert_eq!(lab.conns[&conn].sent.len(), answered, "nothing on the I05 wire");
    // GateView: c1 was open while forwarded and is closed after its one response.
    assert!(lab.i04.open_checked.contains(&("c1".to_string(), true)));
    assert_eq!(lab.i04.open_checked.last(), Some(&("c1".to_string(), false)));
}

#[test]
fn denied_goes_nowhere_on_the_wire_and_empty_does_nothing() {
    let mut bench = Bench::new(new_gate(), lifetimes(NOW));
    let conn = bench.open_broker();
    bench.broker_says(conn, "BIND_EXECUTION", t01("BIND_EXECUTION")).expect("a wake");
    let answered = bench.sent(conn).len();
    bench.wake(vec![]).expect("a wake");
    assert_eq!(bench.last_output(), r#"{"denied":[]}"#);
    assert_eq!(bench.sent(conn).len(), answered);
    // A writer loss without a session (a port's event) answers {} and touches nothing.
    bench.lab.borrow_mut().i04.ready.push_back(vec![PolicyEvent::WChannelLost]);
    bench.wake(vec![(port_token(Owner::I04, 2), readable())]).expect("a wake");
    assert_eq!(bench.last_output(), "{}");
    assert!(!bench.closed(conn));
}

/// A broker channel with T01's action forwarded (in flight) and a writer whose WRITE_BEGIN started the I05 drain,
/// which stays pending while the action is in flight.
fn draining() -> (Bench, u64, u64) {
    let mut bench = Bench::new(new_gate(), lifetimes(NOW + 3600));
    let broker = bench.open_broker();
    bench.broker_says(broker, "BIND_EXECUTION", t01("BIND_EXECUTION")).expect("a wake");
    bench.broker_says(broker, "ARM_ACTION", t01("ARM_ACTION")).expect("a wake");
    bench.lab.borrow_mut().i04.ready.push_back(vec![PolicyEvent::Base(t01_event("BACKLOG")),
                                                    PolicyEvent::Base(t01_event("ACCEPT")),
                                                    PolicyEvent::Base(t01_event("REQUEST"))]);
    bench.wake(vec![(port_token(Owner::I04, 1), readable())]).expect("a wake");
    assert_eq!(bench.last_output(), r#"{"actionId":1,"decision":"FORWARD"}"#);
    let writer = bench.open_writer();
    bench.writer_says(writer, "WRITE_BEGIN", begin()).expect("a wake");
    assert!(bench.last_output().contains(r#""maintenance":"PENDING""#), "{}", bench.last_output());
    assert!(!bench.last_output().contains(r#""drain""#), "the drain is pending");
    (bench, broker, writer)
}

#[test]
fn a_drain_answer_on_an_output_of_either_table_goes_on_no_wire() {
    // HE-003A PR review round 1, R1-3 (c), DESIGN §5.4's drain row: the writer polls MAINTENANCE_STATUS instead.
    // An I05 output: the in-flight action's upstream response settles the drain.
    let (mut bench, broker, writer) = draining();
    let sent = (bench.sent(broker).len(), bench.sent(writer).len());
    bench.lab.borrow_mut().upstream.ready.push_back(vec![PolicyEvent::Base(t01_event("UPSTREAM_RESPONSE"))]);
    bench.wake(vec![(port_token(Owner::Upstream, 1), readable())]).expect("a wake");
    let output = bench.last_output();
    assert!(output.contains(r#""classification":"DELIVERED_RESULT""#) && output.contains(r#""drain":"OPEN""#), "{output}");
    assert_eq!((bench.sent(broker).len(), bench.sent(writer).len()), sent, "nothing on either wire");
    assert!(!bench.closed(broker) && !bench.closed(writer));
    // An I07 output: a writer deviation holds the generation, which settles the drain; the session end's row closes
    // the writer connection, and the drain adds nothing on either wire.
    let (mut bench, broker, writer) = draining();
    let sent = (bench.sent(broker).len(), bench.sent(writer).len());
    let frame = writer_frame(bench.gate(), "MAINTENANCE_STATUS", empty());
    bench.receive(writer, datagram(frame, control(WRITER_PID, 0, 1, &writer_label()))).expect("a wake");
    let output = bench.last_output();
    assert!(output.contains(r#""drain":"HELD""#) && output.contains(r#""sessionEnd":"FATAL""#), "{output}");
    assert_eq!((bench.sent(broker).len(), bench.sent(writer).len()), sent, "nothing on either wire");
    assert!(bench.closed(writer) && !bench.closed(broker));
}

#[test]
fn an_event_error_stops_the_loop() {
    let mut bench = Bench::fresh();
    let conn = bench.open_broker();
    bench.lab.borrow_mut().i04.ready.push_back(vec![PolicyEvent::Base(Event::Accept { conn: "c404".to_string() })]);
    let exit = bench.wake(vec![(port_token(Owner::I04, 1), readable())]);
    assert_eq!(exit, Err(LoopExit::ModelPrecondition("accept outside the backlog")));
    // run() returns the first exit.
    bench.lab.borrow_mut().i04.ready.push_back(vec![PolicyEvent::Base(Event::Accept { conn: "c405".to_string() })]);
    bench.lab.borrow_mut().wakes.push_back(Wake { ready: vec![(port_token(Owner::I04, 1), readable())],
                                                  ..Wake::default() });
    assert_eq!(bench.substrate.run(), LoopExit::ModelPrecondition("accept outside the backlog"));
    assert!(!bench.closed(conn), "a port's event concerns no channel connection");
}

// ------------------------------------------------------------------------------------------ the order of a wake

#[test]
fn the_connection_then_the_pidfd_then_the_listener() {
    let mut bench = Bench::fresh();
    let conn = bench.open_broker();
    let frame = broker_frame(bench.gate(), "GENERATION_STATUS", empty());
    {
        let mut lab = bench.lab.borrow_mut();
        lab.conns.get_mut(&conn).expect("conn").inbox.push_back(datagram(frame, broker_control()));
        lab.accepts.entry(Listen::I05).or_default().push_back(Ok(broker_peer()));
    }
    bench.clear_trace();
    // Reported in the reverse order; handled in the substrate's.
    bench.wake(vec![(I05_LISTENER_TOKEN, readable()), (I05_PIDFD_TOKEN, readable()), (I05_CONN_TOKEN, readable())])
        .expect("a wake");
    let trace = bench.trace();
    let read = position(&trace, &format!("recv #{conn}"), 0);
    let answered = position(&trace, &format!("send #{conn}"), read);
    let probe = position(&trace, &format!("exited #{conn}"), answered + 1);
    let accepted = position(&trace, &format!("accept I05 #{}", conn + 1), probe);
    assert!(read < answered && answered < probe && probe < accepted);
    assert_eq!(bench.last_output(), r#"{"refusedChannel":"CHANNEL_EXISTS"}"#);
}

#[test]
fn the_backlog_is_drained_before_every_frame() {
    let mut bench = Bench::fresh();
    let conn = bench.open_broker();
    bench.lab.borrow_mut().i04.backlog.push_back(vec![PolicyEvent::Base(Event::Backlog { conn: "c9".to_string() })]);
    bench.clear_trace();
    let before = bench.outputs().len();
    bench.broker_says(conn, "GENERATION_STATUS", empty()).expect("a wake");
    let trace = bench.trace();
    let read = position(&trace, &format!("recv #{conn}"), 0);
    let drained = position(&trace, "drain", read);
    position(&trace, &format!("send #{conn}"), drained);
    let outputs = bench.outputs();
    assert_eq!(outputs[before], "{}", "the Backlog event is fed first");
    assert!(outputs[before + 1].starts_with(r#"{"response":"#));
    // The queued connection is the gate's: ACCEPT is inside the backlog.
    bench.lab.borrow_mut().i04.ready.push_back(vec![PolicyEvent::Base(Event::Accept { conn: "c9".to_string() })]);
    bench.wake(vec![(port_token(Owner::I04, 1), readable())]).expect("a wake");
    assert_eq!(bench.last_output(), r#"{"stamp":null}"#);
}

#[test]
fn deadlines_come_first_in_deadline_order_and_a_response_in_the_same_wake_is_late() {
    let mut bench = Bench::fresh();
    let conn = bench.open_writer();
    bench.writer_says(conn, "WRITE_BEGIN", begin()).expect("a wake");
    bench.writer_says(conn, "WRITE_OBJECT", role_create(1)).expect("a wake");
    {
        let mut lab = bench.lab.borrow_mut();
        let now = lab.mono;
        lab.upstream.deadline = Some(now);
        lab.i04.deadline = Some(now + Duration::from_millis(1));
        lab.upstream.due.push_back(vec![PolicyEvent::WUpstream { write_id: 1, outcome: UpstreamOutcome::Timeout }]);
        let outcome = UpstreamOutcome::Response(upstream_response(201));
        lab.upstream.ready.push_back(vec![PolicyEvent::WUpstream { write_id: 1, outcome }]);
    }
    bench.clear_trace();
    bench.wake_with(Wake { advance: Duration::from_millis(5), ready: vec![(port_token(Owner::Upstream, 4), readable())],
                           ..Wake::default() })
        .expect("a wake");
    let trace = bench.trace();
    let upstream_due = position(&trace, "due Upstream", 0);
    let i04_due = position(&trace, "due I04", upstream_due);
    position(&trace, "ready Upstream 4", i04_due);
    let outputs = bench.outputs();
    assert!(outputs[outputs.len() - 2].starts_with(r#"{"classification":"IO_AMBIGUOUS","relayed":true"#));
    assert_eq!(outputs[outputs.len() - 1], r#"{"lateUpstream":"NOT_RELAYED"}"#);
    assert_eq!(bench.sent(conn).len(), 3, "the timeout's answer reached the writer, the late response did not");
}

#[test]
fn eintr_recomputes_the_timeout() {
    let mut bench = Bench::fresh();
    bench.lab.borrow_mut().i04.deadline = Some(Duration::from_micros(5_000_400));
    // An empty wake (EINTR) after 1.2 s, then the next wait.
    bench.wake_with(Wake { advance: Duration::from_millis(1200), ..Wake::default() }).expect("a wake");
    bench.wake(vec![]).expect("a wake");
    assert_eq!(bench.lab.borrow().waits, vec![5001, 3801], "rounded up to milliseconds and recomputed");
    // No deadline at all: no timeout.
    bench.lab.borrow_mut().i04.deadline = None;
    bench.wake(vec![]).expect("a wake");
    assert_eq!(bench.lab.borrow().waits.last(), Some(&-1));
}

// ------------------------------------------------------------------------------------------ expiry

fn bound(lifetimes: Lifetimes) -> (Bench, u64) {
    let mut bench = Bench::new(new_gate(), lifetimes);
    let conn = bench.open_broker();
    bench.broker_says(conn, "BIND_EXECUTION", t01("BIND_EXECUTION")).expect("a wake");
    assert!(bench.gate().bound_run().is_some_and(|run| run.run_nonce == "run-one" && !run.expired));
    (bench, conn)
}

#[test]
fn expiry_by_the_realtime_clock_without_spinning() {
    let (mut bench, _) = bound(lifetimes(NOW + 10));
    bench.wake(vec![]).expect("a wake");
    assert_eq!(bench.lab.borrow().waits.last(), Some(&1000), "capped at one second while the expiry is pending");
    bench.wake_with(Wake { realtime_step: 10_000, ..Wake::default() }).expect("a wake");
    assert_eq!(bench.last_record(), format!(r#"["EXPIRED","{EXECUTION}"]"#));
    assert!(bench.gate().bound_run().is_some_and(|run| run.expired));
    let records = bench.journal().len();
    bench.wake(vec![]).expect("a wake");
    bench.wake(vec![]).expect("a wake");
    assert_eq!(bench.lab.borrow().waits.last(), Some(&-1), "no deadline after EXPIRE: no spin");
    assert_eq!(bench.journal().len(), records);
}

#[test]
fn a_forward_step_is_acted_on_within_the_cap_and_a_backward_step_never_fires() {
    let (mut bench, _) = bound(lifetimes(NOW + 3600));
    let records = bench.journal().len();
    bench.wake_with(Wake { realtime_step: -60_000, ..Wake::default() }).expect("a wake");
    assert_eq!(bench.journal().len(), records, "a backward step never fires early");
    assert_eq!(bench.lab.borrow().waits.last(), Some(&1000));
    bench.wake_with(Wake { realtime_step: 3_700_000, advance: Duration::from_secs(1), ..Wake::default() })
        .expect("a wake");
    assert_eq!(bench.last_record(), format!(r#"["EXPIRED","{EXECUTION}"]"#), "acted on at the wake after the step");
}

#[test]
fn a_due_expiry_comes_before_a_frame() {
    let (mut bench, conn) = bound(lifetimes(NOW + 3600));
    // The clock steps past the end between the wake's start and the frame.
    bench.lab.borrow_mut().realtime_on_recv = Some((NOW + 3600) * 1000);
    let before = bench.outputs().len();
    bench.broker_says(conn, "GENERATION_STATUS", empty()).expect("a wake");
    let outputs = bench.outputs();
    assert_eq!(outputs[before], r#"{"denied":[]}"#, "EXPIRE is fed before the frame");
    assert!(outputs[before + 1].starts_with(r#"{"response":"#));
    assert!(bench.journal().contains(&format!(r#"["EXPIRED","{EXECUTION}"]"#)));
}

#[test]
fn a_due_expiry_comes_before_a_request() {
    let (mut bench, _) = bound(lifetimes(NOW + 3600));
    {
        let mut lab = bench.lab.borrow_mut();
        lab.i04.realtime_on_ready = Some((NOW + 3600) * 1000);
        lab.i04.ready.push_back(vec![PolicyEvent::Base(Event::Backlog { conn: "c1".to_string() }),
                                     PolicyEvent::Base(Event::Accept { conn: "c1".to_string() }),
                                     PolicyEvent::Base(t01_event("REQUEST"))]);
    }
    bench.wake(vec![(port_token(Owner::I04, 1), readable())]).expect("a wake");
    let outputs = bench.outputs();
    let tail: Vec<&str> = outputs[outputs.len() - 4..].iter().map(String::as_str).collect();
    assert_eq!(tail, vec!["{}", r#"{"stamp":null}"#, r#"{"denied":[]}"#,
                          r#"{"decision":"CLOSE","reason":"EXECUTION_EXPIRED"}"#]);
}

#[test]
fn a_bound_run_without_a_lifetime_expires_at_once() {
    let (mut bench, _) = bound(Lifetimes::default());
    bench.wake(vec![]).expect("a wake");
    assert_eq!(bench.lab.borrow().waits.last(), Some(&0));
    assert_eq!(bench.last_record(), format!(r#"["EXPIRED","{EXECUTION}"]"#));
}

#[test]
fn an_unreadable_realtime_clock_expires_at_once() {
    let (mut bench, _) = bound(lifetimes(NOW + 3600));
    bench.lab.borrow_mut().realtime = None;
    bench.wake(vec![]).expect("a wake");
    assert_eq!(bench.last_record(), format!(r#"["EXPIRED","{EXECUTION}"]"#));
}

// ------------------------------------------------------------------------------------------ the 2-second bound

#[test]
fn a_late_i05_answer_is_never_sent() {
    for (stall, late) in [(1999, false), (2000, true), (2500, true)] {
        let mut bench = Bench::fresh();
        let conn = bench.open_broker();
        bench.lab.borrow_mut().stall_on_read = Some(Duration::from_millis(stall));
        bench.broker_says(conn, "GENERATION_STATUS", empty()).expect("a wake");
        if late {
            assert_eq!(bench.sent(conn).len(), 1, "{stall} ms: never sent late");
            assert_eq!(bench.last_output(), r#"{"fatal":"ANSWER_LATE"}"#);
            assert_eq!(bench.last_record(), r#"["INVALIDATED","ANSWER_LATE","HELD"]"#);
            assert_eq!(bench.state(), "HELD");
            assert!(bench.closed(conn));
        } else {
            assert_eq!(bench.sent(conn).len(), 2, "{stall} ms: within the bound");
        }
    }
}

#[test]
fn time_in_the_pre_frame_backlog_drain_counts_against_the_bound() {
    // HE-003A PR review round 1, R1-3 (d): the bound runs from the receive, so the I04 backlog drain before the frame
    // is inside it.
    for (stall, late) in [(1999, false), (2000, true)] {
        let mut bench = Bench::fresh();
        let conn = bench.open_broker();
        {
            let mut lab = bench.lab.borrow_mut();
            lab.i04.backlog.push_back(vec![PolicyEvent::Base(Event::Backlog { conn: "c9".to_string() })]);
            lab.i04.stall_on_backlog = Some(Duration::from_millis(stall));
        }
        bench.broker_says(conn, "GENERATION_STATUS", empty()).expect("a wake");
        assert!(bench.lab.borrow().i04.stall_on_backlog.is_none(), "{stall} ms: the drain ran");
        if late {
            assert_eq!(bench.sent(conn).len(), 1, "{stall} ms: never sent late");
            assert_eq!(bench.last_output(), r#"{"fatal":"ANSWER_LATE"}"#);
            assert_eq!(bench.last_record(), r#"["INVALIDATED","ANSWER_LATE","HELD"]"#);
            assert!(bench.closed(conn));
        } else {
            assert_eq!(bench.sent(conn).len(), 2, "{stall} ms: within the bound");
            assert!(bench.last_output().starts_with(r#"{"response":"#));
        }
    }
}

#[test]
fn a_late_answer_in_an_orderly_state_is_held_not_an_orderly_end() {
    let mut bench = Bench::fresh();
    let conn = bench.open_broker();
    bench.broker_says(conn, "CLOSE_GENERATION", object(vec![("reason", Value::str("NORMAL_DRAIN"))])).expect("a wake");
    assert_eq!(bench.state(), "CLOSED");
    bench.lab.borrow_mut().stall_on_read = Some(Duration::from_millis(2100));
    bench.broker_says(conn, "GENERATION_STATUS", empty()).expect("a wake");
    assert_eq!(bench.last_output(), r#"{"fatal":"ANSWER_LATE"}"#);
    assert_eq!(bench.last_record(), r#"["INVALIDATED","ANSWER_LATE","HELD"]"#);
    assert_eq!(bench.state(), "HELD");
}

#[test]
fn late_synchronous_i07_answers_are_never_sent() {
    for operation in ["MAINTENANCE_STATUS", "WRITE_BEGIN", "WRITE_END"] {
        let mut bench = Bench::fresh();
        let conn = bench.open_writer();
        if operation == "WRITE_END" {
            bench.writer_says(conn, "WRITE_BEGIN", begin()).expect("a wake");
        }
        let answered = bench.sent(conn).len();
        bench.lab.borrow_mut().stall_on_read = Some(Duration::from_millis(2500));
        let payload = if operation == "WRITE_BEGIN" { begin() } else { empty() };
        bench.writer_says(conn, operation, payload).expect("a wake");
        assert_eq!(bench.sent(conn).len(), answered, "{operation}: never sent late");
        let output = bench.last_output();
        assert!(output.starts_with(r#"{"fatal":"ANSWER_LATE""#) && output.ends_with(r#""sessionEnd":"FATAL"}"#),
                "{operation}: {output}");
        let journal = bench.journal();
        let invalidated = journal.iter().position(|record| record == r#"["INVALIDATED","ANSWER_LATE","HELD"]"#)
            .unwrap_or_else(|| panic!("{operation}: {journal:?}"));
        assert!(journal[invalidated..].contains(&r#"["WRITER_SESSION_ENDED","FATAL"]"#.to_string()), "{operation}");
        if operation == "WRITE_BEGIN" {
            assert!(journal[invalidated..].iter().any(|record| record.starts_with(r#"["MAINT_ENDED","SESSION_FATAL""#)),
                    "the owning session's maintenance ends");
        }
        assert_eq!(bench.state(), "HELD", "{operation}");
        assert!(bench.closed(conn) && !bench.gate().session_held(), "{operation}");
    }
}

#[test]
fn a_refused_write_objects_answer_is_not_under_the_two_second_bound() {
    let mut bench = Bench::fresh();
    let conn = bench.open_writer();
    bench.lab.borrow_mut().stall_on_read = Some(Duration::from_millis(2500));
    bench.writer_says(conn, "WRITE_OBJECT", role_create(1)).expect("a wake");
    assert_eq!(bench.sent(conn).len(), 2, "MAINTENANCE_NOT_OPEN is answered (the write bound is the port's)");
    assert!(bench.last_output().contains("MAINTENANCE_NOT_OPEN"));
    assert!(!bench.closed(conn));
}

// ------------------------------------------------------------------------------------------ send failures

#[test]
fn a_failed_i05_send_is_channel_loss() {
    // EAGAIN (the peer stopped reading under lockstep), EPIPE and any other errno: the Os reports a failed send.
    let mut bench = Bench::fresh();
    let conn = bench.open_broker();
    bench.fail_sends(conn);
    bench.broker_says(conn, "GENERATION_STATUS", empty()).expect("a wake");
    assert_eq!(bench.last_output(), r#"{"fatal":"PEER_LOST"}"#);
    assert_eq!(bench.state(), "HELD");
    assert!(bench.closed(conn));

    let mut bench = Bench::fresh();
    let conn = bench.open_broker();
    bench.broker_says(conn, "CLOSE_GENERATION", object(vec![("reason", Value::str("NORMAL_DRAIN"))])).expect("a wake");
    bench.fail_sends(conn);
    bench.broker_says(conn, "GENERATION_STATUS", empty()).expect("a wake");
    assert_eq!(bench.last_output(), r#"{"channelEnd":"ORDERLY"}"#);
    assert_eq!(bench.last_record(), r#"["CHANNEL_ENDED","ORDERLY"]"#);
    assert_eq!(bench.state(), "CLOSED");
    assert!(bench.closed(conn));
}

#[test]
fn a_failed_i07_send_ends_the_session() {
    for operation in ["MAINTENANCE_STATUS", "WRITE_BEGIN", "WRITE_END"] {
        let mut bench = Bench::fresh();
        let conn = bench.open_writer();
        if operation == "WRITE_END" {
            bench.writer_says(conn, "WRITE_BEGIN", begin()).expect("a wake");
        }
        bench.fail_sends(conn);
        let payload = if operation == "WRITE_BEGIN" { begin() } else { empty() };
        bench.writer_says(conn, operation, payload).expect("a wake");
        assert!(bench.last_output().contains(r#""sessionEnd":"ENDED""#), "{operation}");
        assert!(bench.journal().contains(&r#"["WRITER_SESSION_ENDED","ENDED"]"#.to_string()), "{operation}");
        assert!(bench.closed(conn) && !bench.gate().session_held(), "{operation}");
    }
}

// ------------------------------------------------------------------------------------------ registration and exits

#[test]
fn ports_register_their_own_tokens() {
    let shared = lab();
    shared.borrow_mut().i04.register.push_back((SourceId(10), 7));
    shared.borrow_mut().upstream.register.push_back((SourceId(11), 7));
    let bench = Bench::with(new_gate(), Lifetimes::default(), shared);
    let sources = bench.lab.borrow().port_sources.clone();
    assert_eq!(sources.get(&SourceId(10)), Some(&(Owner::I04, (1 << 56) | 7)));
    assert_eq!(sources.get(&SourceId(11)), Some(&(Owner::Upstream, (2 << 56) | 7)));
    assert_eq!(Owner::I04.token(1 << 56), None);

    let shared = lab();
    shared.borrow_mut().i04.register.push_back((SourceId(12), 1 << 56));
    let exit = effect_gate::Substrate::new(new_gate(), FakeOs(shared.clone()), FakeI04(shared.clone()),
                                           FakeUpstream(shared.clone()), effect_gate::ExpectedPeers::r10(),
                                           Lifetimes::default())
        .err();
    assert_eq!(exit, Some(LoopExit::PortToken(Owner::I04)));
}

#[test]
fn the_loop_exits_on_poller_and_accept_failures() {
    let mut bench = Bench::fresh();
    bench.lab.borrow_mut().wait_fails = true;
    assert_eq!(bench.substrate.turn(), Err(LoopExit::Poll));

    let mut bench = Bench::fresh();
    bench.lab.borrow_mut().accepts.entry(Listen::I07).or_default().push_back(Err(OsFailure));
    assert_eq!(bench.wake(vec![(effect_gate::substrate::I07_LISTENER_TOKEN, readable())]), Err(LoopExit::Accept(Listen::I07)));

    let mut bench = Bench::fresh();
    assert_eq!(bench.wake(vec![(99, readable())]), Err(LoopExit::Poll), "a token nobody registered");

    let mut bench = Bench::fresh();
    bench.lab.borrow_mut().watch_fails = true;
    bench.lab.borrow_mut().accepts.entry(Listen::I05).or_default().push_back(Ok(broker_peer()));
    assert_eq!(bench.wake(vec![(I05_LISTENER_TOKEN, readable())]), Err(LoopExit::Poll));
    assert!(bench.closed(1), "the connection is closed before the exit");
}
