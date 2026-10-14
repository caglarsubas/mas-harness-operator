//! HE-003B: the I04 port alone (DESIGN §5.3, §5.4, §7, §9; MODEL_DEFINED R43-R53, R57), over a fake `StreamNet` with
//! a shared fake clock and a rustls test client, with the model's answers given by the test: accepts, the cap and the
//! accept bounds; the deadlines; the `Request` fields; `Close` and `Forward`; the relay's call sequence and its
//! deadline; outcomes that are not relayed; board mismatches; `sync` closures; a hang-up in flight; the linger budget.
//! The registration rules and the loop's order are in `i04_substrate.rs`.

mod tls_support;

use std::time::Duration;

use effect_gate::{Accepted, Classification, ConnectionRefusal, Event, I04Port, Output, OutputKind, PolicyEvent,
                  PolicyOutput, PolicyOutputKind, Port, Readiness};
use gate_tls::{render_response, Exchange, I04Server, SharedExchange, ALPN_HTTP11,
               ACCEPTS_PER_READY, CONNECTION_CAP, DRAIN_LIMIT, PHASE_DEADLINE, READ_BUDGET};
use i05_protocol::sha256;

use tls_support::*;

const GET: &[u8] = b"GET /api/v1/namespaces/planeon-qual/pods/probe-pod HTTP/1.1\r\nHost: 198.51.100.7:6443\r\n\
                     Accept: application/json\r\n\r\n";

fn readable() -> Readiness {
    Readiness { readable: true, ..Readiness::default() }
}

fn output(kind: OutputKind) -> PolicyOutput {
    PolicyOutput { kind: PolicyOutputKind::Base(Output { kind, drain: None, response_frame: None }), drain: None,
                   response_frame: None }
}

struct Rig {
    net: SharedNet,
    exchange: SharedExchange,
    port: I04Server<FakeNet>,
    view: View,
    pki: Pki,
}

fn rig() -> Rig {
    let pki = pki();
    let net = net_lab();
    let exchange = Exchange::shared();
    let port = I04Server::new(FakeNet(net.clone()), production(&pki), exchange.clone());
    Rig { net, exchange, port, view: View::default(), pki }
}

impl Rig {
    /// The loop's part for the port's events: the model's connection map (an Accept opens, a Disconnect removes),
    /// then `sync` after every event.
    fn feed(&mut self, events: &[PolicyEvent]) {
        for event in events {
            match event {
                PolicyEvent::Base(Event::Accept { conn }) => {
                    self.view.open.insert(conn.clone());
                }
                PolicyEvent::Base(Event::Disconnect { conn }) => {
                    self.view.open.remove(conn);
                }
                _ => {}
            }
            self.port.sync(&self.view);
        }
    }

    /// One connection accepted and confirmed; its source number.
    fn accept(&mut self) -> u64 {
        let source = self.net.borrow_mut().connect();
        let events = self.port.ready(0, readable());
        let name = format!("i04-{source}");
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], PolicyEvent::Base(Event::Backlog { conn }) if *conn == name));
        assert!(matches!(&events[1], PolicyEvent::Base(Event::Accept { conn }) if *conn == name));
        self.feed(&events);
        source
    }

    /// A client on `source` that finishes its handshake; the port's events along the way.
    fn handshake(&mut self, source: u64, leaf: Option<Vec<u8>>) -> (Peer, Vec<PolicyEvent>) {
        let mut peer = Peer::new(source, client_config(&self.pki, leaf, &[ALPN_HTTP11]));
        let mut events = Vec::new();
        for _ in 0..6 {
            peer.push(&self.net);
            let more = self.port.ready(source, readable());
            self.feed(&more);
            events.extend(more);
            peer.pull(&self.net);
            if !peer.tls.is_handshaking() && !peer.tls.wants_write() {
                break;
            }
        }
        (peer, events)
    }

    /// An accepted connection with a finished handshake and `request` sent: the port's events.
    fn request(&mut self, request: &[u8]) -> (u64, Peer, Vec<PolicyEvent>) {
        let source = self.accept();
        let (mut peer, events) = self.handshake(source, Some(self.pki.client.clone()));
        assert!(events.is_empty(), "{events:?}");
        peer.write(&self.net, request);
        let events = self.port.ready(source, readable());
        (source, peer, events)
    }

    fn now(&self) -> std::time::Instant {
        self.net.borrow().now()
    }

    fn calls(&self) -> Vec<String> {
        self.net.borrow().calls.clone()
    }

    fn wire_closed(&self, source: u64) -> bool {
        self.net.borrow().wires.get(&source).is_some_and(|wire| wire.closed)
    }
}

#[test]
fn an_accept_yields_backlog_then_accept_and_the_cap_closes_the_rest_unfed() {
    let mut rig = rig();
    for _ in 0..CONNECTION_CAP {
        rig.accept();
    }
    let over = rig.net.borrow_mut().connect();
    let events = rig.port.ready(0, readable());
    assert!(events.is_empty(), "over the cap: never fed");
    assert!(rig.wire_closed(over));
    assert_eq!(rig.port.held().len(), CONNECTION_CAP);
}

#[test]
fn one_readiness_accepts_at_most_64_and_skip_and_failed_are_handled() {
    let mut rig = rig();
    for _ in 0..(ACCEPTS_PER_READY + 10) {
        rig.net.borrow_mut().queue.push_back(Accepted::Skip);
    }
    assert!(rig.port.ready(0, readable()).is_empty());
    assert_eq!(rig.net.borrow().queue.len(), 10, "64 accepts in one readiness, the rest at the next wake");
    assert_eq!(rig.port.failure(), None);
    rig.net.borrow_mut().queue.clear();
    rig.net.borrow_mut().queue.push_back(Accepted::Failed(24));
    rig.port.ready(0, readable());
    assert_eq!(rig.port.failure(), Some("an accept on the I04 listener failed"));
}

#[test]
fn the_drain_accepts_until_empty_and_fails_closed_past_1024() {
    let mut rig = rig();
    for _ in 0..DRAIN_LIMIT {
        rig.net.borrow_mut().queue.push_back(Accepted::Skip);
    }
    assert!(rig.port.drain_backlog().is_empty());
    assert_eq!(rig.port.failure(), None, "1,024 accepts and then an empty queue");
    let mut rig = self::rig();
    for _ in 0..(DRAIN_LIMIT + 5) {
        rig.net.borrow_mut().queue.push_back(Accepted::Skip);
    }
    rig.port.drain_backlog();
    assert_eq!(rig.port.failure(), Some("the pre-frame drain passed 1,024 accepts"));
    // A batch of accepts in one drain: every connection is fed and confirmed by the sync after its own Accept.
    let mut rig = self::rig();
    let sources: Vec<u64> = (0..3).map(|_| rig.net.borrow_mut().connect()).collect();
    let events = rig.port.drain_backlog();
    assert_eq!(events.len(), 6);
    rig.feed(&events);
    assert_eq!(rig.port.held().len(), 3);
    assert!(sources.iter().all(|source| !rig.wire_closed(*source)));
}

#[test]
fn each_deadline_ends_in_a_disconnect() {
    // The handshake deadline: accept + 10 s; nothing was sent, so no close_notify.
    let mut rig = rig();
    let source = rig.accept();
    rig.net.borrow_mut().advance(PHASE_DEADLINE - Duration::from_millis(1));
    assert!(rig.port.due(rig.now()).is_empty());
    rig.net.borrow_mut().advance(Duration::from_millis(1));
    let events = rig.port.due(rig.now());
    assert!(matches!(&events[..], [PolicyEvent::Base(Event::Disconnect { conn })] if *conn == format!("i04-{source}")));
    assert!(rig.wire_closed(source));
    assert_eq!(rig.port.next_deadline(), None);
    // The request deadline: handshake + 10 s; the client sees close_notify.
    let mut rig = self::rig();
    let source = rig.accept();
    let (mut peer, _) = rig.handshake(source, Some(rig.pki.client.clone()));
    peer.write(&rig.net, &GET[..10]);
    assert!(rig.port.ready(source, readable()).is_empty());
    rig.net.borrow_mut().advance(PHASE_DEADLINE);
    let events = rig.port.due(rig.now());
    assert!(matches!(&events[..], [PolicyEvent::Base(Event::Disconnect { .. })]));
    peer.pull(&rig.net);
    assert!(peer.closed_by_server() && peer.received.is_empty());
}

#[test]
fn a_refused_handshake_and_an_eof_end_in_a_disconnect() {
    let mut rig = rig();
    let source = rig.accept();
    let (_, events) = rig.handshake(source, None);
    assert!(matches!(&events[..], [PolicyEvent::Base(Event::Disconnect { .. })]), "{events:?}");
    assert!(rig.wire_closed(source));
    let source = rig.accept();
    rig.net.borrow_mut().wires.get_mut(&source).expect("a wire").client_eof = true;
    let events = rig.port.ready(source, readable());
    assert!(matches!(&events[..], [PolicyEvent::Base(Event::Disconnect { .. })]));
}

#[test]
fn the_request_carries_the_head_the_digests_and_is_staged() {
    let mut rig = rig();
    let (source, _, events) = rig.request(GET);
    let name = format!("i04-{source}");
    match &events[..] {
        [PolicyEvent::Base(Event::Request { conn, certificate_digest, head, body_digest })] => {
            assert_eq!(conn, &name);
            assert_eq!(certificate_digest, &sha256::prefixed(&rig.pki.client));
            assert_eq!(head.as_bytes(), GET);
            assert_eq!(body_digest, &None);
        }
        other => panic!("one Request, not {other:?}"),
    }
    let board = rig.exchange.borrow();
    let staged = board.request().expect("staged");
    assert_eq!((staged.conn.as_str(), staged.head.as_bytes(), staged.forwarded), (name.as_str(), GET, None));
    // Never a second request: later bytes are not read.
    assert_eq!(rig.port.next_deadline(), None);
}

#[test]
fn close_sends_close_notify_and_no_http_byte_once() {
    let mut rig = rig();
    let (source, mut peer, _) = rig.request(GET);
    rig.port.apply(&output(OutputKind::Close(ConnectionRefusal::RequestMismatch)));
    peer.pull(&rig.net);
    assert!(peer.closed_by_server() && peer.received.is_empty(), "close_notify and no HTTP byte");
    assert!(rig.wire_closed(source));
    assert!(rig.exchange.borrow().request().is_none(), "the staged request is dropped");
    // After a sync closure (the expiry case), the Close sends no second close_notify.
    let (source, mut peer, events) = rig.request(GET);
    let name = format!("i04-{source}");
    assert_eq!(events.len(), 1);
    rig.view.open.remove(&name);
    rig.port.sync(&rig.view);
    let sends = rig.calls().iter().filter(|call| call.starts_with(&format!("send {source} "))).count();
    rig.port.apply(&output(OutputKind::Close(ConnectionRefusal::ConnectionClosed)));
    let after = rig.calls().iter().filter(|call| call.starts_with(&format!("send {source} "))).count();
    assert_eq!(sends, after, "no second close_notify");
    peer.pull(&rig.net);
    assert!(peer.closed_by_server());
    assert!(rig.exchange.borrow().request().is_none());
}

#[test]
fn forward_puts_the_connection_in_flight_and_confirms_the_board() {
    let mut rig = rig();
    let (source, _, _) = rig.request(GET);
    rig.port.apply(&output(OutputKind::Forward { action_id: 1 }));
    assert_eq!(rig.exchange.borrow().request().map(|request| request.forwarded), Some(Some(1)));
    assert_eq!(rig.port.failure(), None);
    assert!(!rig.wire_closed(source));
    // An occupied request slot when the next request is returned is a port failure.
    let mut rig = self::rig();
    rig.exchange.borrow_mut().stage_request("i04-99", "GET", b"").expect("staged");
    rig.request(GET);
    assert_eq!(rig.port.failure(), Some("the exchange board's request slot was occupied or busy"));
}

fn relayed() -> PolicyOutput {
    output(OutputKind::Upstream { classification: Classification::DeliveredResult, relayed: true, aborted: false })
}

#[test]
fn a_relayed_response_is_rendered_then_close_notify_shutdown_linger_and_close() {
    let mut rig = rig();
    let (source, mut peer, _) = rig.request(GET);
    let name = format!("i04-{source}");
    rig.port.apply(&output(OutputKind::Forward { action_id: 1 }));
    let body = br#"{"kind":"Pod","metadata":{"name":"probe-pod"}}"#.to_vec();
    rig.exchange.borrow_mut().stage_response(&name, 200, body.clone(), Some("u".into()), Some("7".into())).expect("staged");
    rig.port.apply(&relayed());
    // The model closes the consumed connection when the outcome is recorded; the relay keeps it.
    rig.view.open.remove(&name);
    rig.port.sync(&rig.view);
    peer.pull(&rig.net);
    assert_eq!(peer.received, render_response(200, &body).expect("rendered"), "exactly the rendered response");
    assert!(peer.closed_by_server(), "close_notify after the response");
    let calls = rig.calls();
    let shutdown = calls.iter().position(|call| *call == format!("shutdown {source}")).expect("the write side is shut");
    let last_send = calls.iter().rposition(|call| call.starts_with(&format!("send {source} "))).expect("sends");
    assert!(last_send < shutdown, "shutdown only once nothing is pending");
    // The linger reads and discards within the per-wake budget, then EOF closes.
    rig.net.borrow_mut().wires.get_mut(&source).expect("a wire").to_server.extend(vec![b'z'; READ_BUDGET + 100]);
    rig.port.ready(source, readable());
    assert_eq!(rig.net.borrow().wires.get(&source).map(|wire| wire.to_server.len()), Some(100), "64 KiB per wake");
    rig.port.ready(source, readable());
    rig.net.borrow_mut().wires.get_mut(&source).expect("a wire").client_eof = true;
    rig.port.ready(source, readable());
    assert!(rig.wire_closed(source));
    assert!(!rig.exchange.borrow().has_response());
}

#[test]
fn the_relay_deadline_with_bytes_pending_closes_without_the_shutdown() {
    let mut rig = rig();
    let (source, _, _) = rig.request(GET);
    let name = format!("i04-{source}");
    rig.port.apply(&output(OutputKind::Forward { action_id: 1 }));
    rig.net.borrow_mut().wires.get_mut(&source).expect("a wire").send_room = Some(0);
    rig.exchange.borrow_mut().stage_response(&name, 200, b"{}".to_vec(), None, None).expect("staged");
    rig.port.apply(&relayed());
    rig.net.borrow_mut().advance(PHASE_DEADLINE);
    assert!(rig.port.due(rig.now()).is_empty(), "nothing is fed after a request");
    assert!(rig.wire_closed(source));
    assert!(!rig.calls().contains(&format!("shutdown {source}")));
}

#[test]
fn an_outcome_not_relayed_closes_without_a_byte_and_drops_the_response() {
    let mut rig = rig();
    let (source, mut peer, _) = rig.request(GET);
    let name = format!("i04-{source}");
    rig.port.apply(&output(OutputKind::Forward { action_id: 1 }));
    rig.exchange.borrow_mut().stage_response(&name, 200, b"{}".to_vec(), None, None).expect("staged");
    let sends = rig.calls().len();
    rig.port.apply(&output(OutputKind::Upstream { classification: Classification::IoAmbiguous, relayed: false,
                                                  aborted: false }));
    assert!(rig.wire_closed(source));
    assert!(!rig.calls()[sends..].iter().any(|call| call.starts_with("send")), "no byte");
    assert!(!rig.exchange.borrow().has_response());
    peer.pull(&rig.net);
    assert!(peer.received.is_empty());
}

#[test]
fn a_board_mismatch_closes_and_fails_the_port() {
    let mut rig = rig();
    let (source, _, _) = rig.request(GET);
    rig.port.apply(&output(OutputKind::Forward { action_id: 1 }));
    rig.exchange.borrow_mut().stage_response("i04-somebody-else", 200, b"{}".to_vec(), None, None).expect("staged");
    rig.port.apply(&relayed());
    assert!(rig.wire_closed(source));
    assert_eq!(rig.port.failure(), Some("the staged response does not match the connection in flight"));
}

#[test]
fn sync_closes_a_model_closed_connection_without_a_disconnect() {
    let mut rig = rig();
    let source = rig.accept();
    let (mut peer, _) = rig.handshake(source, Some(rig.pki.client.clone()));
    rig.view.open.remove(&format!("i04-{source}"));
    rig.port.sync(&rig.view);
    assert!(rig.wire_closed(source));
    peer.pull(&rig.net);
    assert!(peer.closed_by_server());
    // An unconfirmed connection (its Accept not yet fed) is never closed by sync.
    let fresh = rig.net.borrow_mut().connect();
    rig.port.ready(0, readable());
    rig.port.sync(&rig.view);
    assert!(!rig.wire_closed(fresh));
}

#[test]
fn a_client_gone_in_flight_skips_the_relay() {
    let mut rig = rig();
    let (source, _, _) = rig.request(GET);
    let name = format!("i04-{source}");
    rig.port.apply(&output(OutputKind::Forward { action_id: 1 }));
    rig.port.ready(source, Readiness { hangup: true, ..Readiness::default() });
    assert!(rig.wire_closed(source));
    rig.exchange.borrow_mut().stage_response(&name, 200, b"{}".to_vec(), None, None).expect("staged");
    let calls = rig.calls().len();
    rig.port.apply(&relayed());
    assert!(!rig.calls()[calls..].iter().any(|call| call.starts_with("send") || call.starts_with("close")));
    assert!(!rig.exchange.borrow().has_response(), "the staged response is taken");
    assert_eq!(rig.port.failure(), None);
}
