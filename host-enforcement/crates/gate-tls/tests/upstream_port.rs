//! HE-003C: the upstream port alone (DESIGN §2, §3, §7; MODEL_DEFINED R59-R64), over a fake `ConnectNet` with the
//! fake clock and a scripted rustls apiserver, with the model's answers given by the test: the connect results; the
//! handshake refusals (wrong CA, missing IP SAN, a TLS 1.2 ServerHello); the identity each channel presents; no
//! resumption, early data or SNI after a real ticket; the exact request bytes (I05 staged, I07 rendered and started
//! through `sync`); the bounds and phase deadlines on the fake clock; the seal and session-end aborts; and the port
//! failures (a mismatched action ID, a start while an exchange is open, a pending write without its request).

mod tls_support;
mod upstream_support;

use std::sync::Arc;
use std::time::Duration;

use effect_gate::net::Connecting;
use effect_gate::{Event, GateView, OutputKind, PolicyEvent, Port, Readiness, UpstreamOutcome};
use gate_tls::{CONNECT_DEADLINE, HANDSHAKE_DEADLINE, UPSTREAM_BOUND, WRITE_BOUND};
use i05_protocol::{Kind, Verb};
use rustls::client::{ClientSessionMemoryCache, Resumption};

use upstream_support::*;

const POD: &[u8] = br#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"probe-pod","namespace":"planeon-qual","uid":"11111111-aaaa-4bbb-8ccc-000000000001","resourceVersion":"42"}}"#;
const ROLE: &[u8] = br#"{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"planeon-role","namespace":"planeon-qual","uid":"u-2","resourceVersion":"43"},"rules":[]}"#;

fn is_lost_i05(events: &[PolicyEvent]) -> bool {
    matches!(events, [PolicyEvent::Base(Event::UpstreamLost { conn })] if conn == "i04-7")
}

fn is_lost_i07(events: &[PolicyEvent]) -> bool {
    matches!(events, [PolicyEvent::WUpstream { write_id: 1, outcome: UpstreamOutcome::Lost }])
}

fn is_response_i05(events: &[PolicyEvent], status: i64) -> bool {
    matches!(events, [PolicyEvent::Base(Event::UpstreamResponse { conn, response })]
             if conn == "i04-7" && response.http_status == status)
}

// ------------------------------------------------------------------------------------------ arming and connect

#[test]
fn a_forward_arms_with_a_start_deadline_at_the_anchor_and_connects_at_the_next_due() {
    let mut rig = rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    let anchor = rig.now();
    assert!(rig.port.is_open());
    assert_eq!(rig.port.next_deadline(), Some(anchor), "a zero wait: the start runs at the next wake");
    assert!(rig.calls().is_empty(), "no socket before the due");
    assert!(rig.exchange.borrow().request().is_none(), "the confirmed request was taken");
    let events = rig.connect(Ok(Connecting::InProgress));
    assert!(events.is_empty());
    assert_eq!(rig.lab.borrow().addresses, vec![APISERVER], "the one parsed apiserver address");
    assert_eq!(rig.port.next_deadline(), Some(anchor + CONNECT_DEADLINE), "the I05 connect phase deadline");
}

#[test]
fn an_immediate_connection_refusal_is_exactly_one_lost_at_the_next_wake() {
    let mut rig = rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    let events = rig.connect(Err(111)); // ECONNREFUSED from the non-blocking connect itself
    assert!(is_lost_i05(&events), "{events:?}");
    assert!(!rig.port.is_open());
    assert_eq!(rig.port.next_deadline(), None, "every deadline cleared after the outcome");
    let now = rig.now();
    assert!(rig.port.due(now).is_empty(), "exactly one");
    // I07 likewise, and EMFILE from socket() is the same LOST.
    let mut rig = upstream_support::rig();
    rig.start_write(1, rendered(ROLE_CREATE));
    assert!(is_lost_i07(&rig.connect(Err(24))));
    assert_eq!(rig.port.failure(), None);
}

#[test]
fn an_immediate_connection_success_starts_the_handshake_at_once() {
    let mut rig = rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    let events = rig.connect(Ok(Connecting::Connected));
    assert!(events.is_empty());
    let source = rig.lab.borrow().last();
    assert!(!rig.lab.borrow().lines[&source].to_apiserver.is_empty(), "the ClientHello is sent in the same due");
    assert!(!rig.calls().iter().any(|call| call.starts_with("so_error")), "no SO_ERROR for an immediate success");
    assert_eq!(rig.port.next_deadline(), Some(rig.now() + HANDSHAKE_DEADLINE));
}

#[test]
fn in_progress_then_so_error_and_readiness_errors_are_lost() {
    // SO_ERROR non-zero once writable.
    let mut rig = rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    rig.connect(Ok(Connecting::InProgress));
    let source = rig.lab.borrow().last();
    rig.lab.borrow_mut().so_error = 111;
    let events = rig.port.ready(source, writable());
    assert!(is_lost_i05(&events), "{events:?}");
    assert!(rig.closed(source));
    // A readable-only readiness during the connect waits; an error or a hang-up is LOST.
    for readiness in [Readiness { error: true, ..Readiness::default() }, Readiness { hangup: true, writable: true, ..Readiness::default() }] {
        let mut rig = upstream_support::rig();
        rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
        rig.connect(Ok(Connecting::InProgress));
        let source = rig.lab.borrow().last();
        assert!(rig.port.ready(source, readable()).is_empty());
        assert!(is_lost_i05(&rig.port.ready(source, readiness)));
        assert!(!rig.calls().iter().any(|call| call.starts_with("so_error")), "no SO_ERROR read after an error");
    }
    // SO_ERROR 0: connected, the ClientHello follows.
    let mut rig = upstream_support::rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    rig.connect(Ok(Connecting::InProgress));
    let source = rig.lab.borrow().last();
    assert!(rig.port.ready(source, writable()).is_empty());
    assert!(rig.calls().contains(&format!("so_error {source}")));
    assert!(!rig.lab.borrow().lines[&source].to_apiserver.is_empty());
}

#[test]
fn a_reset_and_an_eof_before_the_answer_are_lost() {
    for (reset, partial) in [(true, false), (false, false), (false, true)] {
        let mut rig = rig();
        rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
        let (mut apiserver, events) = rig.handshake();
        assert!(events.is_empty());
        if partial {
            apiserver.respond(&rig.lab, b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n{}");
        }
        {
            let mut lab = rig.lab.borrow_mut();
            let line = lab.lines.get_mut(&apiserver.source).expect("the line");
            if reset { line.reset = true } else { line.eof = true }
        }
        let events = rig.port.ready(apiserver.source, readable());
        assert!(is_lost_i05(&events), "reset {reset} partial {partial}: {events:?}");
        assert!(rig.closed(apiserver.source));
    }
}

// ------------------------------------------------------------------------------------------ the handshake

#[test]
fn a_server_certificate_of_another_ca_or_without_the_ip_san_is_lost() {
    // The client trusts another serving CA.
    let pki = upstream_pki();
    let effect = effect_config(&pki, &pki.other_ca);
    let writer = writer_config(&pki, &pki.serving_ca);
    let mut rig = rig_with(effect, writer, pki);
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    let (apiserver, events) = rig.handshake();
    assert!(is_lost_i05(&events), "{events:?}");
    assert!(apiserver.received.is_empty(), "no request byte reached the apiserver");
    // The apiserver's leaf has no IP SAN, or another loopback address's.
    for san in [tls_support::San::None, tls_support::San::Ip([127, 0, 0, 2])] {
        let mut rig = upstream_support::rig();
        let leaf = tls_support::certificate(
            &tls_support::Spec::leaf(30, "planeon serving ca", "kube-apiserver", tls_support::SERVER_AUTH, san),
            &rig.pki.apiserver_key, &rig.pki.serving_ca_key);
        let config = apiserver_config_with(&rig.pki, &leaf, 0);
        rig.start_write(1, rendered(ROLE_CREATE));
        let (apiserver, events) = rig.handshake_with(config);
        assert!(is_lost_i07(&events), "{san:?}: {events:?}");
        assert!(apiserver.received.is_empty());
    }
}

/// A TLS 1.2 ServerHello (no supported_versions extension) choosing an ECDHE suite, as fixed bytes: the scripted
/// apiserver cannot send one with `tls12` off.
fn tls12_server_hello() -> Vec<u8> {
    let mut hello = vec![0x03, 0x03];
    hello.extend_from_slice(&[0x24; 32]);
    hello.push(0); // no session ID
    hello.extend_from_slice(&[0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    hello.push(0); // null compression
    hello.extend_from_slice(&[0x00, 0x00]); // no extensions
    let mut handshake = vec![0x02, 0x00];
    handshake.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&hello);
    let mut record = vec![0x16, 0x03, 0x03];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[test]
fn a_tls_12_server_hello_is_lost() {
    let mut rig = rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    assert!(rig.connect(Ok(Connecting::Connected)).is_empty());
    let source = rig.lab.borrow().last();
    rig.lab.borrow_mut().lines.get_mut(&source).expect("the line").to_gate.extend(tls12_server_hello());
    let events = rig.port.ready(source, readable());
    assert!(is_lost_i05(&events), "{events:?}");
    let sent = rig.lab.borrow().lines[&source].to_apiserver.clone();
    assert_eq!(tls_support::record_types(&sent).last(), Some(&0x15), "the client's alert was flushed");
}

#[test]
fn each_channel_presents_its_own_identity() {
    let mut rig = rig();
    let (apiserver, events) = rig.i05_exchange(Verb::Get, Kind::Pod, "probe-pod", &http("200 OK", POD));
    assert!(is_response_i05(&events, 200), "{events:?}");
    assert_eq!(apiserver.peer_leaf(), Some(rig.pki.effect.clone()), "I05: the gate effect identity");
    let mut rig = upstream_support::rig();
    let (apiserver, events) = rig.i07_exchange(ROLE_CREATE, &http("201 Created", ROLE));
    assert!(matches!(&events[..], [PolicyEvent::WUpstream { write_id: 1, outcome: UpstreamOutcome::Response(_) }]),
            "{events:?}");
    assert_eq!(apiserver.peer_leaf(), Some(rig.pki.writer.clone()), "I07: the gate writer identity");
    assert_eq!(apiserver.tls.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(apiserver.tls.alpn_protocol(), Some(b"http/1.1".as_slice()));
}

#[test]
fn after_a_real_ticket_the_next_client_hello_offers_no_resumption_early_data_or_sni() {
    let mut rig = rig();
    let ticketing = apiserver_config_with(&rig.pki, &rig.pki.apiserver, 4);
    // Control: a rustls test client with a session store gets a ticket from this configuration and offers it.
    let store = Arc::new(ClientSessionMemoryCache::new(8));
    let mut control = (*effect_config(&rig.pki, &rig.pki.serving_ca)).clone();
    control.resumption = Resumption::store(store);
    let control = Arc::new(control);
    for leg in 0..2 {
        let mut client = rustls::ClientConnection::new(control.clone(), gate_tls::server_name(&APISERVER)).expect("a client");
        let mut server = rustls::ServerConnection::new(ticketing.clone()).expect("a server");
        if leg == 1 {
            let first = tls_support::drain_client(&mut client);
            assert!(client_hello(&first).0.contains(&41), "the control offers the issued ticket");
            server.read_tls(&mut first.as_slice()).expect("read");
            server.process_new_packets().expect("the ClientHello");
        }
        let mut pump = || {
            for _ in 0..10 {
                let to_server = tls_support::drain_client(&mut client);
                let mut slice = to_server.as_slice();
                while !slice.is_empty() {
                    server.read_tls(&mut slice).expect("read");
                    server.process_new_packets().expect("server");
                }
                let to_client = tls_support::drain_server(&mut server);
                let mut slice = to_client.as_slice();
                while !slice.is_empty() {
                    client.read_tls(&mut slice).expect("read");
                    client.process_new_packets().expect("client");
                }
            }
        };
        pump();
    }
    // The gate's client: a full exchange with the ticketing apiserver (tickets delivered), then a second exchange.
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    let (mut apiserver, events) = rig.handshake_with(ticketing.clone());
    assert!(events.is_empty());
    assert!(is_response_i05(&rig.answer(&mut apiserver, &http("200 OK", POD)), 200));
    let first_hello = {
        rig.exchange.borrow_mut().drop_response();
        let (head, body) = i05_request(Verb::Get, Kind::Pod, "probe-pod");
        rig.forward("i04-8", &head, &body, 2, 2);
        assert!(rig.connect(Ok(Connecting::Connected)).is_empty());
        let source = rig.lab.borrow().last();
        rig.lab.borrow().lines[&source].to_apiserver.clone()
    };
    let (extensions, alpn) = client_hello(&first_hello);
    for (code, what) in [(41, "pre_shared_key"), (42, "early_data"), (0, "server_name")] {
        assert!(!extensions.contains(&code), "the ClientHello carries no {what} extension: {extensions:?}");
    }
    assert_eq!(alpn, vec![b"http/1.1".to_vec()], "ALPN http/1.1 only");
}

// ------------------------------------------------------------------------------------------ the request

#[test]
fn the_i05_request_is_exactly_the_staged_bytes_and_the_i07_request_the_rendered_ones() {
    for (verb, kind, name) in [(Verb::Get, Kind::Pod, "probe-pod"), (Verb::Create, Kind::Service, "probe-svc"),
                               (Verb::Delete, Kind::ConfigMap, "probe-cm")] {
        let mut rig = rig();
        let request = rig.forward_i05(verb, kind, name);
        let (apiserver, _) = rig.handshake();
        assert_eq!(apiserver.received, request, "{verb:?} {kind:?}");
        assert!(!String::from_utf8_lossy(&apiserver.received).contains("Connection: close"), "nothing added");
    }
    for payload in [ROLE_CREATE, ROLE_UPDATE, ROLE_DELETE] {
        let mut rig = rig();
        let request = rig.start_write(1, rendered(payload));
        assert_eq!(rig.port.next_deadline(), Some(rig.now()), "the I07 start through sync");
        let (apiserver, _) = rig.handshake();
        assert_eq!(apiserver.received, request);
    }
}

// ------------------------------------------------------------------------------------------ bounds and deadlines

#[test]
fn the_i05_bound_feeds_one_timeout_and_clears_every_deadline() {
    let mut rig = rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    let anchor = rig.now();
    let (apiserver, events) = rig.handshake();
    assert!(events.is_empty());
    assert_eq!(rig.port.next_deadline(), Some(anchor + UPSTREAM_BOUND), "after the handshake only the bound");
    rig.advance(UPSTREAM_BOUND - Duration::from_millis(1));
    assert!(rig.port.due(rig.now()).is_empty());
    rig.advance(Duration::from_millis(1));
    let events = rig.port.due(rig.now());
    assert!(matches!(&events[..], [PolicyEvent::Base(Event::UpstreamTimeout { conn })] if conn == "i04-7"), "{events:?}");
    assert!(rig.closed(apiserver.source));
    assert_eq!(rig.port.next_deadline(), None);
    assert!(rig.port.due(rig.now()).is_empty(), "fed once");
    assert!(rig.port.ready(apiserver.source, readable()).is_empty(), "a closed exchange's token feeds nothing");
}

#[test]
fn the_i07_bound_is_ten_seconds_with_no_phase_deadline() {
    let mut rig = rig();
    rig.start_write(1, rendered(ROLE_CREATE));
    let anchor = rig.now();
    assert!(rig.connect(Ok(Connecting::InProgress)).is_empty());
    assert_eq!(rig.port.next_deadline(), Some(anchor + WRITE_BOUND), "no connect deadline for I07");
    rig.advance(WRITE_BOUND);
    let events = rig.port.due(rig.now());
    assert!(matches!(&events[..], [PolicyEvent::WUpstream { write_id: 1, outcome: UpstreamOutcome::Timeout }]),
            "{events:?}");
    assert!(rig.port.due(rig.now()).is_empty() && rig.port.next_deadline().is_none());
}

#[test]
fn i05_phase_deadlines_are_lost_and_a_tie_with_the_bound_is_a_timeout() {
    // The connect phase deadline, strictly earlier than the bound: LOST.
    let mut rig = rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    rig.connect(Ok(Connecting::InProgress));
    rig.advance(CONNECT_DEADLINE);
    assert!(is_lost_i05(&rig.port.due(rig.now())));
    // The handshake phase deadline: LOST.
    let mut rig = upstream_support::rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    rig.connect(Ok(Connecting::Connected));
    rig.advance(HANDSHAKE_DEADLINE);
    assert!(is_lost_i05(&rig.port.due(rig.now())));
    // The connect starts 890 s late, so its phase deadline equals the bound: the bound wins.
    let mut rig = upstream_support::rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    let anchor = rig.now();
    rig.advance(UPSTREAM_BOUND - CONNECT_DEADLINE);
    rig.connect(Ok(Connecting::InProgress));
    assert_eq!(rig.port.next_deadline(), Some(anchor + UPSTREAM_BOUND));
    rig.advance(CONNECT_DEADLINE);
    let events = rig.port.due(rig.now());
    assert!(matches!(&events[..], [PolicyEvent::Base(Event::UpstreamTimeout { .. })]), "{events:?}");
    // A start whose due comes after the bound: the TIMEOUT, no connect.
    let mut rig = upstream_support::rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    rig.advance(UPSTREAM_BOUND);
    assert!(matches!(&rig.port.due(rig.now())[..], [PolicyEvent::Base(Event::UpstreamTimeout { .. })]));
    assert!(rig.lab.borrow().addresses.is_empty());
}

#[test]
fn an_answer_completed_after_the_bound_feeds_nothing_and_the_timeout_follows() {
    let mut rig = rig();
    rig.start_write(1, rendered(ROLE_CREATE));
    let (mut apiserver, _) = rig.handshake();
    rig.advance(WRITE_BOUND + Duration::from_millis(5));
    // The deadlines were fed earlier in this wake (none due then, as far as that check saw); the answer completes now.
    let events = rig.answer(&mut apiserver, &http("201 Created", ROLE));
    assert!(events.is_empty(), "nothing fed past the bound: {events:?}");
    assert!(rig.closed(apiserver.source), "the descriptor closes at once");
    assert!(rig.port.next_deadline().is_some_and(|deadline| deadline <= rig.now()), "a zero wait for the TIMEOUT");
    let events = rig.port.due(rig.now());
    assert!(matches!(&events[..], [PolicyEvent::WUpstream { write_id: 1, outcome: UpstreamOutcome::Timeout }]));
    assert!(rig.port.next_deadline().is_none());
}

#[test]
fn after_a_response_every_deadline_is_cleared_and_stale_tokens_feed_nothing() {
    let mut rig = rig();
    let (apiserver, events) = rig.i05_exchange(Verb::Get, Kind::Pod, "probe-pod", &http("200 OK", POD));
    assert!(is_response_i05(&events, 200));
    assert!(!rig.port.is_open() && rig.port.next_deadline().is_none());
    assert!(rig.closed(apiserver.source));
    assert!(rig.port.ready(apiserver.source, both()).is_empty());
    assert!(rig.port.due(rig.now() + UPSTREAM_BOUND).is_empty());
    // The server's close_notify after the answer is not surplus (sent by the gate too).
    let sent = rig.lab.borrow().lines[&apiserver.source].to_apiserver.clone();
    let mut apiserver = apiserver;
    let mut slice = sent.as_slice();
    while !slice.is_empty() {
        if apiserver.tls.read_tls(&mut slice).is_err() || apiserver.tls.process_new_packets().is_err() {
            break;
        }
    }
    let mut chunk = [0u8; 16];
    assert!(matches!(std::io::Read::read(&mut apiserver.tls.reader(), &mut chunk), Ok(0)), "the gate sent close_notify");
    // A token of another source while an exchange is open feeds nothing either.
    let mut rig = upstream_support::rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    rig.connect(Ok(Connecting::InProgress));
    let source = rig.lab.borrow().last();
    assert!(rig.port.ready(source + 1, writable()).is_empty() && rig.port.ready(0, writable()).is_empty());
    assert!(rig.port.is_open());
}

// ------------------------------------------------------------------------------------------ aborts and failures

#[test]
fn a_seal_and_a_session_end_close_the_exchange_and_feed_nothing() {
    let mut rig = rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    let (apiserver, _) = rig.handshake();
    rig.view.open.clear(); // the model sealed the consumed action (Decision 1)
    rig.port.sync(&rig.view);
    assert!(!rig.port.is_open() && rig.closed(apiserver.source) && rig.port.next_deadline().is_none());
    assert!(rig.port.due(rig.now() + UPSTREAM_BOUND).is_empty() && rig.port.ready(apiserver.source, both()).is_empty());
    assert_eq!(rig.port.failure(), None);
    let mut rig = upstream_support::rig();
    rig.start_write(1, rendered(ROLE_CREATE));
    rig.connect(Ok(Connecting::InProgress));
    let source = rig.lab.borrow().last();
    rig.view.pending = None; // the session ended; the model aborted the write
    rig.port.sync(&rig.view);
    assert!(!rig.port.is_open() && rig.closed(source));
    assert!(rig.port.due(rig.now() + WRITE_BOUND).is_empty());
    // Armed only (no socket yet): closed without a call.
    let mut rig = upstream_support::rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    rig.view.open.clear();
    rig.port.sync(&rig.view);
    assert!(!rig.port.is_open() && rig.calls().is_empty());
}

#[test]
fn a_forward_whose_action_id_does_not_match_the_confirmed_request_is_a_port_failure() {
    let mut rig = rig();
    let (head, body) = i05_request(Verb::Get, Kind::Pod, "probe-pod");
    rig.forward("i04-7", &head, &body, 1, 2);
    assert_eq!(rig.port.failure(), Some("a forward without the staged request confirmed with its action ID"));
    assert!(!rig.port.is_open());
    assert!(rig.exchange.borrow().request().is_some(), "the board keeps what it was not asked for");
    // An unconfirmed request is not taken either.
    let mut rig = upstream_support::rig();
    rig.exchange.borrow_mut().stage_request("i04-7", &head, &body).expect("staged");
    rig.port.apply(&output(OutputKind::Forward { action_id: 1 }));
    assert!(rig.port.failure().is_some());
    // A staged head that is not one of the rendered forms.
    let mut rig = upstream_support::rig();
    rig.forward("i04-7", "PATCH /api/v1/namespaces/planeon-qual/pods/probe-pod HTTP/1.1\r\n\r\n", b"", 1, 1);
    assert_eq!(rig.port.failure(), Some("the forwarded request is not one of the rendered I05 forms"));
}

#[test]
fn a_start_while_an_exchange_is_open_is_a_port_failure() {
    let mut rig = rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    let (head, body) = i05_request(Verb::Get, Kind::Pod, "probe-pod");
    rig.forward("i04-8", &head, &body, 2, 2);
    assert_eq!(rig.port.failure(), Some("an I05 exchange started while an exchange is open"));
    let mut rig = upstream_support::rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    rig.start_write(1, rendered(ROLE_CREATE));
    assert_eq!(rig.port.failure(), Some("an I07 write started while an exchange is open"));
    let mut rig = upstream_support::rig();
    rig.start_write(1, rendered(ROLE_CREATE));
    rig.port.sync(&rig.view);
    assert_eq!(rig.port.failure(), None, "a write already started is not started again");
    // A pending write that changed (never without an outcome in the model): the old exchange is aborted first, so
    // the new one starts rather than counting as a start while open.
    rig.connect(Ok(Connecting::InProgress));
    let first = rig.lab.borrow().last();
    let next = rendered(ROLE_UPDATE);
    rig.start_write(2, next);
    assert_eq!(rig.port.failure(), None);
    assert!(rig.closed(first) && rig.port.is_open());
}

#[test]
fn a_pending_write_without_its_rendered_request_is_a_port_failure() {
    let mut rig = rig();
    rig.view.hide_rendered = true;
    rig.start_write(1, rendered(ROLE_CREATE));
    assert_eq!(rig.port.failure(), Some("a pending write without its rendered request"));
    assert!(!rig.port.is_open());
    // The provided GateView method is None for HE-003B's unchanged view.
    assert!(tls_support::View::default().forwarded_write().is_none());
}
