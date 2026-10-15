//! HE-003C: the I04 port's side of the upstream outcome (DESIGN §6, PR review R1-7, D1-11; MODEL_DEFINED R68), over
//! HE-003B's fake `StreamNet` and rustls test client: an `Upstream` output takes the connection in flight, so a second
//! one finds none and the port fails (closed), as does an `Upstream` output when nothing was forwarded; the not-relayed
//! close still closes without a byte.

mod tls_support;

use effect_gate::{Classification, Event, OutputKind, PolicyEvent, PolicyOutput, PolicyOutputKind, Port, Readiness};
use gate_tls::{render_response, Exchange, I04Server, SharedExchange, ALPN_HTTP11};

use tls_support::*;

const GET: &[u8] = b"GET /api/v1/namespaces/planeon-qual/pods/probe-pod HTTP/1.1\r\nHost: 198.51.100.7:6443\r\n\
                     Accept: application/json\r\n\r\n";
const FAILURE: &str = "an upstream outcome with no connection in flight";

fn readable() -> Readiness {
    Readiness { readable: true, ..Readiness::default() }
}

fn output(kind: OutputKind) -> PolicyOutput {
    PolicyOutput { kind: PolicyOutputKind::Base(effect_gate::Output { kind, drain: None, response_frame: None }),
                   drain: None, response_frame: None }
}

fn upstream(relayed: bool) -> PolicyOutput {
    output(OutputKind::Upstream { classification: Classification::DeliveredResult, relayed, aborted: false })
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
    fn feed(&mut self, events: &[PolicyEvent]) {
        for event in events {
            if let PolicyEvent::Base(Event::Accept { conn }) = event {
                self.view.open.insert(conn.clone());
            }
            self.port.sync(&self.view);
        }
    }

    /// A connection accepted, its handshake done and its request fed and forwarded as action 1: its client.
    fn forwarded(&mut self) -> Peer {
        let source = self.net.borrow_mut().connect();
        let events = self.port.ready(0, readable());
        self.feed(&events);
        let mut peer = Peer::new(source, client_config(&self.pki, Some(self.pki.client.clone()), &[ALPN_HTTP11]));
        for _ in 0..6 {
            peer.push(&self.net);
            let more = self.port.ready(source, readable());
            self.feed(&more);
            peer.pull(&self.net);
            if !peer.tls.is_handshaking() && !peer.tls.wants_write() {
                break;
            }
        }
        peer.write(&self.net, GET);
        let events = self.port.ready(source, readable());
        assert!(matches!(&events[..], [PolicyEvent::Base(Event::Request { .. })]), "{events:?}");
        self.port.apply(&output(OutputKind::Forward { action_id: 1 }));
        peer
    }
}

#[test]
fn a_relayed_outcome_takes_the_connection_in_flight_and_a_second_one_fails() {
    let mut rig = rig();
    let mut peer = rig.forwarded();
    let name = format!("i04-{}", peer.source);
    rig.exchange.borrow_mut().stage_response(&name, 200, b"{}".to_vec(), None, None).expect("staged");
    rig.port.apply(&upstream(true));
    assert_eq!(rig.port.failure(), None);
    peer.pull(&rig.net);
    assert_eq!(peer.received, render_response(200, b"{}").expect("rendered"));
    // A stray second outcome finds no connection in flight: the port fails closed instead of ignoring it.
    rig.port.apply(&upstream(true));
    assert_eq!(rig.port.failure(), Some(FAILURE));
}

#[test]
fn a_not_relayed_outcome_closes_without_a_byte_and_a_second_one_fails() {
    let mut rig = rig();
    let mut peer = rig.forwarded();
    rig.port.apply(&upstream(false));
    assert_eq!(rig.port.failure(), None);
    assert!(rig.net.borrow().wires.get(&peer.source).is_some_and(|wire| wire.closed));
    peer.pull(&rig.net);
    assert!(peer.received.is_empty());
    rig.port.apply(&upstream(false));
    assert_eq!(rig.port.failure(), Some(FAILURE));
}

#[test]
fn an_outcome_with_nothing_forwarded_is_a_port_failure() {
    for relayed in [true, false] {
        let mut rig = rig();
        rig.port.apply(&upstream(relayed));
        assert_eq!(rig.port.failure(), Some(FAILURE), "relayed {relayed}");
    }
    // The late-upstream output still only drops a staged response.
    let mut rig = rig();
    rig.port.apply(&output(OutputKind::LateUpstream));
    assert_eq!(rig.port.failure(), None);
}
