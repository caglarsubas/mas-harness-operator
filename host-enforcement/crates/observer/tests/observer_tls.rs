//! HE-004C DESIGN-C section 4.3 (HE-003C's R64; D1-15): the observer's TLS 1.3 client through the client driver over
//! the fake wire with the scripted rustls server: a wrong CA, a missing IP SAN and a TLS 1.2 ServerHello are transport
//! failures; the ClientHello carries no `pre_shared_key`, `early_data` or `server_name` and offers ALPN `http/1.1` and
//! TLS 1.3 only; the server sees the observer's identity; the IPv6 loopback name works; each exchange ends with
//! `close_notify`.

mod b1_rbac_support;
mod b1_support;
mod c_support;

use std::time::Duration;

use c_support::*;
use gate_sys::inet::{InetAddress, IpLiteral};
use planeon_observer::client::{Client, Event, Failure, Kind};
use planeon_observer::http::SMALL_BODY_LIMIT;
use planeon_observer::requests;
use planeon_observer::tls::{server_name, ALPN_HTTP11};
use rustls::pki_types::ServerName;

const V4: InetAddress = InetAddress { ip: IpLiteral::V4([127, 0, 0, 1]), port: 6443 };
const V6: InetAddress = InetAddress { ip: IpLiteral::V6(V6_LOOPBACK), port: 6443 };

fn version_of(rig: &Rig, trusted: &[u8], address: InetAddress) -> Event {
    let config = observer_tls(&rig.pki, trusted);
    let mut client = Client::new(FakeWire(rig.lab.clone()), config, address, "127.0.0.1:6443");
    let deadline = client.now() + Duration::from_secs(60);
    client.run(&requests::version(), Kind::Answer(SMALL_BODY_LIMIT), deadline).expect("no poll failure")
}

/// The extensions of a ClientHello record: (type, data).
pub fn client_hello_extensions(record: &[u8]) -> Vec<(u16, Vec<u8>)> {
    assert_eq!(record[0], 0x16, "a handshake record");
    let body = &record[5..];
    assert_eq!(body[0], 1, "a ClientHello");
    let mut at = 4 + 2 + 32;
    at += 1 + body[at] as usize;
    let suites = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
    at += 2 + suites;
    at += 1 + body[at] as usize;
    let total = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
    at += 2;
    let end = at + total;
    let mut extensions = Vec::new();
    while at < end {
        let kind = u16::from_be_bytes([body[at], body[at + 1]]);
        let length = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
        extensions.push((kind, body[at + 4..at + 4 + length].to_vec()));
        at += 4 + length;
    }
    extensions
}

#[test]
fn a_good_exchange_shows_the_observers_identity_and_ends_with_close_notify() {
    let rig = Rig::new();
    match version_of(&rig, &rig.pki.serving_ca, V4) {
        Event::Answer(answer) => assert_eq!(answer.status, 200),
        other => panic!("an answer: {other:?}"),
    }
    let lab = rig.lab.borrow();
    assert_eq!(lab.peers, vec![rig.pki.observer.clone()], "the server verified the observer's certificate");
    assert_eq!((lab.connects, lab.closes), (1, 1));
    assert_eq!(lab.api.log.len(), 1);
    assert_eq!(lab.api.log[0].target, "/version");
}

#[test]
fn the_v6_loopback_server_name_is_its_ip_literal() {
    let rig = Rig::new();
    assert!(matches!(version_of(&rig, &rig.pki.serving_ca, V6), Event::Answer(_)));
    assert_eq!(server_name(&V4), ServerName::try_from("127.0.0.1").expect("name"));
    assert_eq!(server_name(&V6), ServerName::try_from("::1").expect("name"));
}

#[test]
fn a_wrong_ca_or_a_missing_ip_san_is_a_transport_failure() {
    let rig = Rig::new();
    assert_eq!(version_of(&rig, &rig.pki.other_ca, V4), Event::Failed(Failure::Transport));
    let rig = Rig::new();
    let server = apiserver_config(&rig.pki, &rig.pki.no_san);
    rig.lab(|lab| lab.server = server);
    assert_eq!(version_of(&rig, &rig.pki.serving_ca, V4), Event::Failed(Failure::Transport));
    let rig = Rig::new();
    let server = apiserver_config(&rig.pki, &rig.pki.other_apiserver);
    rig.lab(|lab| lab.server = server);
    assert_eq!(version_of(&rig, &rig.pki.serving_ca, V4), Event::Failed(Failure::Transport));
    // The address the leaf names: ::1 is in its SANs, so the IPv6 name also verifies (the good case above).
}

/// A TLS 1.2 ServerHello (legacy version 0x0303, no supported_versions extension) echoing the client's session id.
fn tls12_server_hello(client_hello: &[u8]) -> Vec<u8> {
    let body = &client_hello[5..];
    let session = &body[4 + 2 + 32..];
    let session = &session[..1 + session[0] as usize];
    let mut hello = vec![0x03, 0x03];
    hello.extend_from_slice(&[0x5a; 32]);
    hello.extend_from_slice(session);
    hello.extend_from_slice(&[0xc0, 0x2b, 0x00, 0x00, 0x00]);
    let mut handshake = vec![2, 0, 0, hello.len() as u8];
    handshake.extend_from_slice(&hello);
    let mut record = vec![0x16, 0x03, 0x03, 0, handshake.len() as u8];
    record.extend_from_slice(&handshake);
    record
}

#[test]
fn a_tls_1_2_server_hello_is_a_transport_failure() {
    let rig = Rig::new();
    rig.lab(|lab| lab.raw_server = Some(Box::new(tls12_server_hello)));
    assert_eq!(version_of(&rig, &rig.pki.serving_ca, V4), Event::Failed(Failure::Transport));
    // And so is garbage from the server.
    let rig = Rig::new();
    rig.lab(|lab| lab.raw_server = Some(Box::new(|_| b"HTTP/1.1 200 OK\r\n\r\n".to_vec())));
    assert_eq!(version_of(&rig, &rig.pki.serving_ca, V4), Event::Failed(Failure::Transport));
}

#[test]
fn the_client_hello_offers_tls_1_3_and_http_1_1_without_psk_early_data_or_sni() {
    let rig = Rig::new();
    let _ = version_of(&rig, &rig.pki.serving_ca, V4);
    let first = rig.lab.borrow().first_flights[0].clone();
    let extensions = client_hello_extensions(&first);
    let kinds: Vec<u16> = extensions.iter().map(|(kind, _)| *kind).collect();
    for absent in [0u16, 41, 42] {
        assert!(!kinds.contains(&absent), "extension {absent} offered: {kinds:?}");
    }
    let versions = &extensions.iter().find(|(kind, _)| *kind == 43).expect("supported_versions").1;
    assert_eq!(versions.as_slice(), &[2, 0x03, 0x04], "TLS 1.3 only");
    let alpn = &extensions.iter().find(|(kind, _)| *kind == 16).expect("ALPN").1;
    let mut wanted = vec![0, (ALPN_HTTP11.len() + 1) as u8, ALPN_HTTP11.len() as u8];
    wanted.extend_from_slice(ALPN_HTTP11);
    assert_eq!(alpn, &wanted);
    // No session ticket is offered either (resumption disabled).
    assert!(!kinds.contains(&35), "{kinds:?}");
}
