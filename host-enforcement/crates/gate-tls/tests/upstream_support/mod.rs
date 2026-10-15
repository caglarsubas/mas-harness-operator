//! Test support for HE-003C's upstream port (DESIGN §7), next to HE-003B's unchanged `tls_support`: the upstream test
//! PKI (an apiserver serving CA and the apiserver's leaf with the loopback IP SAN, a client CA with the gate effect and
//! gate writer identities; Ed25519 keys from fixed seeds), the two production client configurations built by
//! `client_config` with the fixed time, a scripted apiserver (a rustls `ServerConnection` that verifies the client
//! certificate) over a fake `ConnectNet` sharing `tls_support`'s fake clock, a model view with a forwarded write, and
//! a rig that drives the port alone. Nothing here reads a file or the network.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use effect_gate::net::{ConnectNet, Connecting, InetAddress, IpLiteral};
use effect_gate::{check_write, render_write, GateView, Output, OutputKind, PolicyEvent, PolicyKinds, PolicyOutput,
                  PolicyOutputKind, Port, Readiness, RenderedWrite, SourceId, Transfer, WriteRequest};
use gate_tls::{client_config, Exchange, SharedExchange, TlsClientIdentity, UpstreamClient, ALPN_HTTP11};
use i05_protocol::json;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection, SignatureScheme};
use zeroize::Zeroizing;

use crate::tls_support::{bit_string, certificate, extension, fixed_time, integer, key, name, net_lab, oid, seq, tlv,
                         utc_time, Key, San, SharedNet, Spec, CLIENT_AUTH, SERVER_AUTH};

/// The apiserver authority of the I07 vectors' configuration, parsed.
pub const APISERVER: InetAddress = InetAddress { ip: IpLiteral::V4([127, 0, 0, 1]), port: 6443 };

pub const KINDS: &str = include_str!("../../../../contracts/i07-v3/policy-kinds.json");

// ------------------------------------------------------------------------------------------ the PKI

pub struct UpstreamPki {
    pub serving_ca_key: Key,
    pub serving_ca: Vec<u8>,
    pub apiserver_key: Key,
    pub apiserver: Vec<u8>,
    pub client_ca_key: Key,
    pub client_ca: Vec<u8>,
    pub effect_key: Key,
    pub effect: Vec<u8>,
    pub writer_key: Key,
    pub writer: Vec<u8>,
    pub other_ca_key: Key,
    pub other_ca: Vec<u8>,
}

pub fn upstream_pki() -> UpstreamPki {
    let serving_ca_key = key(11);
    let apiserver_key = key(12);
    let client_ca_key = key(13);
    let effect_key = key(14);
    let writer_key = key(15);
    let other_ca_key = key(16);
    let serving_ca = certificate(&Spec::ca(21, "planeon serving ca"), &serving_ca_key, &serving_ca_key);
    let apiserver = certificate(&Spec::leaf(22, "planeon serving ca", "kube-apiserver", SERVER_AUTH, San::Ip([127, 0, 0, 1])),
                                &apiserver_key, &serving_ca_key);
    let client_ca = certificate(&Spec::ca(23, "planeon client ca"), &client_ca_key, &client_ca_key);
    let effect = certificate(&Spec::leaf(24, "planeon client ca", "planeon:effect-gate", CLIENT_AUTH, San::None),
                             &effect_key, &client_ca_key);
    let writer = certificate(&Spec::leaf(25, "planeon client ca", "planeon:policy-writer", CLIENT_AUTH, San::None),
                             &writer_key, &client_ca_key);
    let other_ca = certificate(&Spec::ca(26, "another serving ca"), &other_ca_key, &other_ca_key);
    UpstreamPki { serving_ca_key, serving_ca, apiserver_key, apiserver, client_ca_key, client_ca, effect_key, effect,
                  writer_key, writer, other_ca_key, other_ca }
}

/// A leaf like `tls_support::certificate`'s with an IPv6 address SAN (16 bytes).
pub fn leaf_v6(serial: u64, issuer: &str, subject_key: &Key, issuer_key: &Key, address: [u8; 16]) -> Vec<u8> {
    let algorithm = seq(&[oid(&[1, 3, 101, 112])]);
    let extensions = vec![
        extension(&[2, 5, 29, 19], true, seq(&[])),
        extension(&[2, 5, 29, 15], true, bit_string(7, &[0x80])),
        extension(&[2, 5, 29, 37], false, seq(&[oid(SERVER_AUTH)])),
        extension(&[2, 5, 29, 17], false, seq(&[tlv(0x87, &address)])),
    ];
    let tbs = seq(&[
        tlv(0xa0, &integer(2)),
        integer(serial),
        algorithm.clone(),
        name(issuer),
        seq(&[utc_time(2026, 1, 1), utc_time(2027, 1, 1)]),
        name("kube-apiserver"),
        subject_key.spki.clone(),
        tlv(0xa3, &seq(&extensions)),
    ]);
    let signer = issuer_key.signing.choose_scheme(&[SignatureScheme::ED25519]).expect("an Ed25519 signer");
    let signature = signer.sign(&tbs).expect("a signature");
    seq(&[tbs, algorithm, bit_string(0, &signature)])
}

pub fn identity(leaf: &[u8], key: &Key) -> TlsClientIdentity {
    TlsClientIdentity { chain: vec![leaf.to_vec()], key: Zeroizing::new(key.pkcs8.clone()) }
}

/// The gate effect identity's production configuration (I05), trusting `serving_ca`.
pub fn effect_config(pki: &UpstreamPki, serving_ca: &[u8]) -> Arc<ClientConfig> {
    client_config(identity(&pki.effect, &pki.effect_key), &[serving_ca.to_vec()], fixed_time()).expect("the effect identity")
}

/// The gate writer identity's production configuration (I07), trusting `serving_ca`.
pub fn writer_config(pki: &UpstreamPki, serving_ca: &[u8]) -> Arc<ClientConfig> {
    client_config(identity(&pki.writer, &pki.writer_key), &[serving_ca.to_vec()], fixed_time()).expect("the writer identity")
}

/// A scripted apiserver configuration: `leaf` signed by the serving CA, client certificates required from the client
/// CA, ALPN http/1.1, and `tickets` TLS 1.3 tickets after each handshake (rustls's default session cache).
pub fn apiserver_config_with(pki: &UpstreamPki, leaf: &[u8], tickets: usize) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(pki.client_ca.clone())).expect("the client CA");
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build().expect("a verifier");
    let mut config = ServerConfig::builder_with_details(provider, fixed_time())
        .with_protocol_versions(&[&TLS13])
        .expect("TLS 1.3")
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from(leaf.to_vec())],
                          PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.apiserver_key.pkcs8.clone())))
        .expect("the apiserver credential");
    config.send_tls13_tickets = tickets;
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    Arc::new(config)
}

pub fn apiserver_config(pki: &UpstreamPki) -> Arc<ServerConfig> {
    apiserver_config_with(pki, &pki.apiserver, 0)
}

// ------------------------------------------------------------------------------------------ the fake ConnectNet

/// One fake outgoing connection.
#[derive(Debug, Default)]
pub struct Line {
    /// What the gate sent.
    pub to_apiserver: Vec<u8>,
    /// What the apiserver sent, not yet received by the gate.
    pub to_gate: VecDeque<u8>,
    /// The apiserver closed its side.
    pub eof: bool,
    pub reset: bool,
    pub closed: bool,
}

pub struct ConnectLab {
    /// The next connects' results (an empty queue: in progress).
    pub connects: VecDeque<Result<Connecting, i32>>,
    /// SO_ERROR's value (0: connected).
    pub so_error: i32,
    pub lines: BTreeMap<u64, Line>,
    pub next: u64,
    pub calls: Vec<String>,
    pub addresses: Vec<InetAddress>,
}

pub type SharedConnect = Rc<RefCell<ConnectLab>>;

pub fn connect_lab() -> SharedConnect {
    Rc::new(RefCell::new(ConnectLab { connects: VecDeque::new(), so_error: 0, lines: BTreeMap::new(), next: 100,
                                      calls: Vec::new(), addresses: Vec::new() }))
}

impl ConnectLab {
    /// The last connection's source number.
    pub fn last(&self) -> u64 {
        self.next - 1
    }
}

/// The fake `ConnectNet`: scripted connect results, byte queues, a recorded call sequence and `tls_support`'s clock.
pub struct FakeConnect {
    pub lab: SharedConnect,
    pub clock: SharedNet,
}

impl ConnectNet for FakeConnect {
    fn connect(&mut self, address: &InetAddress) -> Result<(SourceId, Connecting), i32> {
        let mut lab = self.lab.borrow_mut();
        lab.addresses.push(*address);
        match lab.connects.pop_front().unwrap_or(Ok(Connecting::InProgress)) {
            Err(errno) => {
                lab.calls.push(format!("connect failed {errno}"));
                Err(errno)
            }
            Ok(started) => {
                let number = lab.next;
                lab.next += 1;
                lab.lines.insert(number, Line::default());
                lab.calls.push(format!("connect {number} {started:?}"));
                Ok((SourceId(number), started))
            }
        }
    }

    fn connect_result(&mut self, source: SourceId) -> Result<(), i32> {
        let mut lab = self.lab.borrow_mut();
        lab.calls.push(format!("so_error {}", source.0));
        if lab.so_error == 0 { Ok(()) } else { Err(lab.so_error) }
    }

    fn recv(&mut self, source: SourceId, buffer: &mut [u8]) -> Transfer {
        let mut lab = self.lab.borrow_mut();
        let Some(line) = lab.lines.get_mut(&source.0) else { return Transfer::Failed(9) };
        if line.closed {
            return Transfer::Failed(9);
        }
        if line.reset {
            return Transfer::Failed(104);
        }
        if line.to_gate.is_empty() {
            return if line.eof { Transfer::Eof } else { Transfer::WouldBlock };
        }
        let count = buffer.len().min(line.to_gate.len());
        for (slot, byte) in buffer.iter_mut().zip(line.to_gate.drain(..count)) {
            *slot = byte;
        }
        lab.calls.push(format!("recv {} {}", source.0, count));
        Transfer::Data(count)
    }

    fn send(&mut self, source: SourceId, bytes: &[u8]) -> Transfer {
        let mut lab = self.lab.borrow_mut();
        let Some(line) = lab.lines.get_mut(&source.0) else { return Transfer::Failed(9) };
        if line.closed || line.reset {
            return Transfer::Failed(32);
        }
        line.to_apiserver.extend_from_slice(bytes);
        lab.calls.push(format!("send {} {}", source.0, bytes.len()));
        Transfer::Data(bytes.len())
    }

    fn shutdown_write(&mut self, source: SourceId) -> bool {
        self.lab.borrow_mut().calls.push(format!("shutdown {}", source.0));
        true
    }

    fn close(&mut self, source: SourceId) {
        let mut lab = self.lab.borrow_mut();
        lab.calls.push(format!("close {}", source.0));
        if let Some(line) = lab.lines.get_mut(&source.0) {
            assert!(!line.closed, "a source is closed once");
            line.closed = true;
        }
    }

    fn monotonic(&self) -> std::time::Instant {
        self.clock.borrow().now()
    }
}

// ------------------------------------------------------------------------------------------ the scripted apiserver

/// The scripted apiserver on one fake connection.
pub struct Apiserver {
    pub source: u64,
    pub tls: ServerConnection,
    /// The plaintext the gate sent.
    pub received: Vec<u8>,
    pub error: Option<rustls::Error>,
}

impl Apiserver {
    pub fn new(source: u64, config: Arc<ServerConfig>) -> Apiserver {
        Apiserver { source, tls: ServerConnection::new(config).expect("a server connection"), received: Vec::new(),
                    error: None }
    }

    /// Takes what the gate sent, processes it and sends the apiserver's records back.
    pub fn pump(&mut self, lab: &SharedConnect) {
        let bytes = lab.borrow_mut().lines.get_mut(&self.source).map(|line| std::mem::take(&mut line.to_apiserver))
                       .unwrap_or_default();
        let mut slice = bytes.as_slice();
        while !slice.is_empty() && self.error.is_none() {
            if self.tls.read_tls(&mut slice).is_err() {
                break;
            }
            if let Err(error) = self.tls.process_new_packets() {
                self.error = Some(error);
            }
        }
        let mut chunk = [0u8; 8192];
        while let Ok(count) = std::io::Read::read(&mut self.tls.reader(), &mut chunk) {
            if count == 0 {
                break;
            }
            self.received.extend_from_slice(&chunk[..count]);
        }
        self.flush(lab);
    }

    pub fn flush(&mut self, lab: &SharedConnect) {
        let mut out = Vec::new();
        while self.tls.wants_write() {
            if self.tls.write_tls(&mut out).is_err() {
                break;
            }
        }
        if let Some(line) = lab.borrow_mut().lines.get_mut(&self.source) {
            line.to_gate.extend(out);
        }
    }

    /// Sends `bytes` as application data.
    pub fn respond(&mut self, lab: &SharedConnect, bytes: &[u8]) {
        std::io::Write::write_all(&mut self.tls.writer(), bytes).expect("the apiserver takes the plaintext");
        self.flush(lab);
    }

    /// The client's leaf certificate, once verified.
    pub fn peer_leaf(&self) -> Option<Vec<u8>> {
        self.tls.peer_certificates().and_then(|chain| chain.first()).map(|leaf| leaf.as_ref().to_vec())
    }
}

/// The extension types and the ALPN protocols of the first ClientHello in a client's first flight.
pub fn client_hello(flight: &[u8]) -> (Vec<u16>, Vec<Vec<u8>>) {
    let body = &flight[5 + 4..];
    let mut at = 2 + 32;
    at += 1 + usize::from(body[at]);
    at += 2 + usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
    at += 1 + usize::from(body[at]);
    let end = at + 2 + usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
    at += 2;
    let (mut types, mut alpn) = (Vec::new(), Vec::new());
    while at + 4 <= end {
        let kind = u16::from_be_bytes([body[at], body[at + 1]]);
        let length = usize::from(u16::from_be_bytes([body[at + 2], body[at + 3]]));
        if kind == 16 {
            let data = &body[at + 6..at + 4 + length];
            let mut cursor = 0;
            while cursor < data.len() {
                let size = usize::from(data[cursor]);
                alpn.push(data[cursor + 1..cursor + 1 + size].to_vec());
                cursor += 1 + size;
            }
        }
        types.push(kind);
        at += 4 + length;
    }
    (types, alpn)
}

// ------------------------------------------------------------------------------------------ the model's side

/// A model view for the port alone: the I04 connections the test holds open and the forwarded write.
#[derive(Default)]
pub struct UView {
    pub open: BTreeSet<String>,
    pub pending: Option<(u16, RenderedWrite)>,
    /// A pending write whose rendered request the view does not give (a defect the port refuses).
    pub hide_rendered: bool,
}

impl GateView for UView {
    fn connection_open(&self, conn: &str) -> bool {
        self.open.contains(conn)
    }

    fn pending_write(&self) -> Option<u16> {
        self.pending.as_ref().map(|(write_id, _)| *write_id)
    }

    fn forwarded_write(&self) -> Option<(u16, &RenderedWrite)> {
        if self.hide_rendered {
            return None;
        }
        self.pending.as_ref().map(|(write_id, rendered)| (*write_id, rendered))
    }
}

pub fn output(kind: OutputKind) -> PolicyOutput {
    PolicyOutput { kind: PolicyOutputKind::Base(Output { kind, drain: None, response_frame: None }), drain: None,
                   response_frame: None }
}

/// The request one I07 WRITE_OBJECT payload renders to (through the table's checks), for the qualification
/// namespace and the vectors' authority.
pub fn rendered(payload: &str) -> RenderedWrite {
    let kinds = PolicyKinds::from_value(&json::parse(KINDS).expect("the table parses")).expect("the table");
    let request = WriteRequest::from_payload(&json::parse(payload).expect("a payload")).expect("a typed payload");
    let row = check_write(&kinds, "planeon-qual", &request).expect("a checked write");
    render_write(row, &request, "planeon-qual", "127.0.0.1:6443").expect("a rendered write")
}

pub const ROLE_CREATE: &str = r#"{"writeId":1,"operation":"CREATE","resource":{"group":"rbac.authorization.k8s.io","version":"v1","resource":"roles"},"namespace":"planeon-qual","name":"planeon-role","object":{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"planeon-role","namespace":"planeon-qual"},"rules":[]},"prior":null}"#;
pub const ROLE_UPDATE: &str = r#"{"writeId":1,"operation":"UPDATE","resource":{"group":"rbac.authorization.k8s.io","version":"v1","resource":"roles"},"namespace":"planeon-qual","name":"planeon-role","object":{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"planeon-role","namespace":"planeon-qual","uid":"u-1","resourceVersion":"41"},"rules":[]},"prior":{"uid":"u-1","resourceVersion":"41","projectionDigest":"sha256:5555555555555555555555555555555555555555555555555555555555555555"}}"#;
pub const ROLE_DELETE: &str = r#"{"writeId":1,"operation":"DELETE","resource":{"group":"rbac.authorization.k8s.io","version":"v1","resource":"roles"},"namespace":"planeon-qual","name":"planeon-role","object":null,"prior":{"uid":"u-1","resourceVersion":"41","projectionDigest":"sha256:5555555555555555555555555555555555555555555555555555555555555555"}}"#;

// ------------------------------------------------------------------------------------------ I05 heads

pub const ENDPOINT: &str = "198.51.100.7:6443";

pub fn manifest(kind: i05_protocol::Kind, name: &str) -> i05_protocol::Manifest {
    i05_protocol::Manifest { api_version: "v1".into(), kind, namespace: "planeon-qual".into(), name: name.into(),
                             digest: format!("sha256:{}", "1".repeat(64)), size: 2 }
}

/// The staged request of an I05 action: the rendered head and body bytes of its length (the port never checks the
/// digest; the model compared it).
pub fn i05_request(verb: i05_protocol::Verb, kind: i05_protocol::Kind, name: &str) -> (String, Vec<u8>) {
    let uid = "11111111-aaaa-4bbb-8ccc-000000000001";
    let rendered = i05_protocol::render_request(verb, &manifest(kind, name), Some(uid), ENDPOINT);
    let body = match verb {
        i05_protocol::Verb::Get => Vec::new(),
        i05_protocol::Verb::Create => b"{}".to_vec(),
        i05_protocol::Verb::Delete => i05_protocol::render::delete_options(Some(uid)),
    };
    (rendered.head, body)
}

// ------------------------------------------------------------------------------------------ the rig

pub fn readable() -> Readiness {
    Readiness { readable: true, ..Readiness::default() }
}

pub fn writable() -> Readiness {
    Readiness { writable: true, ..Readiness::default() }
}

pub fn both() -> Readiness {
    Readiness { readable: true, writable: true, ..Readiness::default() }
}

/// The port alone, with the test as the model.
pub struct Rig {
    pub clock: SharedNet,
    pub lab: SharedConnect,
    pub exchange: SharedExchange,
    pub port: UpstreamClient<FakeConnect>,
    pub view: UView,
    pub pki: UpstreamPki,
}

pub fn rig() -> Rig {
    let pki = upstream_pki();
    rig_with(effect_config(&pki, &pki.serving_ca), writer_config(&pki, &pki.serving_ca), pki)
}

pub fn rig_with(effect: Arc<ClientConfig>, writer: Arc<ClientConfig>, pki: UpstreamPki) -> Rig {
    let clock = net_lab();
    let lab = connect_lab();
    let exchange = Exchange::shared();
    let port = UpstreamClient::new(FakeConnect { lab: lab.clone(), clock: clock.clone() }, APISERVER, effect, writer,
                                   exchange.clone());
    Rig { clock, lab, exchange, port, view: UView::default(), pki }
}

impl Rig {
    pub fn now(&self) -> std::time::Instant {
        self.clock.borrow().now()
    }

    pub fn advance(&mut self, by: Duration) {
        self.clock.borrow_mut().advance(by);
    }

    pub fn calls(&self) -> Vec<String> {
        self.lab.borrow().calls.clone()
    }

    pub fn closed(&self, source: u64) -> bool {
        self.lab.borrow().lines.get(&source).is_some_and(|line| line.closed)
    }

    /// The I04 port's part and the model's: the request staged and confirmed with `action_id`, the connection held
    /// open, then the model's `Forward { action_id }` applied and the views synced.
    pub fn forward(&mut self, conn: &str, head: &str, body: &[u8], staged_id: u16, action_id: u16) {
        {
            let mut board = self.exchange.borrow_mut();
            board.stage_request(conn, head, body).expect("staged");
            assert!(board.confirm_request(conn, staged_id));
        }
        self.view.open.insert(conn.to_string());
        self.port.apply(&output(OutputKind::Forward { action_id }));
        self.port.sync(&self.view);
    }

    pub fn forward_i05(&mut self, verb: i05_protocol::Verb, kind: i05_protocol::Kind, name: &str) -> Vec<u8> {
        let (head, body) = i05_request(verb, kind, name);
        self.forward("i04-7", &head, &body, 1, 1);
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(&body);
        bytes
    }

    /// The model forwarded write `write_id` with `rendered`: the views synced.
    pub fn start_write(&mut self, write_id: u16, rendered: RenderedWrite) -> Vec<u8> {
        let mut bytes = rendered.head.as_bytes().to_vec();
        bytes.extend_from_slice(&rendered.body);
        self.view.pending = Some((write_id, rendered));
        self.port.sync(&self.view);
        bytes
    }

    /// The start deadline's `due`, the connect scripted as `started`.
    pub fn connect(&mut self, started: Result<Connecting, i32>) -> Vec<PolicyEvent> {
        self.lab.borrow_mut().connects.push_back(started);
        let now = self.now();
        self.port.due(now)
    }

    /// An immediate connect and a full handshake with a scripted apiserver of `config`, which then holds the whole
    /// request; the port's events along the way.
    pub fn handshake_with(&mut self, config: Arc<ServerConfig>) -> (Apiserver, Vec<PolicyEvent>) {
        let mut events = self.connect(Ok(Connecting::Connected));
        let source = self.lab.borrow().last();
        let mut apiserver = Apiserver::new(source, config);
        for _ in 0..8 {
            apiserver.pump(&self.lab);
            if !self.port.is_open() || apiserver.error.is_some() {
                break;
            }
            events.extend(self.port.ready(source, both()));
            if !self.port.is_open() {
                break;
            }
        }
        apiserver.pump(&self.lab);
        (apiserver, events)
    }

    pub fn handshake(&mut self) -> (Apiserver, Vec<PolicyEvent>) {
        let config = apiserver_config(&self.pki);
        self.handshake_with(config)
    }

    /// The apiserver's answer `bytes`, then one readable wake: the port's events.
    pub fn answer(&mut self, apiserver: &mut Apiserver, bytes: &[u8]) -> Vec<PolicyEvent> {
        apiserver.respond(&self.lab, bytes);
        self.port.ready(apiserver.source, readable())
    }

    /// A whole I05 exchange of `verb`/`kind`/`name` answered with `answer`: the apiserver and the events.
    pub fn i05_exchange(&mut self, verb: i05_protocol::Verb, kind: i05_protocol::Kind, name: &str, answer: &[u8])
                        -> (Apiserver, Vec<PolicyEvent>) {
        let request = self.forward_i05(verb, kind, name);
        let (mut apiserver, mut events) = self.handshake();
        assert!(events.is_empty(), "{events:?}");
        assert_eq!(apiserver.received, request, "exactly the staged bytes");
        events.extend(self.answer(&mut apiserver, answer));
        (apiserver, events)
    }

    /// A whole I07 exchange of write 1 with `payload`, answered with `answer`.
    pub fn i07_exchange(&mut self, payload: &str, answer: &[u8]) -> (Apiserver, Vec<PolicyEvent>) {
        let request = self.start_write(1, rendered(payload));
        let (mut apiserver, mut events) = self.handshake();
        assert!(events.is_empty(), "{events:?}");
        assert_eq!(apiserver.received, request, "exactly the rendered bytes");
        events.extend(self.answer(&mut apiserver, answer));
        (apiserver, events)
    }
}

/// An HTTP answer with a Content-Length.
pub fn http(status: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len())
        .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
