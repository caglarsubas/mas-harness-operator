//! Test support for gate-tls (HE-003B DESIGN §9, Q-HE3B-22 (a)): deterministic test certificates (Ed25519 keys from
//! fixed seeds, signed through rustls's own ring signer, written by a small DER writer), the production configuration
//! built with a fixed time, rustls test clients, an in-memory pump, a fake `StreamNet` with a shared fake clock, a
//! fake model view, and a fake `Os` for the whole loop. No key or certificate file is committed; nothing here reads a
//! file or the network.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use effect_gate::{Accepted, ConnId, GateView, Interest, Listen, Os, OsFailure, Owner, PeerCredentials, PortPoll,
                  ProcIdentity, Readiness, Received, SourceId, StreamNet, Transfer, Watch};
use gate_tls::{server_config, TlsServerInputs};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::sign::SigningKey;
use rustls::time_provider::TimeProvider;
use rustls::version::TLS13;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, SignatureScheme};
use zeroize::Zeroizing;

// ------------------------------------------------------------------------------------------ time

/// Days since 1970-01-01 of a civil date (H. Hinnant's algorithm).
pub fn days(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The tests' fixed time: 2026-06-01T00:00:00Z.
pub fn now_seconds() -> u64 {
    (days(2026, 6, 1) * 86_400) as u64
}

/// A time provider that always answers the fixed time.
#[derive(Debug)]
pub struct FixedTime(pub u64);

impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
    }
}

pub fn fixed_time() -> Arc<dyn TimeProvider> {
    Arc::new(FixedTime(now_seconds()))
}

// ------------------------------------------------------------------------------------------ DER

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes: Vec<u8> = length.to_be_bytes().iter().copied().skip_while(|byte| *byte == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

pub fn integer(value: u64) -> Vec<u8> {
    let mut bytes: Vec<u8> = value.to_be_bytes().iter().copied().skip_while(|byte| *byte == 0).collect();
    if bytes.is_empty() || bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tlv(0x02, &bytes)
}

pub fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut chunk = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            chunk.insert(0, 0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        body.extend(chunk);
    }
    tlv(0x06, &body)
}

pub fn utc_time(year: i64, month: i64, day: i64) -> Vec<u8> {
    tlv(0x17, format!("{:02}{:02}{:02}000000Z", year % 100, month, day).as_bytes())
}

pub fn bit_string(unused: u8, bytes: &[u8]) -> Vec<u8> {
    let mut body = vec![unused];
    body.extend_from_slice(bytes);
    tlv(0x03, &body)
}

pub fn name(common_name: &str) -> Vec<u8> {
    seq(&[set(&[seq(&[oid(&[2, 5, 4, 3]), tlv(0x0c, common_name.as_bytes())])])])
}

pub fn extension(id: &[u64], critical: bool, value: Vec<u8>) -> Vec<u8> {
    let mut parts = vec![oid(id)];
    if critical {
        parts.push(tlv(0x01, &[0xff]));
    }
    parts.push(tlv(0x04, &value));
    seq(&parts)
}

pub const SERVER_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];
pub const CLIENT_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 2];
const ED25519: &[u64] = &[1, 3, 101, 112];

// ------------------------------------------------------------------------------------------ keys and certificates

/// An Ed25519 key from a fixed seed: its seed-only PKCS#8 v1 form (RFC 8410: a fixed 16-byte prefix and the seed),
/// rustls's ring signer and its SubjectPublicKeyInfo.
pub struct Key {
    pub pkcs8: Vec<u8>,
    pub signing: Arc<dyn SigningKey>,
    pub spki: Vec<u8>,
}

pub fn key(seed: u8) -> Key {
    let mut pkcs8 = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    pkcs8.extend_from_slice(&[seed; 32]);
    let signing = any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.clone())))
        .expect("the ring signer takes the seed-only Ed25519 PKCS#8 form");
    let spki = signing.public_key().expect("the signer gives its public key").as_ref().to_vec();
    Key { pkcs8, signing, spki }
}

fn sign(key: &Key, message: &[u8]) -> Vec<u8> {
    let signer = key.signing.choose_scheme(&[SignatureScheme::ED25519]).expect("an Ed25519 signer");
    signer.sign(message).expect("a signature")
}

/// The subject alternative name a certificate carries.
#[derive(Copy, Clone, Debug)]
pub enum San {
    None,
    Ip([u8; 4]),
    Uri(&'static str),
}

/// What a test certificate says.
#[derive(Clone, Debug)]
pub struct Spec {
    pub serial: u64,
    pub issuer: &'static str,
    pub subject: &'static str,
    pub not_before: (i64, i64, i64),
    pub not_after: (i64, i64, i64),
    pub ca: bool,
    pub eku: Option<&'static [u64]>,
    pub san: San,
}

impl Spec {
    pub fn leaf(serial: u64, issuer: &'static str, subject: &'static str, eku: &'static [u64], san: San) -> Spec {
        Spec { serial, issuer, subject, not_before: (2026, 1, 1), not_after: (2027, 1, 1), ca: false, eku: Some(eku), san }
    }

    pub fn ca(serial: u64, name: &'static str) -> Spec {
        Spec { serial, issuer: name, subject: name, not_before: (2026, 1, 1), not_after: (2027, 1, 1), ca: true, eku: None,
               san: San::None }
    }
}

/// A DER certificate for `spec`, holding `subject_key`'s public key, signed by `issuer_key`.
pub fn certificate(spec: &Spec, subject_key: &Key, issuer_key: &Key) -> Vec<u8> {
    let algorithm = seq(&[oid(ED25519)]);
    let mut extensions = Vec::new();
    let constraints = if spec.ca { seq(&[tlv(0x01, &[0xff])]) } else { seq(&[]) };
    extensions.push(extension(&[2, 5, 29, 19], true, constraints));
    let usage = if spec.ca { bit_string(2, &[0x04]) } else { bit_string(7, &[0x80]) };
    extensions.push(extension(&[2, 5, 29, 15], true, usage));
    if let Some(eku) = spec.eku {
        extensions.push(extension(&[2, 5, 29, 37], false, seq(&[oid(eku)])));
    }
    match spec.san {
        San::None => {}
        San::Ip(address) => extensions.push(extension(&[2, 5, 29, 17], false, seq(&[tlv(0x87, &address)]))),
        San::Uri(uri) => extensions.push(extension(&[2, 5, 29, 17], false, seq(&[tlv(0x86, uri.as_bytes())]))),
    }
    let (by, bm, bd) = spec.not_before;
    let (ay, am, ad) = spec.not_after;
    let tbs = seq(&[
        tlv(0xa0, &integer(2)),
        integer(spec.serial),
        algorithm.clone(),
        name(spec.issuer),
        seq(&[utc_time(by, bm, bd), utc_time(ay, am, ad)]),
        name(spec.subject),
        subject_key.spki.clone(),
        tlv(0xa3, &seq(&extensions)),
    ]);
    let signature = sign(issuer_key, &tbs);
    seq(&[tbs, algorithm, bit_string(0, &signature)])
}

/// The test PKI: the client CA and the server's credential chained to it (with an IP SAN 127.0.0.1), a client leaf
/// (clientAuth, a URI SAN), and a second, unrelated CA with its own client leaf.
pub struct Pki {
    pub ca_key: Key,
    pub ca: Vec<u8>,
    pub server_key: Key,
    pub server: Vec<u8>,
    pub client_key: Key,
    pub client: Vec<u8>,
    pub other_ca_key: Key,
    pub other_ca: Vec<u8>,
    pub other_client: Vec<u8>,
}

pub const RUN_URI: &str = "spiffe://planeon.test/run/run-one";

pub fn pki() -> Pki {
    let ca_key = key(1);
    let server_key = key(2);
    let client_key = key(3);
    let other_ca_key = key(4);
    let ca = certificate(&Spec::ca(1, "planeon test ca"), &ca_key, &ca_key);
    let server = certificate(&Spec::leaf(2, "planeon test ca", "planeon gate", SERVER_AUTH, San::Ip([127, 0, 0, 1])),
                             &server_key, &ca_key);
    let client = certificate(&Spec::leaf(3, "planeon test ca", "planeon server", CLIENT_AUTH, San::Uri(RUN_URI)),
                             &client_key, &ca_key);
    let other_ca = certificate(&Spec::ca(4, "another ca"), &other_ca_key, &other_ca_key);
    let other_client = certificate(&Spec::leaf(5, "another ca", "planeon server", CLIENT_AUTH, San::Uri(RUN_URI)),
                                   &client_key, &other_ca_key);
    Pki { ca_key, ca, server_key, server, client_key, client, other_ca_key, other_ca, other_client }
}

/// The client leaf of `spec`, issued by the test CA for the client key.
pub fn client_leaf(pki: &Pki, spec: &Spec) -> Vec<u8> {
    certificate(spec, &pki.client_key, &pki.ca_key)
}

pub fn inputs(pki: &Pki) -> TlsServerInputs {
    TlsServerInputs { chain: vec![pki.server.clone()], key: Zeroizing::new(pki.server_key.pkcs8.clone()),
                      client_cas: vec![pki.ca.clone()] }
}

/// The production configuration, through the production builder with the fixed time.
pub fn production(pki: &Pki) -> Arc<ServerConfig> {
    server_config(inputs(pki), fixed_time()).expect("the production configuration builds")
}

/// A TLS 1.3 test client of the test CA, with an optional client certificate and the given ALPN list.
pub fn client_config(pki: &Pki, leaf: Option<Vec<u8>>, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(pki.ca.clone())).expect("the test CA");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_details(provider, fixed_time())
        .with_protocol_versions(&[&TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(roots);
    let mut config = match leaf {
        Some(leaf) => builder
            .with_client_auth_cert(vec![CertificateDer::from(leaf)],
                                   PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.client_key.pkcs8.clone())))
            .expect("the client credential"),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Arc::new(config)
}

pub fn client(config: Arc<ClientConfig>) -> ClientConnection {
    ClientConnection::new(config, ServerName::try_from("127.0.0.1").expect("an IP server name")).expect("a client")
}

// ------------------------------------------------------------------------------------------ the in-memory pump

/// Which side failed.
#[derive(Debug)]
pub enum Failed {
    Server(rustls::Error),
    Client(rustls::Error),
}

fn deliver_to_server(bytes: &[u8], server: &mut ServerConnection) -> Result<(), rustls::Error> {
    let mut slice = bytes;
    while !slice.is_empty() {
        if server.read_tls(&mut slice).is_err() {
            break;
        }
        server.process_new_packets()?;
    }
    Ok(())
}

fn deliver_to_client(bytes: &[u8], client: &mut ClientConnection) -> Result<(), rustls::Error> {
    let mut slice = bytes;
    while !slice.is_empty() {
        if client.read_tls(&mut slice).is_err() {
            break;
        }
        client.process_new_packets()?;
    }
    Ok(())
}

pub fn drain_client(client: &mut ClientConnection) -> Vec<u8> {
    let mut bytes = Vec::new();
    while client.wants_write() {
        if client.write_tls(&mut bytes).is_err() {
            break;
        }
    }
    bytes
}

pub fn drain_server(server: &mut ServerConnection) -> Vec<u8> {
    let mut bytes = Vec::new();
    while server.wants_write() {
        if server.write_tls(&mut bytes).is_err() {
            break;
        }
    }
    bytes
}

/// Moves records both ways until both handshakes are done or a side fails (the failing side's alert is delivered).
pub fn handshake(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), Failed> {
    for _ in 0..20 {
        let to_server = drain_client(client);
        if !to_server.is_empty() {
            if let Err(error) = deliver_to_server(&to_server, server) {
                let alert = drain_server(server);
                let _ = deliver_to_client(&alert, client);
                return Err(Failed::Server(error));
            }
        }
        let to_client = drain_server(server);
        if !to_client.is_empty() {
            deliver_to_client(&to_client, client).map_err(Failed::Client)?;
        }
        if !client.is_handshaking() && !server.is_handshaking() && !client.wants_write() && !server.wants_write() {
            return Ok(());
        }
    }
    Ok(())
}

/// The record types (first byte of each record) of a TLS byte stream.
pub fn record_types(bytes: &[u8]) -> Vec<u8> {
    let mut types = Vec::new();
    let mut at = 0;
    while at + 5 <= bytes.len() {
        types.push(bytes[at]);
        let length = usize::from(u16::from_be_bytes([bytes[at + 3], bytes[at + 4]]));
        at += 5 + length;
    }
    types
}

// ------------------------------------------------------------------------------------------ the fake StreamNet

/// One fake TCP connection: the bytes each way and what happened to it.
#[derive(Debug, Default)]
pub struct Wire {
    pub to_server: VecDeque<u8>,
    pub to_client: Vec<u8>,
    pub client_eof: bool,
    pub reset: bool,
    pub shut: bool,
    pub closed: bool,
    /// At most this many bytes per send (`None`: all); 0 makes every send would-block.
    pub send_room: Option<usize>,
}

/// What the fake network shares with the test.
pub struct NetLab {
    pub base: Instant,
    pub elapsed: Duration,
    pub queue: VecDeque<Accepted>,
    pub wires: BTreeMap<u64, Wire>,
    pub next: u64,
    pub calls: Vec<String>,
}

pub type SharedNet = Rc<RefCell<NetLab>>;

pub fn net_lab() -> SharedNet {
    Rc::new(RefCell::new(NetLab { base: Instant::now(), elapsed: Duration::ZERO, queue: VecDeque::new(),
                                  wires: BTreeMap::new(), next: 2, calls: Vec::new() }))
}

/// The listener's source.
pub const LISTENER: SourceId = SourceId(1);

impl NetLab {
    /// Queues a new connection; its source number.
    pub fn connect(&mut self) -> u64 {
        let number = self.next;
        self.next += 1;
        self.wires.insert(number, Wire::default());
        self.queue.push_back(Accepted::Conn(SourceId(number)));
        number
    }

    pub fn advance(&mut self, by: Duration) {
        self.elapsed += by;
    }

    pub fn now(&self) -> Instant {
        self.base + self.elapsed
    }
}

/// The fake `StreamNet`: scripted accepts, byte queues, a recorded call sequence and the shared clock.
pub struct FakeNet(pub SharedNet);

impl StreamNet for FakeNet {
    fn listener(&self) -> SourceId {
        LISTENER
    }

    fn accept(&mut self) -> Accepted {
        let mut lab = self.0.borrow_mut();
        let next = lab.queue.pop_front().unwrap_or(Accepted::Empty);
        lab.calls.push(match next {
            Accepted::Conn(source) => format!("accept {}", source.0),
            other => format!("accept {other:?}"),
        });
        next
    }

    fn recv(&mut self, source: SourceId, buffer: &mut [u8]) -> Transfer {
        let mut lab = self.0.borrow_mut();
        let Some(wire) = lab.wires.get_mut(&source.0) else { return Transfer::Failed(9) };
        if wire.closed {
            return Transfer::Failed(9);
        }
        if wire.reset {
            return Transfer::Failed(104);
        }
        if wire.to_server.is_empty() {
            return if wire.client_eof { Transfer::Eof } else { Transfer::WouldBlock };
        }
        let count = buffer.len().min(wire.to_server.len());
        for (slot, byte) in buffer.iter_mut().zip(wire.to_server.drain(..count)) {
            *slot = byte;
        }
        lab.calls.push(format!("recv {} {}", source.0, count));
        Transfer::Data(count)
    }

    fn send(&mut self, source: SourceId, bytes: &[u8]) -> Transfer {
        let mut lab = self.0.borrow_mut();
        let Some(wire) = lab.wires.get_mut(&source.0) else { return Transfer::Failed(9) };
        if wire.closed || wire.shut {
            return Transfer::Failed(32);
        }
        let count = wire.send_room.map_or(bytes.len(), |room| room.min(bytes.len()));
        if count == 0 && !bytes.is_empty() {
            return Transfer::WouldBlock;
        }
        wire.to_client.extend_from_slice(&bytes[..count]);
        lab.calls.push(format!("send {} {}", source.0, count));
        Transfer::Data(count)
    }

    fn shutdown_write(&mut self, source: SourceId) -> bool {
        let mut lab = self.0.borrow_mut();
        lab.calls.push(format!("shutdown {}", source.0));
        match lab.wires.get_mut(&source.0) {
            Some(wire) if !wire.closed => {
                wire.shut = true;
                true
            }
            _ => false,
        }
    }

    fn close(&mut self, source: SourceId) {
        let mut lab = self.0.borrow_mut();
        lab.calls.push(format!("close {}", source.0));
        if let Some(wire) = lab.wires.get_mut(&source.0) {
            assert!(!wire.closed, "a source is closed once");
            wire.closed = true;
        }
    }

    fn monotonic(&self) -> Instant {
        self.0.borrow().now()
    }
}

/// A test client on one fake connection.
pub struct Peer {
    pub source: u64,
    pub tls: ClientConnection,
    pub received: Vec<u8>,
    pub error: Option<rustls::Error>,
}

impl Peer {
    pub fn new(source: u64, config: Arc<ClientConfig>) -> Peer {
        Peer { source, tls: client(config), received: Vec::new(), error: None }
    }

    /// Sends what the client has queued.
    pub fn push(&mut self, net: &SharedNet) {
        let bytes = drain_client(&mut self.tls);
        let mut lab = net.borrow_mut();
        if let Some(wire) = lab.wires.get_mut(&self.source) {
            wire.to_server.extend(bytes);
        }
    }

    /// Takes what the server sent and processes it; plaintext lands in `received`.
    pub fn pull(&mut self, net: &SharedNet) {
        let bytes = {
            let mut lab = net.borrow_mut();
            lab.wires.get_mut(&self.source).map(|wire| std::mem::take(&mut wire.to_client)).unwrap_or_default()
        };
        if let Err(error) = deliver_to_client(&bytes, &mut self.tls) {
            self.error = Some(error);
        }
        let mut chunk = [0u8; 8192];
        loop {
            match std::io::Read::read(&mut self.tls.reader(), &mut chunk) {
                Ok(0) => break,
                Ok(count) => self.received.extend_from_slice(&chunk[..count]),
                Err(_) => break,
            }
        }
    }

    /// Queues plaintext and sends it.
    pub fn write(&mut self, net: &SharedNet, bytes: &[u8]) {
        std::io::Write::write_all(&mut self.tls.writer(), bytes).expect("the client takes the plaintext");
        self.push(net);
    }

    /// Whether the client has seen the server's close_notify.
    pub fn closed_by_server(&mut self) -> bool {
        let mut chunk = [0u8; 16];
        matches!(std::io::Read::read(&mut self.tls.reader(), &mut chunk), Ok(0))
    }
}

/// A model view for the port alone: the connections the test says are open.
#[derive(Default)]
pub struct View {
    pub open: BTreeSet<String>,
}

impl GateView for View {
    fn connection_open(&self, conn: &str) -> bool {
        self.open.contains(conn)
    }

    fn pending_write(&self) -> Option<u16> {
        None
    }
}

// ------------------------------------------------------------------------------------------ a fake Os for the loop

/// A recorded poller request of a port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollCall {
    pub kind: &'static str,
    pub owner: Owner,
    pub source: u64,
    pub interest: Option<Interest>,
}

/// gate-tls's own fake `Os` (HE-003A's is in effect-gate's test tree): one broker connection on the I05 listener,
/// scripted wakes, the shared clock of the fake network, a fixed realtime clock.
pub struct LoopLab {
    pub broker: Option<(PeerCredentials, ProcIdentity)>,
    pub accepted: bool,
    pub inbox: VecDeque<Received>,
    pub sent: Vec<Vec<u8>>,
    pub closed: Vec<u64>,
    pub wakes: VecDeque<Vec<(u64, Readiness)>>,
    pub polls: Vec<PollCall>,
    pub realtime: i64,
    /// After this many more realtime reads, the realtime clock jumps to the given value.
    pub expire_after: Option<(u32, i64)>,
}

pub type SharedLoop = Rc<RefCell<LoopLab>>;

pub fn loop_lab(broker: (PeerCredentials, ProcIdentity)) -> SharedLoop {
    Rc::new(RefCell::new(LoopLab { broker: Some(broker), accepted: false, inbox: VecDeque::new(), sent: Vec::new(),
                                   closed: Vec::new(), wakes: VecDeque::new(), polls: Vec::new(),
                                   realtime: 1_900_000_000_000, expire_after: None }))
}

pub struct LoopOs {
    pub lab: SharedLoop,
    pub net: SharedNet,
}

impl PortPoll for LoopOs {
    fn port_add(&mut self, owner: Owner, source: SourceId, _token: u64, interest: Interest) -> bool {
        self.lab.borrow_mut().polls.push(PollCall { kind: "add", owner, source: source.0, interest: Some(interest) });
        true
    }

    fn port_modify(&mut self, owner: Owner, source: SourceId, _token: u64, interest: Interest) -> bool {
        self.lab.borrow_mut().polls.push(PollCall { kind: "modify", owner, source: source.0, interest: Some(interest) });
        true
    }

    fn port_delete(&mut self, owner: Owner, source: SourceId) -> bool {
        self.lab.borrow_mut().polls.push(PollCall { kind: "delete", owner, source: source.0, interest: None });
        true
    }
}

/// The broker connection's number.
pub const BROKER_CONN: u64 = 7;

impl Os for LoopOs {
    fn accept(&mut self, listener: Listen) -> Result<Option<ConnId>, OsFailure> {
        let mut lab = self.lab.borrow_mut();
        if listener == Listen::I05 && !lab.accepted {
            lab.accepted = true;
            return Ok(Some(ConnId(BROKER_CONN)));
        }
        Ok(None)
    }

    fn peer(&mut self, _conn: ConnId) -> Option<PeerCredentials> {
        self.lab.borrow().broker.as_ref().map(|broker| broker.0.clone())
    }

    fn open_proc(&mut self, _conn: ConnId, _pid: i32) -> bool {
        true
    }

    fn read_proc(&mut self, _conn: ConnId) -> Option<ProcIdentity> {
        self.lab.borrow().broker.as_ref().map(|broker| broker.1.clone())
    }

    fn peer_exited(&mut self, _conn: ConnId) -> bool {
        false
    }

    fn recv(&mut self, _conn: ConnId, _control_capacity: usize) -> Received {
        self.lab.borrow_mut().inbox.pop_front().unwrap_or(Received::WouldBlock)
    }

    fn send(&mut self, _conn: ConnId, bytes: &[u8]) -> bool {
        self.lab.borrow_mut().sent.push(bytes.to_vec());
        true
    }

    fn close(&mut self, conn: ConnId) {
        self.lab.borrow_mut().closed.push(conn.0);
    }

    fn watch(&mut self, _watch: Watch, _token: u64) -> bool {
        true
    }

    fn wait(&mut self, _timeout_ms: i32) -> Option<Vec<(u64, Readiness)>> {
        Some(self.lab.borrow_mut().wakes.pop_front().unwrap_or_default())
    }

    fn monotonic(&self) -> Instant {
        self.net.borrow().now()
    }

    fn realtime_ms(&self) -> Option<i64> {
        let mut lab = self.lab.borrow_mut();
        if let Some((left, value)) = lab.expire_after {
            if left == 0 {
                lab.realtime = value;
                lab.expire_after = None;
            } else {
                lab.expire_after = Some((left - 1, value));
            }
        }
        Some(lab.realtime)
    }
}
