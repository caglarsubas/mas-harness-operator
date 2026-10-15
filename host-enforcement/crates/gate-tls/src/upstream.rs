//! The upstream port (HE-003C DESIGN §2; MODEL_DEFINED R59-R66): the effect gate's apiserver client in the channel
//! substrate's loop, generic over effect-gate's `ConnectNet`, driving one sans-I/O rustls `ClientConnection` per
//! exchange. One port serves both channels, with at most one exchange open at a time (I05: the one consumed action;
//! I07: the one pending write; a WRITE_BEGIN drains I05 first, so the model never has both in flight).
//!
//! - **Start** (§2.1, D1-1): `apply` and `sync` return no events, so a start only arms the exchange. I05: on
//!   `Forward { action_id }` the board's request is taken only when confirmed with that action ID (D2-4); I07: in
//!   `sync`, when the model's pending write is one the port has not started, from `GateView::forwarded_write`. A
//!   missing request, a start while an exchange is open, or a head that is not a rendered form is a port failure. The
//!   bound is anchored at the arming call (900 s for I05, Decision 12; 10 s for I07, v3 W2), after the CONSUMED or
//!   WRITE_FORWARDED record of the same delivery; a start deadline at the anchor makes the next wait zero.
//! - **Connect** (§2.2): in `due`, a non-blocking connect to the one loopback apiserver address; in progress, the port
//!   waits for writability and reads SO_ERROR; any failure, error or hang-up is one LOST. I05 connect and handshake
//!   phase deadlines of 10 s each; I07 has none (its 10-second bound covers them).
//! - **Handshake, request, answer** (§2.3-§2.5): TLS 1.3 with the channel's identity (`tls_client`); then exactly the
//!   staged (I05) or rendered (I07) bytes; the answer read within the 64 KiB per-wake budget and framed by
//!   `http1::ResponseReader`; a complete answer re-checks the bound first (if it has passed nothing is fed and `due`
//!   feeds the TIMEOUT); the identity fields are read only where the model journals them (§4); I05 answers go through
//!   the board's `stage_response`, I07 answers through `exchange::write_response`; then `close_notify` and the close.
//! - **Outcomes** (§2.6): exactly one per exchange, Response, LOST or TIMEOUT; afterwards every deadline is cleared and
//!   the descriptor is only closed (closing removes it from the poller; a closed source is never deleted, D2-1), and a
//!   readiness for its token feeds nothing.
//! - **Seal and session end** (§2.7): when the model no longer holds the I05 connection open or the I07 write pending,
//!   `sync` closes the exchange and feeds nothing; so the model's late-upstream records are unreachable from this port.
//! - **Deadlines** (§2.8): `due` checks the bound first; a phase deadline gives LOST only when strictly earlier.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use effect_gate::net::{ConnectNet, Connecting, InetAddress};
use effect_gate::{Event, GateView, Interest, LoopExit, OutputKind, PolicyEvent, PolicyOutput, PolicyOutputKind, Port,
                  Readiness, Registry, SourceId, Transfer, UpstreamOutcome, UpstreamPort, WriteOperation};
use i05_protocol::json::{self, Value};
use i05_protocol::{Kind, Verb, MAX_DEPTH};
use rustls::{ClientConfig, ClientConnection, ProtocolVersion};

use crate::exchange::{is_resource_version, is_uid, write_response, BoardError, SharedExchange};
use crate::http1::{ResponseProgress, ResponseReader};
use crate::i04::READ_BUDGET;
use crate::tls_client::server_name;

/// The I05 upstream bound (Decision 12).
pub const UPSTREAM_BOUND: Duration = Duration::from_secs(900);
/// The I07 write bound (I07 v3 W2).
pub const WRITE_BOUND: Duration = Duration::from_secs(10);
/// The I05 connect phase deadline (R10-defined, from the I04 phase limits).
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(10);
/// The I05 handshake phase deadline (R10-defined, from the I04 phase limits).
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

/// The channel an exchange serves, with what its outcome event and its identity read need.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Channel {
    /// The verb and kind come from the staged head's method and resource plural, which the model already matched
    /// against the consumed action (Decision 4); the name from its path.
    I05 { conn: String, verb: Verb, kind: Kind, name: String },
    /// The operation, resource plural and name come from the rendered head of the pending write.
    I07 { write_id: u16, operation: WriteOperation, plural: String, name: String },
}

impl Channel {
    fn lost(self) -> PolicyEvent {
        match self {
            Channel::I05 { conn, .. } => PolicyEvent::Base(Event::UpstreamLost { conn }),
            Channel::I07 { write_id, .. } => PolicyEvent::WUpstream { write_id, outcome: UpstreamOutcome::Lost },
        }
    }

    fn timeout(self) -> PolicyEvent {
        match self {
            Channel::I05 { conn, .. } => PolicyEvent::Base(Event::UpstreamTimeout { conn }),
            Channel::I07 { write_id, .. } => PolicyEvent::WUpstream { write_id, outcome: UpstreamOutcome::Timeout },
        }
    }

    fn is_i05(&self) -> bool {
        matches!(self, Channel::I05 { .. })
    }

    /// R65: the identity form an answer with `status` must carry (DESIGN §4, Q-HE3C-6 (a), Q-HE3C-7 (a)).
    fn form(&self, status: u16) -> Form<'_> {
        match self {
            Channel::I05 { verb, kind, name, .. } => match (verb, status) {
                (Verb::Get, 200) | (Verb::Create, 201) => Form::Object,
                // The kind's deleteResponseBody: OBJECT for Pod and Service, STATUS for ConfigMap.
                (Verb::Delete, 200 | 202) if *kind == Kind::ConfigMap => Form::Status { plural: kind.plural(), name },
                (Verb::Delete, 200 | 202) => Form::Object,
                _ => Form::None,
            },
            Channel::I07 { operation, plural, name, .. } => {
                if !operation.is_success(i64::from(status)) {
                    Form::None
                } else if *operation == WriteOperation::Delete {
                    Form::Either { plural, name }
                } else {
                    Form::Object
                }
            }
        }
    }
}

/// Where the identity fields are read from (R65).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Form<'a> {
    /// Not journalled: UID and resourceVersion None, so Decision 0's reconciliation runs.
    None,
    /// An object with `metadata.uid` and `metadata.resourceVersion`.
    Object,
    /// A v1 `Status` with `status: "Success"`, `details.name`, `details.kind` (the resource plural) and `details.uid`.
    Status { plural: &'a str, name: &'a str },
    /// Either form (an I07 DELETE success).
    Either { plural: &'a str, name: &'a str },
}

/// Whether the nesting of a JSON text's arrays and objects stays within `limit`, counted over the brackets outside
/// strings before any value is built (a text that is not JSON is refused by the parser afterwards).
fn depth_within(body: &[u8], limit: usize) -> bool {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for &byte in body {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > limit {
                    return false;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

fn text<'a>(value: Option<&'a Value>) -> Option<&'a str> {
    value.and_then(Value::as_str)
}

/// The object form: `metadata.uid` and `metadata.resourceVersion` within the patterns; a `Status` is not an object.
fn object_identity(value: &Value) -> Option<(Option<String>, Option<String>)> {
    if text(value.get("kind")) == Some("Status") {
        return None;
    }
    let metadata = value.get("metadata")?;
    let uid = text(metadata.get("uid")).filter(|uid| is_uid(uid))?;
    let version = text(metadata.get("resourceVersion")).filter(|version| is_resource_version(version))?;
    Some((Some(uid.to_string()), Some(version.to_string())))
}

/// The v1 `Status` form: `apiVersion` v1, `kind` Status, `status` Success, `details.name` the request's name,
/// `details.kind` the resource plural and `details.uid` within the pattern; no resourceVersion is observed.
fn status_identity(value: &Value, plural: &str, name: &str) -> Option<(Option<String>, Option<String>)> {
    if text(value.get("apiVersion")) != Some("v1") || text(value.get("kind")) != Some("Status")
        || text(value.get("status")) != Some("Success")
    {
        return None;
    }
    let details = value.get("details")?;
    if text(details.get("name")) != Some(name) || text(details.get("kind")) != Some(plural) {
        return None;
    }
    let uid = text(details.get("uid")).filter(|uid| is_uid(uid))?;
    Some((Some(uid.to_string()), None))
}

/// R65: the UID and resourceVersion of an answer's body in `form`, or `None` when the form requires them and they
/// cannot be read (the exchange is then LOST, fail closed): depth at most 16 pre-scanned, UTF-8, then the
/// agreement-mode decoder (whitespace and floats allowed, duplicates and NaN refused), an object at the top.
fn identity(form: Form<'_>, body: &[u8]) -> Option<(Option<String>, Option<String>)> {
    if form == Form::None {
        return Some((None, None));
    }
    if !depth_within(body, MAX_DEPTH) {
        return None;
    }
    let value = json::parse(std::str::from_utf8(body).ok()?).ok()?;
    value.as_object()?;
    match form {
        Form::None => Some((None, None)),
        Form::Object => object_identity(&value),
        Form::Status { plural, name } => status_identity(&value, plural, name),
        Form::Either { plural, name } if text(value.get("kind")) == Some("Status") => {
            status_identity(&value, plural, name)
        }
        Form::Either { .. } => object_identity(&value),
    }
}

/// The method and the path segments of a head's request line `METHOD SP /path SP HTTP/1.1`.
fn request_line(head: &str) -> Option<(&str, Vec<&str>)> {
    let line = head.split("\r\n").next()?;
    let mut parts = line.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || version != "HTTP/1.1" {
        return None;
    }
    Some((method, target.strip_prefix('/')?.split('/').collect()))
}

/// An I05 exchange from the staged head: one of `render_request`'s three forms.
fn i05_channel(conn: &str, head: &str) -> Option<Channel> {
    let (method, segments) = request_line(head)?;
    let (verb, plural, name) = match (method, segments.as_slice()) {
        ("POST", ["api", "v1", "namespaces", _, plural]) => (Verb::Create, *plural, ""),
        ("GET", ["api", "v1", "namespaces", _, plural, name]) => (Verb::Get, *plural, *name),
        ("DELETE", ["api", "v1", "namespaces", _, plural, name]) => (Verb::Delete, *plural, *name),
        _ => return None,
    };
    let kind = [Kind::Pod, Kind::ConfigMap, Kind::Service].into_iter().find(|kind| kind.plural() == plural)?;
    Some(Channel::I05 { conn: conn.to_string(), verb, kind, name: name.to_string() })
}

/// An I07 exchange from the rendered head: POST to the collection, PUT or DELETE of the item (`render_write`).
fn i07_channel(write_id: u16, head: &str) -> Option<Channel> {
    let (method, segments) = request_line(head)?;
    let (operation, plural, name) = match (method, segments.as_slice()) {
        ("POST", [.., plural]) => (WriteOperation::Create, *plural, ""),
        ("PUT", [.., plural, name]) => (WriteOperation::Update, *plural, *name),
        ("DELETE", [.., plural, name]) => (WriteOperation::Delete, *plural, *name),
        _ => return None,
    };
    Some(Channel::I07 { write_id, operation, plural: plural.to_string(), name: name.to_string() })
}

/// An exchange's phase.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Phase {
    /// Armed: the connect runs at the start deadline.
    Armed,
    /// Waiting for the connect's writability.
    Connecting,
    Handshaking,
    /// Writing the request and reading the answer.
    Exchanging,
    /// A complete answer arrived after the bound: the descriptor is closed, nothing was fed, the TIMEOUT follows.
    Expired,
}

/// The one open exchange.
struct Open {
    channel: Channel,
    /// The exact bytes to send: the head, then the body.
    request: Vec<u8>,
    /// How many of them rustls has taken.
    sent: usize,
    bound: Instant,
    start: Option<Instant>,
    phase_deadline: Option<Instant>,
    phase: Phase,
    source: Option<SourceId>,
    registered: Option<Interest>,
    tls: Option<ClientConnection>,
    reader: ResponseReader,
}

/// `std::io::Read` over the port's `ConnectNet`, at most `budget` bytes in all.
struct NetRead<'a, C: ConnectNet> {
    net: &'a mut C,
    source: SourceId,
    budget: &'a mut usize,
}

impl<C: ConnectNet> io::Read for NetRead<'_, C> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let room = buffer.len().min(*self.budget);
        if room == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        match self.net.recv(self.source, &mut buffer[..room]) {
            Transfer::Data(count) => {
                *self.budget -= count.min(*self.budget);
                Ok(count)
            }
            Transfer::WouldBlock => Err(io::ErrorKind::WouldBlock.into()),
            Transfer::Eof => Ok(0),
            Transfer::Failed(_) => Err(io::ErrorKind::ConnectionReset.into()),
        }
    }
}

/// `std::io::Write` over the port's `ConnectNet`.
struct NetWrite<'a, C: ConnectNet> {
    net: &'a mut C,
    source: SourceId,
}

impl<C: ConnectNet> io::Write for NetWrite<'_, C> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.net.send(self.source, bytes) {
            Transfer::Data(count) => Ok(count),
            Transfer::WouldBlock => Err(io::ErrorKind::WouldBlock.into()),
            Transfer::Eof | Transfer::Failed(_) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Writes rustls's pending output until nothing is pending or the socket would block; `Err` on a failed send.
fn flush<C: ConnectNet>(net: &mut C, source: SourceId, tls: &mut ClientConnection) -> Result<(), ()> {
    while tls.wants_write() {
        match tls.write_tls(&mut NetWrite { net: &mut *net, source }) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

/// Once the handshake is done, gives rustls the request bytes it has not taken and writes them out; `Err` on a
/// refusal of rustls or a failed send.
fn write_out<C: ConnectNet>(net: &mut C, open: &mut Open) -> Result<(), ()> {
    let (Some(source), Some(tls)) = (open.source, open.tls.as_mut()) else { return Err(()) };
    if !tls.is_handshaking() {
        while open.sent < open.request.len() {
            match io::Write::write(&mut tls.writer(), &open.request[open.sent..]) {
                Ok(0) => break,
                Ok(count) => open.sent += count.min(open.request.len() - open.sent),
                Err(_) => return Err(()),
            }
            match tls.write_tls(&mut NetWrite { net: &mut *net, source }) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return Err(()),
            }
        }
    }
    flush(net, source, tls)
}

/// The result of reading the plaintext rustls holds.
enum Drained {
    /// The answer is not complete yet.
    More,
    /// The answer is complete and no byte followed it in this read.
    Complete,
    /// A refused answer, surplus, a close before the answer, or a read error.
    Lost,
}

/// Reads the plaintext of one `process_new_packets` into the answer reader (R63's "same read": surplus is any byte
/// after the complete answer in it). The server's `close_notify` after a complete answer is not surplus.
fn drain(open: &mut Open) -> Drained {
    let Some(tls) = open.tls.as_mut() else { return Drained::Lost };
    let mut chunk = [0u8; 4096];
    loop {
        match io::Read::read(&mut tls.reader(), &mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                if let ResponseProgress::Refused(_) = open.reader.push(&chunk[..count]) {
                    return Drained::Lost;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return match open.reader.progress() {
                    ResponseProgress::Complete => Drained::Complete,
                    ResponseProgress::NeedMore => Drained::More,
                    ResponseProgress::Refused(_) => Drained::Lost,
                };
            }
            Err(_) => break,
        }
    }
    // The server closed (close_notify, or the TCP close without it): only a complete answer counts.
    match open.reader.progress() {
        ResponseProgress::Complete => Drained::Complete,
        _ => Drained::Lost,
    }
}

/// `now + by`, or `now` itself when the clock cannot hold it (the deadline is then due at once: fail closed).
fn after(now: Instant, by: Duration) -> Instant {
    now.checked_add(by).unwrap_or(now)
}

/// The upstream port.
pub struct UpstreamClient<C: ConnectNet> {
    net: C,
    address: InetAddress,
    /// The gate effect identity's configuration (I05).
    effect: Arc<ClientConfig>,
    /// The gate writer identity's configuration (I07).
    writer: Arc<ClientConfig>,
    exchange: SharedExchange,
    open: Option<Open>,
    /// The last I07 write started (write IDs are never reused within a generation).
    started_write: Option<u16>,
    failure: Option<&'static str>,
}

impl<C: ConnectNet> UpstreamClient<C> {
    /// The port: its connections, the one apiserver address (`PolicyGate::apiserver_address`, parsed once by R16), the
    /// two identities' configurations (`tls_client::client_config`) and the board shared with the I04 port.
    pub fn new(net: C, address: InetAddress, effect: Arc<ClientConfig>, writer: Arc<ClientConfig>,
               exchange: SharedExchange) -> UpstreamClient<C> {
        UpstreamClient { net, address, effect, writer, exchange, open: None, started_write: None, failure: None }
    }

    /// The connections (read only; the tests' fakes record through them).
    pub fn net(&self) -> &C {
        &self.net
    }

    /// Whether an exchange is open (for the tests).
    pub fn is_open(&self) -> bool {
        self.open.is_some()
    }

    fn fail(&mut self, reason: &'static str) {
        if self.failure.is_none() {
            self.failure = Some(reason);
        }
    }

    /// Arms an exchange (§2.1): the bound from the anchor now, and a start deadline at the anchor.
    fn arm(&mut self, channel: Channel, request: Vec<u8>, bound: Duration) {
        let anchor = self.net.monotonic();
        let Some(bound) = anchor.checked_add(bound) else {
            self.fail("the monotonic clock cannot hold the upstream bound");
            return;
        };
        self.open = Some(Open {
            channel,
            request,
            sent: 0,
            bound,
            start: Some(anchor),
            phase_deadline: None,
            phase: Phase::Armed,
            source: None,
            registered: None,
            tls: None,
            reader: ResponseReader::new(),
        });
    }

    /// Ends the exchange: `close_notify` first when asked and the handshake is done (one best-effort flush), then the
    /// descriptor's close (never a poller delete, D2-1); every deadline goes with it. Its channel.
    fn end(&mut self, notify: bool) -> Option<Channel> {
        let mut open = self.open.take()?;
        if let (Some(source), Some(tls)) = (open.source, open.tls.as_mut())
            && notify
            && !tls.is_handshaking()
        {
            tls.send_close_notify();
            let _best_effort = flush(&mut self.net, source, tls);
        }
        if let Some(source) = open.source {
            self.net.close(source);
        }
        Some(open.channel)
    }

    /// One LOST for the open exchange, which ends.
    fn lose(&mut self) -> Vec<PolicyEvent> {
        self.end(false).map(Channel::lost).into_iter().collect()
    }

    /// §2.2: the connect, from `due` at the start deadline.
    fn connect(&mut self, now: Instant) -> Vec<PolicyEvent> {
        let address = self.address;
        let started = self.net.connect(&address);
        let Some(open) = self.open.as_mut() else { return Vec::new() };
        open.start = None;
        match started {
            Err(_) => self.lose(),
            Ok((source, Connecting::InProgress)) => {
                open.source = Some(source);
                open.phase = Phase::Connecting;
                open.phase_deadline = open.channel.is_i05().then(|| after(now, CONNECT_DEADLINE));
                Vec::new()
            }
            Ok((source, Connecting::Connected)) => {
                open.source = Some(source);
                self.handshake(now)
            }
        }
    }

    /// §2.3: the TLS client of the exchange's identity, its first flight sent.
    fn handshake(&mut self, now: Instant) -> Vec<PolicyEvent> {
        let address = self.address;
        let Some(open) = self.open.as_mut() else { return Vec::new() };
        let config = if open.channel.is_i05() { self.effect.clone() } else { self.writer.clone() };
        let Ok(tls) = ClientConnection::new(config, server_name(&address)) else { return self.lose() };
        open.tls = Some(tls);
        open.phase = Phase::Handshaking;
        open.phase_deadline = open.channel.is_i05().then(|| after(now, HANDSHAKE_DEADLINE));
        if write_out(&mut self.net, open).is_err() {
            return self.lose();
        }
        Vec::new()
    }

    /// §2.3-§2.5 for a readiness of a handshaking or exchanging connection.
    fn drive(&mut self, readiness: Readiness) -> Vec<PolicyEvent> {
        let Some(open) = self.open.as_mut() else { return Vec::new() };
        if write_out(&mut self.net, open).is_err() {
            return self.lose();
        }
        let Some(source) = open.source else { return self.lose() };
        let mut budget = READ_BUDGET;
        loop {
            let Some(tls) = open.tls.as_mut() else { return self.lose() };
            match tls.read_tls(&mut NetRead { net: &mut self.net, source, budget: &mut budget }) {
                Ok(0) => return self.lose(), // the server closed before a complete answer
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return self.lose(),
            }
            if tls.process_new_packets().is_err() {
                // rustls queued its alert: flushed once, best effort.
                let _best_effort = flush(&mut self.net, source, tls);
                return self.lose();
            }
            if open.phase == Phase::Handshaking && !tls.is_handshaking() {
                // Defence in depth: the configuration offers TLS 1.3 only.
                if tls.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
                    return self.lose();
                }
                open.phase = Phase::Exchanging;
                open.phase_deadline = None;
            }
            match drain(open) {
                Drained::More => {}
                Drained::Complete => return self.complete(),
                Drained::Lost => return self.lose(),
            }
            if write_out(&mut self.net, open).is_err() {
                return self.lose();
            }
        }
        if readiness.error {
            return self.lose(); // an error the reads did not surface
        }
        Vec::new()
    }

    /// §2.5: a complete answer. The bound is re-checked first: past it nothing is fed and the descriptor closes, so
    /// `due` feeds the TIMEOUT. Otherwise the identity is read where the model journals it and the outcome built.
    fn complete(&mut self) -> Vec<PolicyEvent> {
        let now = self.net.monotonic();
        let Some(open) = self.open.as_mut() else { return Vec::new() };
        if now >= open.bound {
            if let Some(source) = open.source.take() {
                self.net.close(source);
            }
            open.tls = None;
            open.phase = Phase::Expired;
            open.phase_deadline = None;
            open.start = None;
            return Vec::new();
        }
        let reader = std::mem::take(&mut open.reader);
        let Some(channel) = self.end(true) else { return Vec::new() };
        let lost = channel.clone().lost();
        let Some((status, body)) = reader.answer() else { return vec![lost] };
        let Some((uid, resource_version)) = identity(channel.form(status), &body) else { return vec![lost] };
        match channel {
            Channel::I05 { conn, .. } => {
                let staged = match self.exchange.try_borrow_mut() {
                    Ok(mut board) => board.stage_response(&conn, status, body, uid, resource_version),
                    Err(_) => Err(BoardError::Occupied),
                };
                match staged {
                    Ok(event) => vec![event],
                    Err(BoardError::Status | BoardError::Size) => vec![lost],
                    Err(BoardError::Occupied) => {
                        self.fail("the exchange board's response slot was occupied or busy");
                        Vec::new()
                    }
                }
            }
            Channel::I07 { write_id, .. } => vec![write_response(write_id, status, &body, uid, resource_version)],
        }
    }

    /// The interest the open exchange asks for (rustls's wants_read and wants_write, so the poller never spins).
    fn interest(open: &Open) -> Option<Interest> {
        match open.phase {
            Phase::Connecting => Some(Interest { readable: false, writable: true }),
            Phase::Handshaking | Phase::Exchanging => open.tls.as_ref().map(|tls| Interest {
                readable: tls.wants_read(),
                writable: tls.wants_write() || (!tls.is_handshaking() && open.sent < open.request.len()),
            }),
            Phase::Armed | Phase::Expired => None,
        }
    }
}

impl<C: ConnectNet> Port for UpstreamClient<C> {
    fn register(&mut self, registry: &mut Registry<'_>) -> Result<(), LoopExit> {
        let Some(open) = self.open.as_mut() else { return Ok(()) };
        let (Some(source), Some(wanted)) = (open.source, UpstreamClient::<C>::interest(open)) else { return Ok(()) };
        match open.registered {
            None => registry.add(source, source.0, wanted)?,
            Some(current) if current != wanted => registry.modify(source, source.0, wanted)?,
            Some(_) => {}
        }
        open.registered = Some(wanted);
        Ok(())
    }

    fn next_deadline(&self) -> Option<Instant> {
        let open = self.open.as_ref()?;
        [Some(open.bound), open.start, open.phase_deadline].into_iter().flatten().min()
    }

    fn due(&mut self, now: Instant) -> Vec<PolicyEvent> {
        let Some(open) = self.open.as_ref() else { return Vec::new() };
        // The bound first (R1-9, D1-2): whatever phase deadline is due too, the TIMEOUT is fed.
        if open.bound <= now {
            return self.end(false).map(Channel::timeout).into_iter().collect();
        }
        if open.start.is_some_and(|start| start <= now) {
            return self.connect(now);
        }
        // A phase deadline (I05 only), strictly earlier than the bound here.
        if open.phase_deadline.is_some_and(|deadline| deadline <= now) {
            return self.lose();
        }
        Vec::new()
    }

    fn ready(&mut self, value: u64, readiness: Readiness) -> Vec<PolicyEvent> {
        let Some(open) = self.open.as_ref() else { return Vec::new() };
        let Some(source) = open.source.filter(|source| source.0 == value) else {
            return Vec::new(); // a closed exchange's token
        };
        match open.phase {
            Phase::Connecting => {
                if readiness.error || readiness.hangup {
                    return self.lose();
                }
                if !readiness.writable {
                    return Vec::new();
                }
                match self.net.connect_result(source) {
                    Ok(()) => {
                        let now = self.net.monotonic();
                        self.handshake(now)
                    }
                    Err(_) => self.lose(),
                }
            }
            Phase::Handshaking | Phase::Exchanging => self.drive(readiness),
            Phase::Armed | Phase::Expired => Vec::new(),
        }
    }

    fn apply(&mut self, output: &PolicyOutput) {
        let PolicyOutputKind::Base(base) = &output.kind else { return };
        let OutputKind::Forward { action_id } = base.kind else { return };
        if self.open.is_some() {
            self.fail("an I05 exchange started while an exchange is open");
            return;
        }
        let taken = match self.exchange.try_borrow_mut() {
            Ok(mut board) => board.take_request(action_id),
            Err(_) => None,
        };
        let Some(request) = taken else {
            self.fail("a forward without the staged request confirmed with its action ID");
            return;
        };
        let Some(channel) = i05_channel(&request.conn, &request.head) else {
            self.fail("the forwarded request is not one of the rendered I05 forms");
            return;
        };
        let mut bytes = request.head.into_bytes();
        bytes.extend_from_slice(&request.body);
        self.arm(channel, bytes, UPSTREAM_BOUND);
    }

    fn sync(&mut self, view: &dyn GateView) {
        // §2.7: the model sealed the consumed action, or the writer session ended.
        let aborted = match self.open.as_ref().map(|open| &open.channel) {
            Some(Channel::I05 { conn, .. }) => !view.connection_open(conn),
            Some(Channel::I07 { write_id, .. }) => view.pending_write() != Some(*write_id),
            None => false,
        };
        if aborted {
            self.end(false);
        }
        // §2.1: the I07 start, from the rendered write the model forwarded.
        let Some(write_id) = view.pending_write() else { return };
        if self.started_write == Some(write_id) {
            return;
        }
        self.started_write = Some(write_id);
        if self.open.is_some() {
            self.fail("an I07 write started while an exchange is open");
            return;
        }
        let Some((_, rendered)) = view.forwarded_write().filter(|(forwarded, _)| *forwarded == write_id) else {
            self.fail("a pending write without its rendered request");
            return;
        };
        let Some(channel) = i07_channel(write_id, &rendered.head) else {
            self.fail("the pending write's request is not one of the rendered I07 forms");
            return;
        };
        let mut bytes = rendered.head.as_bytes().to_vec();
        bytes.extend_from_slice(&rendered.body);
        self.arm(channel, bytes, WRITE_BOUND);
    }

    fn failure(&self) -> Option<&'static str> {
        self.failure
    }
}

impl<C: ConnectNet> UpstreamPort for UpstreamClient<C> {}
