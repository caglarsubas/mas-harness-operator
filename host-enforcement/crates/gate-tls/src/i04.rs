//! The I04 port (HE-003B DESIGN §5.3, §5.4, §6, §7; MODEL_DEFINED R43-R53, R56, R57): the gate's KUBERNETES_API_PROXY
//! listener in the channel substrate's loop, generic over effect-gate's `StreamNet`, driving one sans-I/O rustls
//! `ServerConnection` per connection.
//!
//! - **Accept** (C2, C3, R43, R45): every accept feeds `Backlog` then `Accept` before any TLS byte, so the stamp is the
//!   action armed at the TCP accept. At most 64 accepts per readiness; the pre-frame drain accepts until the queue is
//!   empty and fails closed past 1,024. At most 16 connections are held; one accepted beyond that is closed unfed.
//! - **Model-held** (Q-HE3B-24 (a), R57): a connection is unconfirmed from its accept to the first `sync` that sees it
//!   open; `sync` never closes an unconfirmed one, and `register` stops the loop if one is left at the end of a wake.
//! - **Phases**: handshaking (deadline accept + 10 s), reading (handshake + 10 s), fed (its `Request` returned, at
//!   most one), in flight (after `Forward`; no I04 deadline), relaying and lingering (relay start + 10 s), closed.
//! - **Reads** (§5.3): at most 64 KiB of ciphertext (or of discarded linger bytes) per connection per wake; after the
//!   request is fed its bytes never reach rustls again (R49).
//! - **Closing** (§7.1, R44, R51): a connection the port ends on its own before its request feeds `Disconnect` once it
//!   is model-held; a connection the model closed is closed by `sync` without one; a refusal gets `close_notify` and no
//!   HTTP byte; a relayed response is followed by `close_notify`, the write-side shutdown once rustls has nothing left
//!   to write, and a bounded linger that reads and discards.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use effect_gate::{Accepted, Event, GateView, I04Port, Interest, LoopExit, OutputKind, Owner, PolicyEvent, PolicyOutput,
                  PolicyOutputKind, Port, Readiness, Registry, SourceId, StreamNet, Transfer};
use i05_protocol::sha256;
use rustls::{ProtocolVersion, ServerConfig, ServerConnection};

use crate::exchange::SharedExchange;
use crate::http1::{frame, render_response, Frame, BODY_LIMIT, HEAD_LIMIT};
use crate::tls::certificate_digest;

/// The handshake, request and relay deadlines (Q-HE3B-16 (a), Q-HE3B-19 (a)).
pub const PHASE_DEADLINE: Duration = Duration::from_secs(10);
/// The connections held at once (Q-HE3B-21 (a)).
pub const CONNECTION_CAP: usize = 16;
/// The accepts of one `ready(listener)`.
pub const ACCEPTS_PER_READY: usize = 64;
/// The accepts of one pre-frame drain before the port fails (closed).
pub const DRAIN_LIMIT: usize = 1_024;
/// The bytes read from one connection in one wake (ciphertext, or discarded linger bytes).
pub const READ_BUDGET: usize = 64 * 1024;

/// The listener's token value.
const LISTENER: u64 = 0;
/// The plaintext kept for one request: a head and a body at their limits.
const REQUEST_LIMIT: usize = HEAD_LIMIT + BODY_LIMIT;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Phase {
    Handshaking,
    Reading,
    Fed,
    InFlight,
    Relaying,
    Lingering,
}

/// One connection.
struct Connection {
    name: String,
    tls: ServerConnection,
    phase: Phase,
    confirmed: bool,
    deadline: Option<Instant>,
    plaintext: Vec<u8>,
    certificate: Option<String>,
    registered: Option<Interest>,
    /// The client hung up while its request was in flight: the descriptor is closed, the relay will be skipped.
    gone: bool,
    /// The response plaintext not yet given to rustls.
    response: Vec<u8>,
    notified: bool,
}

/// `std::io::Read` over the port's `StreamNet`, at most `budget` bytes in all.
struct NetRead<'a, N: StreamNet> {
    net: &'a mut N,
    source: SourceId,
    budget: &'a mut usize,
}

impl<N: StreamNet> io::Read for NetRead<'_, N> {
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

/// `std::io::Write` over the port's `StreamNet`.
struct NetWrite<'a, N: StreamNet> {
    net: &'a mut N,
    source: SourceId,
}

impl<N: StreamNet> io::Write for NetWrite<'_, N> {
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

/// The I04 port.
pub struct I04Server<N: StreamNet> {
    net: N,
    config: Arc<ServerConfig>,
    exchange: SharedExchange,
    conns: BTreeMap<u64, Connection>,
    listener_registered: bool,
    /// The connection whose `Request` was returned and whose output is awaited.
    fed: Option<u64>,
    /// The connection whose request was forwarded.
    in_flight: Option<u64>,
    failure: Option<&'static str>,
}

impl<N: StreamNet> I04Server<N> {
    pub fn new(net: N, config: Arc<ServerConfig>, exchange: SharedExchange) -> I04Server<N> {
        I04Server { net, config, exchange, conns: BTreeMap::new(), listener_registered: false, fed: None,
                    in_flight: None, failure: None }
    }

    /// The stream I/O (read only; the tests' fakes record through it).
    pub fn net(&self) -> &N {
        &self.net
    }

    /// The connections held, by name (for the tests).
    pub fn held(&self) -> Vec<String> {
        self.conns.values().filter(|conn| !conn.gone).map(|conn| conn.name.clone()).collect()
    }

    fn fail(&mut self, reason: &'static str) {
        if self.failure.is_none() {
            self.failure = Some(reason);
        }
    }

    fn live(&self) -> usize {
        self.conns.values().filter(|conn| !conn.gone).count()
    }

    // ------------------------------------------------------------------------------------------ accept

    /// Accepts up to `limit` connections (all of them with `None`), each fed as `Backlog` then `Accept`.
    fn accept(&mut self, limit: Option<usize>) -> Vec<PolicyEvent> {
        let mut events = Vec::new();
        let mut calls = 0usize;
        loop {
            if limit.is_some_and(|limit| calls >= limit) {
                break;
            }
            if limit.is_none() && calls > DRAIN_LIMIT {
                // A sustained connect flood: the loop stops before the frame (fail closed, R43).
                self.fail("the pre-frame drain passed 1,024 accepts");
                break;
            }
            calls += 1;
            match self.net.accept() {
                Accepted::Conn(source) => {
                    if self.live() >= CONNECTION_CAP {
                        self.net.close(source); // R45: over the cap, closed unfed
                        continue;
                    }
                    let Ok(tls) = ServerConnection::new(self.config.clone()) else {
                        self.net.close(source);
                        continue;
                    };
                    let name = format!("i04-{}", source.0);
                    let deadline = Some(self.net.monotonic() + PHASE_DEADLINE);
                    self.conns.insert(source.0, Connection {
                        name: name.clone(),
                        tls,
                        phase: Phase::Handshaking,
                        confirmed: false,
                        deadline,
                        plaintext: Vec::new(),
                        certificate: None,
                        registered: None,
                        gone: false,
                        response: Vec::new(),
                        notified: false,
                    });
                    events.push(PolicyEvent::Base(Event::Backlog { conn: name.clone() }));
                    events.push(PolicyEvent::Base(Event::Accept { conn: name }));
                }
                Accepted::Empty => break,
                Accepted::Skip => continue,
                Accepted::Failed(_) => {
                    self.fail("an accept on the I04 listener failed");
                    break;
                }
            }
        }
        events
    }

    // ------------------------------------------------------------------------------------------ closing

    /// Writes rustls's pending output until nothing is pending or the socket would block; false on a failed send.
    fn flush(&mut self, id: u64) -> bool {
        let Some(conn) = self.conns.get_mut(&id) else { return false };
        while conn.tls.wants_write() {
            let mut writer = NetWrite { net: &mut self.net, source: SourceId(id) };
            match conn.tls.write_tls(&mut writer) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return false,
            }
        }
        true
    }

    /// Closes a connection: `close_notify` first when asked and the handshake has finished (one best-effort flush),
    /// then the descriptor. The entry is removed.
    fn close(&mut self, id: u64, notify: bool) {
        if let Some(conn) = self.conns.get_mut(&id) {
            if notify && !conn.gone && !conn.tls.is_handshaking() && !conn.notified {
                conn.tls.send_close_notify();
                conn.notified = true;
                let _best_effort = self.flush(id);
            }
        }
        if let Some(conn) = self.conns.remove(&id)
            && !conn.gone
        {
            self.net.close(SourceId(id));
        }
        if self.in_flight == Some(id) {
            self.in_flight = None;
        }
    }

    /// The port ends a connection on its own before its request: `close_notify` when the handshake has finished, the
    /// close, and `Disconnect` once the model holds it (R44).
    fn disconnect(&mut self, id: u64, events: &mut Vec<PolicyEvent>) {
        let held = self.conns.get(&id).map(|conn| (conn.confirmed, conn.name.clone()));
        self.close(id, true);
        if let Some((true, name)) = held {
            events.push(PolicyEvent::Base(Event::Disconnect { conn: name }));
        }
    }

    // ------------------------------------------------------------------------------------------ reading

    /// §5.3's read step for a handshaking or reading connection: `Disconnect`, at most one `Request`, or nothing yet.
    fn read(&mut self, id: u64) -> Vec<PolicyEvent> {
        let mut events = Vec::new();
        let mut budget = READ_BUDGET;
        loop {
            let Some(conn) = self.conns.get_mut(&id) else { return events };
            let mut reader = NetRead { net: &mut self.net, source: SourceId(id), budget: &mut budget };
            let read = conn.tls.read_tls(&mut reader);
            match read {
                Ok(0) => {
                    self.disconnect(id, &mut events); // EOF before a request
                    return events;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.disconnect(id, &mut events);
                    return events;
                }
            }
            if conn.tls.process_new_packets().is_err() {
                // rustls queued its alert: flushed once, best effort, then closed.
                let _best_effort = self.flush(id);
                if let Some(conn) = self.conns.get_mut(&id) {
                    conn.notified = true;
                }
                self.disconnect(id, &mut events);
                return events;
            }
            match self.after_packets(id) {
                Step::Continue => {}
                Step::Done(mut more) => {
                    events.append(&mut more);
                    return events;
                }
            }
        }
        if !self.flush(id) {
            self.disconnect(id, &mut events);
        }
        events
    }

    /// After `process_new_packets`: the handshake check, then the plaintext and the framing.
    fn after_packets(&mut self, id: u64) -> Step {
        let now = self.net.monotonic();
        let Some(conn) = self.conns.get_mut(&id) else { return Step::Done(Vec::new()) };
        if conn.phase == Phase::Handshaking && !conn.tls.is_handshaking() {
            // Defence in depth: both are forced by the configuration.
            let certificate = certificate_digest(&conn.tls);
            if conn.tls.protocol_version() != Some(ProtocolVersion::TLSv1_3) || certificate.is_none() {
                let mut events = Vec::new();
                self.disconnect(id, &mut events);
                return Step::Done(events);
            }
            conn.certificate = certificate;
            conn.phase = Phase::Reading;
            conn.deadline = Some(now + PHASE_DEADLINE);
        }
        if conn.phase != Phase::Reading {
            return Step::Continue;
        }
        let mut chunk = [0u8; 4096];
        // rustls hands back buffered plaintext before Ok(0) (the client's close_notify), so a whole request and the
        // close_notify can arrive in one batch: frame what was received first (PR review R1-1). Only a request that is
        // still incomplete, or an oversize head, ends in a Disconnect.
        let mut closed = false;
        loop {
            match io::Read::read(&mut conn.tls.reader(), &mut chunk) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(count) => {
                    let room = REQUEST_LIMIT.saturating_sub(conn.plaintext.len());
                    conn.plaintext.extend_from_slice(&chunk[..count.min(room)]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    let mut events = Vec::new();
                    self.disconnect(id, &mut events);
                    return Step::Done(events);
                }
            }
        }
        match frame(&conn.plaintext) {
            Frame::NeedMore if closed => {
                // The client's close_notify before a whole request: a truncated request.
                let mut events = Vec::new();
                self.disconnect(id, &mut events);
                Step::Done(events)
            }
            Frame::NeedMore => Step::Continue,
            Frame::OversizeHead => {
                let mut events = Vec::new();
                self.disconnect(id, &mut events);
                Step::Done(events)
            }
            Frame::Request { head, body, body_digest } => {
                conn.phase = Phase::Fed;
                conn.deadline = None;
                conn.plaintext = Vec::new(); // surplus discarded, never parsed (R49)
                let event = Event::Request {
                    conn: conn.name.clone(),
                    certificate_digest: conn.certificate.clone().unwrap_or_default(),
                    head: head.clone(),
                    body_digest,
                };
                let staged = match self.exchange.try_borrow_mut() {
                    Ok(mut board) => board.stage_request(&conn.name, &head, &body).is_ok(),
                    Err(_) => false,
                };
                if !staged {
                    self.fail("the exchange board's request slot was occupied or busy");
                }
                self.fed = Some(id);
                Step::Done(vec![PolicyEvent::Base(event)])
            }
        }
    }

    // ------------------------------------------------------------------------------------------ relaying

    /// Gives the response plaintext to rustls and writes it out; then `close_notify`; then, once rustls has nothing
    /// left to write, the write-side shutdown and the linger (§7.1, D2-3).
    fn relay(&mut self, id: u64) {
        let Some(conn) = self.conns.get_mut(&id) else { return };
        while !conn.response.is_empty() {
            match io::Write::write(&mut conn.tls.writer(), &conn.response) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    conn.response.drain(..count.min(conn.response.len()));
                }
            }
            let mut writer = NetWrite { net: &mut self.net, source: SourceId(id) };
            match conn.tls.write_tls(&mut writer) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.close(id, false);
                    return;
                }
            }
        }
        if !self.flush(id) {
            self.close(id, false);
            return;
        }
        let Some(conn) = self.conns.get_mut(&id) else { return };
        if conn.response.is_empty() && !conn.notified {
            conn.tls.send_close_notify();
            conn.notified = true;
            if !self.flush(id) {
                self.close(id, false);
                return;
            }
        }
        let Some(conn) = self.conns.get_mut(&id) else { return };
        if conn.notified && conn.response.is_empty() && !conn.tls.wants_write() && conn.phase == Phase::Relaying {
            if self.net.shutdown_write(SourceId(id)) {
                conn.phase = Phase::Lingering;
            } else {
                self.close(id, false);
            }
        }
    }

    /// Reads and discards a lingering connection's raw bytes within the per-wake budget; EOF or an error closes it.
    fn linger(&mut self, id: u64) {
        let mut budget = READ_BUDGET;
        let mut scratch = [0u8; 4096];
        while budget > 0 {
            let room = scratch.len().min(budget);
            match self.net.recv(SourceId(id), &mut scratch[..room]) {
                Transfer::Data(count) => budget -= count.min(budget),
                Transfer::WouldBlock => return,
                Transfer::Eof | Transfer::Failed(_) => {
                    self.close(id, false);
                    return;
                }
            }
        }
    }

    /// Starts the relay of the staged response for the connection in flight (`Upstream { relayed: true }`).
    fn start_relay(&mut self) {
        let Some(staged) = self.exchange.try_borrow_mut().map(|mut board| board.take_response()).ok() else {
            self.fail("the exchange board was busy");
            return;
        };
        let Some(id) = self.in_flight else { return };
        let Some(conn) = self.conns.get(&id) else {
            self.in_flight = None;
            return;
        };
        let Some(response) = staged else {
            self.fail("a relayed outcome without a staged response");
            self.close(id, false);
            return;
        };
        if response.conn != conn.name || sha256::prefixed(&response.body) != response.body_digest {
            self.fail("the staged response does not match the connection in flight");
            self.close(id, false);
            return;
        }
        if conn.gone {
            self.close(id, false); // the client hung up in flight: the relay is skipped
            return;
        }
        let Ok(bytes) = render_response(response.status, &response.body) else {
            self.close(id, false); // a refusal of the renderer: no byte
            return;
        };
        let now = self.net.monotonic();
        if let Some(conn) = self.conns.get_mut(&id) {
            conn.phase = Phase::Relaying;
            conn.deadline = Some(now + PHASE_DEADLINE);
            conn.response = bytes;
        }
        self.relay(id);
    }

    /// The interest a connection's phase asks for.
    fn interest(conn: &Connection) -> Interest {
        let pending = conn.tls.wants_write() || !conn.response.is_empty();
        match conn.phase {
            Phase::Handshaking | Phase::Reading | Phase::Lingering => Interest { readable: true, writable: pending },
            Phase::Fed | Phase::InFlight | Phase::Relaying => Interest { readable: false, writable: pending },
        }
    }
}

enum Step {
    Continue,
    Done(Vec<PolicyEvent>),
}

impl<N: StreamNet> Port for I04Server<N> {
    fn register(&mut self, registry: &mut Registry<'_>) -> Result<(), LoopExit> {
        if self.conns.values().any(|conn| !conn.confirmed) {
            // A connection whose Accept was never fed: a substrate defect (R57).
            return Err(LoopExit::Port(Owner::I04, "an accepted I04 connection was never confirmed by the model"));
        }
        if !self.listener_registered {
            registry.add(self.net.listener(), LISTENER, Interest { readable: true, writable: false })?;
            self.listener_registered = true;
        }
        for (id, conn) in self.conns.iter_mut() {
            if conn.gone {
                continue;
            }
            let wanted = I04Server::<N>::interest(conn);
            match conn.registered {
                None => registry.add(SourceId(*id), *id, wanted)?,
                Some(current) if current != wanted => registry.modify(SourceId(*id), *id, wanted)?,
                Some(_) => {}
            }
            conn.registered = Some(wanted);
        }
        Ok(())
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.conns.values().filter_map(|conn| conn.deadline).min()
    }

    fn due(&mut self, now: Instant) -> Vec<PolicyEvent> {
        let mut events = Vec::new();
        let due: Vec<(u64, Phase)> = self
            .conns
            .iter()
            .filter(|(_, conn)| conn.deadline.is_some_and(|deadline| deadline <= now))
            .map(|(id, conn)| (*id, conn.phase))
            .collect();
        for (id, phase) in due {
            match phase {
                Phase::Handshaking | Phase::Reading => self.disconnect(id, &mut events),
                // The relay's deadline: closed without the shutdown, nothing fed (the model holds it closed).
                _ => self.close(id, false),
            }
        }
        events
    }

    fn ready(&mut self, value: u64, readiness: Readiness) -> Vec<PolicyEvent> {
        if value == LISTENER {
            return self.accept(Some(ACCEPTS_PER_READY));
        }
        let Some(phase) = self.conns.get(&value).filter(|conn| !conn.gone).map(|conn| conn.phase) else {
            return Vec::new(); // closed earlier in this wake
        };
        match phase {
            Phase::Handshaking | Phase::Reading => self.read(value),
            Phase::Fed => Vec::new(),
            Phase::InFlight => {
                if readiness.error || readiness.hangup {
                    // The client is gone: its descriptor closes now, the later relay is skipped.
                    self.net.close(SourceId(value));
                    if let Some(conn) = self.conns.get_mut(&value) {
                        conn.gone = true;
                    }
                } else if readiness.writable && !self.flush(value) {
                    self.net.close(SourceId(value));
                    if let Some(conn) = self.conns.get_mut(&value) {
                        conn.gone = true;
                    }
                }
                Vec::new()
            }
            Phase::Relaying => {
                if readiness.error {
                    self.close(value, false);
                } else {
                    self.relay(value);
                }
                Vec::new()
            }
            Phase::Lingering => {
                self.linger(value);
                Vec::new()
            }
        }
    }

    fn apply(&mut self, output: &PolicyOutput) {
        let PolicyOutputKind::Base(base) = &output.kind else { return };
        match &base.kind {
            OutputKind::Close(_) => {
                // The fed connection closes, unless sync already closed it (no second close_notify).
                if let Some(id) = self.fed.take() {
                    self.close(id, true);
                }
                if let Ok(mut board) = self.exchange.try_borrow_mut() {
                    board.drop_request();
                } else {
                    self.fail("the exchange board was busy");
                }
            }
            OutputKind::Forward { action_id } => {
                let Some(id) = self.fed.take() else {
                    self.fail("a forward without a fed connection");
                    return;
                };
                let name = match self.conns.get_mut(&id) {
                    Some(conn) => {
                        conn.phase = Phase::InFlight;
                        conn.name.clone()
                    }
                    None => {
                        self.fail("a forward for a connection already closed");
                        return;
                    }
                };
                self.in_flight = Some(id);
                let confirmed = match self.exchange.try_borrow_mut() {
                    Ok(mut board) => board.confirm_request(&name, *action_id),
                    Err(_) => false,
                };
                if !confirmed {
                    self.fail("the forwarded request is not the staged one");
                }
            }
            OutputKind::Upstream { relayed: true, .. } => self.start_relay(),
            OutputKind::Upstream { relayed: false, .. } => {
                if let Ok(mut board) = self.exchange.try_borrow_mut() {
                    board.drop_response();
                } else {
                    self.fail("the exchange board was busy");
                }
                if let Some(id) = self.in_flight {
                    self.close(id, false); // R51: not relayed, closed without a byte
                }
            }
            OutputKind::LateUpstream => {
                if let Ok(mut board) = self.exchange.try_borrow_mut() {
                    board.drop_response();
                } else {
                    self.fail("the exchange board was busy");
                }
            }
            _ => {}
        }
    }

    fn sync(&mut self, view: &dyn GateView) {
        let ids: Vec<u64> = self.conns.keys().copied().collect();
        for id in ids {
            let Some(conn) = self.conns.get_mut(&id) else { continue };
            let open = view.connection_open(&conn.name);
            if !conn.confirmed {
                if open {
                    conn.confirmed = true; // its own Accept was just fed
                }
                continue;
            }
            if open {
                continue;
            }
            match conn.phase {
                // The model closes the consumed connection when the outcome arrives; the relay closes it.
                Phase::Relaying | Phase::Lingering => {}
                Phase::InFlight => self.close(id, false),
                // A flush, an urgent close, a deny or the expiry: closed once, never a Disconnect.
                Phase::Fed | Phase::Handshaking | Phase::Reading => self.close(id, true),
            }
        }
    }

    fn failure(&self) -> Option<&'static str> {
        self.failure
    }
}

impl<N: StreamNet> I04Port for I04Server<N> {
    fn drain_backlog(&mut self) -> Vec<PolicyEvent> {
        self.accept(None)
    }
}
