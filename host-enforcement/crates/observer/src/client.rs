//! The observer's transport (HE-004C DESIGN-C section 4.4, D1-14 (a); MODEL_DEFINED R109): the portable [`Wire`]
//! trait with its own types, and the connection driver over it. gate-sys's `tcp::Connecting`, `tcp::Transfer` and
//! `channel::Ready` are Linux-only and reachable only from the socket module, so this module defines its own;
//! `linux_net.rs` maps them, and the tests drive a fake `Wire` with a scripted rustls server.
//!
//! - One exchange per connection: a non-blocking connect to the one apiserver address (10 s), the TLS 1.3 handshake of
//!   `tls::client_config` (10 s), then the request's bytes and the answer (30 s from the request to the complete
//!   answer, or to a watch's head); each exchange ends with `close_notify` and the close. A connection is only closed,
//!   never deleted from the poller explicitly (HE-003C D2-1).
//! - Interest follows rustls's `wants_read` and `wants_write` (and unsent request bytes), so a level-triggered poller
//!   never spins; each connection reads at most 64 KiB per wake, so many streams share the loop fairly.
//! - Three readers: a complete answer ([`http::AnswerReader`]), the `/metrics` exposition streamed into
//!   [`ExpositionReader`], and a watch stream whose decoded bytes are split into lines ([`watch::Lines`]); a watch
//!   stream that sends no byte for 300 s has ended.
//! - [`Client::poll`] reports each link's events; [`Client::run`] drives one link to its end (the snapshot's sequential
//!   requests). A `Wire::wait` failure other than an interrupted call is a [`PollError`] (status 95, D1-2).
//!
//! HE-004-I01a (DESIGN-I01A sections 4 and 5; MODEL_DEFINED's HE-004-I01a section) adds the I01 side of the transport,
//! portable like the rest: the peer types ([`PeerId`], [`PeerCreds`], [`ProcIdentity`], [`ExeLink`], [`PeerRecv`],
//! [`AcceptResult`]), the listener's setup steps ([`ListenerSetup`], [`WireSetup`], which `status.rs` maps on every
//! target), the [`PeerOps`] operations a wire offers beside [`Wire`] (no send: nothing leaves I01a), the
//! [`PeerService`] the waits serve, and the listener's fault backoff ([`ListenerBackoff`]). The client's every wait, in
//! `poll` and `pause`, is the one wire wait inside `Client::wait_serving` (G-I01-2): it watches the service's listener
//! and peer beside the links, on poller tokens of their own, shortens its timeout to the service's earliest deadline,
//! routes the links' readiness as before and hands each ready I01 descriptor to the service, one step each.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use gate_sys::inet::InetAddress;
use gate_sys::peer_wire::parse_control;
use rustls::{ClientConfig, ClientConnection, ProtocolVersion};

use crate::exposition::{Exposition, ExpositionError, ExpositionReader};
use crate::http::{self, Answer, AnswerReader, Bounds, Progress, Request, StreamReader};
use crate::tls::server_name;
use crate::watch::Lines;

/// The connect deadline (gate-tls's value, HE-003C).
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(10);
/// The TLS handshake deadline (gate-tls's value, HE-003C).
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
/// One exchange: the request written to the complete answer (or a watch's head).
pub const EXCHANGE_DEADLINE: Duration = Duration::from_secs(30);
/// A watch stream without a byte for this long has ended.
pub const IDLE_DEADLINE: Duration = Duration::from_secs(300);
/// The bytes one connection reads per wake.
pub const READ_BUDGET: usize = 64 << 10;
/// The errno reported for a connection the wire does not hold (EBADF).
pub const NO_CONNECTION: i32 = 9;

/// A connection of the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConnId(pub u64);

/// How a non-blocking connect started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Connecting {
    /// The connection is established.
    Connected,
    /// Wait for writability, then read `connect_result`.
    InProgress,
}

/// One receive or send, never waiting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transfer {
    /// The bytes received (at least 1) or sent.
    Data(usize),
    /// Nothing now.
    WouldBlock,
    /// The peer closed its side (a receive returned 0).
    Eof,
    /// Any other error, as its errno.
    Failed(i32),
}

/// The events a connection is watched for (error and hang-up are always reported).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interest {
    pub readable: bool,
    pub writable: bool,
}

/// The events one wake reported for a connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ready {
    pub readable: bool,
    pub writable: bool,
    pub error: bool,
    pub hangup: bool,
}

/// A wait failure other than an interrupted call (status 95), with its errno.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollError(pub i32);

// ------------------------------------------------------------------------------------------ I01 peers (HE-004-I01a)

/// An accepted I01 peer of the wire: a counter, never reused within the process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerId(pub u64);

/// What the kernel recorded about an accepted peer at its `connect`: SO_PEERCRED's process number, user and group, and
/// SO_PEERSEC's label exactly as delivered (its trailing NUL included). The pidfd (SO_PEERPIDFD) stays in the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerCreds {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
    pub label: Vec<u8>,
}

/// One read through the peer's kept process directory: `stat`'s start time (field 22, clock ticks since boot), the
/// whole `cgroup` file and `attr/current` (the process label, its trailing NUL included).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcIdentity {
    pub start_time: u64,
    pub cgroup: Vec<u8>,
    pub label: Vec<u8>,
}

/// The peer's `exe` link, read through its kept process directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExeLink(pub Vec<u8>);

/// One receive on a peer, never waiting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerRecv {
    /// One datagram of `length` bytes in the buffer, with the one SCM_CREDENTIALS it carried (`pid`, `uid`, `gid`) and
    /// the one SCM_SECURITY (`security`, exactly as delivered).
    Data { length: usize, pid: i32, uid: u32, gid: u32, security: Vec<u8> },
    /// A datagram longer than the buffer (MSG_TRUNC).
    Truncated,
    /// Control data outside the one-of-each rule: cut short (MSG_CTRUNC, a passed descriptor among its causes), a
    /// message missing, repeated, of another level or type, or malformed.
    Ancillary,
    /// Nothing queued.
    WouldBlock,
    /// The peer closed its side.
    Eof,
    /// Any other error, as its errno.
    Failed(i32),
}

impl PeerRecv {
    /// One received datagram as the wire reports it: `length` bytes (`truncated` when it was longer than the buffer) and
    /// the control bytes up to their returned length (`control_truncated` for MSG_CTRUNC), read by gate-sys's
    /// `parse_control`: exactly one SCM_CREDENTIALS of the kernel's length and exactly one SCM_SECURITY, nothing else.
    pub fn datagram(length: usize, truncated: bool, control: &[u8], control_truncated: bool) -> PeerRecv {
        if truncated {
            return PeerRecv::Truncated;
        }
        match parse_control(control, control_truncated) {
            Ok(delivered) => PeerRecv::Data {
                length,
                pid: delivered.credentials.pid,
                uid: delivered.credentials.uid,
                gid: delivered.credentials.gid,
                security: delivered.security,
            },
            Err(_) => PeerRecv::Ancillary,
        }
    }
}

/// One accept on the I01 listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptResult {
    /// A new peer.
    Peer(PeerId),
    /// None queued (EAGAIN), or the queued one died (ECONNABORTED).
    Nothing,
    /// Any other error, as its errno: a listener fault.
    Fault(i32),
}

/// The step of the I01 listener's setup that failed (statuses 31-34, `status::wire_setup`): its socket, address or
/// socket options (31), `bind` (32), `listen` (33), or its registration with the poller (34). gate-sys's own step type
/// stays inside the Linux listener file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerSetup {
    Socket,
    Address,
    Options,
    Bind,
    Listen,
    Register,
}

/// Why the Linux wire's constructor failed: the poller, with its errno (status 24), or the I01 listener (31-34).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireSetup {
    Poller(i32),
    Listener(ListenerSetup),
}

/// The I01 descriptors one wait watches for reading: the listener, and the open session's peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerWatch {
    pub listener: bool,
    pub peer: Option<PeerId>,
}

/// One wake, the links' connections and the I01 descriptors apart (their poller tokens are disjoint).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Woken {
    /// The connections' readiness.
    pub conns: Vec<(ConnId, Ready)>,
    /// The listener's readiness, when it was watched and reported.
    pub listener: Option<Ready>,
    /// The watched peer's readiness.
    pub peers: Vec<(PeerId, Ready)>,
    /// Adding the listener to the poller, or removing it, failed: a listener fault.
    pub listener_fault: bool,
    /// Peers whose watch failed: each one's session closes (never status 95).
    pub peer_faults: Vec<PeerId>,
}

/// The I01 operations a wire offers beside [`Wire`] (DESIGN-I01A section 5): `linux_net::LinuxWire` serves them through
/// its I01 listener, the tests through fakes. No supertrait, and no send operation: nothing leaves I01a.
pub trait PeerOps {
    /// One accept: a new peer, nothing queued, or a fault.
    fn accept_peer(&mut self) -> AcceptResult;
    /// SO_PEERCRED, SO_PEERSEC and SO_PEERPIDFD (the pidfd kept inside the wire), or the errno.
    fn peer_creds(&mut self, peer: PeerId) -> Result<PeerCreds, i32>;
    /// Opens and keeps the peer's process directory by SO_PEERCRED's number; reads nothing.
    fn peer_proc_open(&mut self, peer: PeerId) -> Result<(), i32>;
    /// `stat`'s start time, `cgroup` and `attr/current`, read through the kept directory.
    fn peer_proc_read(&mut self, peer: PeerId) -> Result<ProcIdentity, i32>;
    /// The `exe` link, read through the kept directory.
    fn peer_exe(&mut self, peer: PeerId) -> Result<ExeLink, i32>;
    /// Whether the pidfd's zero-timeout poll shows the process alive (an error counts as an exit).
    fn peer_alive(&mut self, peer: PeerId) -> bool;
    /// One receive into `buffer`, with the datagram's control messages.
    fn peer_recv(&mut self, peer: PeerId, buffer: &mut [u8]) -> PeerRecv;
    /// Closes the peer and everything kept with it.
    fn peer_close(&mut self, peer: PeerId);
}

/// What the I01 service wants of the next wait: the descriptors it watches and its earliest deadline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerPlan {
    pub watch: PeerWatch,
    pub deadline: Option<Instant>,
}

/// One ready I01 descriptor of a wake, as the service receives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerReady {
    Listener(Ready),
    /// The listener's add to, or removal from, the poller failed.
    ListenerFault,
    Peer(PeerId, Ready),
    /// The peer's add to the poller failed.
    PeerFault(PeerId),
}

/// A step's outcome: served, or the listener failing persistently, which ends the epoch (status 35).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerOutcome {
    Served,
    ListenerFailed,
}

/// The I01 service the client's waits serve (`i01_service::I01Service`; DESIGN-I01A section 5). It holds session state
/// only and is handed the peer operations at each call, so it has no tie to the wire.
pub trait PeerService {
    /// The descriptors the next wait watches and the earliest I01 deadline (the idle and outer bounds, the backoff's
    /// re-add).
    fn peer_plan(&self, now: Instant) -> PeerPlan;
    /// One ready I01 descriptor, bounded: one accept, or one request read and its checks, then a close. `wall` is the
    /// wire's wall second (`None` before the epoch), `now` its monotonic clock.
    fn serve_peer_step(&mut self, ops: &mut dyn PeerOps, wall: Option<u64>, now: Instant, ready: PeerReady) -> PeerOutcome;
    /// Once per wake, after the steps: the deadlines that have come (a session's bounds and the record's window, the
    /// backoff's end).
    fn serve_peer_deadlines(&mut self, ops: &mut dyn PeerOps, wall: Option<u64>, now: Instant);
}

/// The listener's backoff after a fault (DESIGN-I01A section 4).
pub const LISTENER_BACKOFF: Duration = Duration::from_secs(5);
/// The faults in a row that end the epoch (status 35): about 60 s with no accept between them.
pub const LISTENER_FAULT_LIMIT: u32 = 12;

/// The I01 listener's fault handling (DESIGN-I01A section 4): a fault (an accept error other than EAGAIN or
/// ECONNABORTED, EPOLLERR or EPOLLHUP on the listener, a failed add or removal) takes the listener out of the wait for
/// 5 s, and its re-add deadline joins the wait's earliest deadline; the twelfth fault in a row is fatal; an accept
/// clears the count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListenerBackoff {
    faults: u32,
    until: Option<Instant>,
}

impl ListenerBackoff {
    /// One fault at `now`: `true` when it is the twelfth in a row (fatal); otherwise the listener backs off for 5 s.
    pub fn fault(&mut self, now: Instant) -> bool {
        self.faults = self.faults.saturating_add(1);
        if self.faults >= LISTENER_FAULT_LIMIT {
            return true;
        }
        self.until = Some(after(now, LISTENER_BACKOFF));
        false
    }

    /// A successful accept: the count starts again.
    pub fn accepted(&mut self) {
        self.faults = 0;
    }

    /// Ends a backoff whose deadline has come.
    pub fn settle(&mut self, now: Instant) {
        if self.until.is_some_and(|at| at <= now) {
            self.until = None;
        }
    }

    /// The re-add deadline while backing off.
    pub fn until(&self) -> Option<Instant> {
        self.until
    }

    /// The faults in a row so far.
    pub fn faults(&self) -> u32 {
        self.faults
    }
}

/// The error a wait reports when the listener failed persistently: not an OS errno; [`Client::listener_failed`] tells
/// the epoch, which exits with status 35.
const LISTENER_FAILED_ERRNO: i32 = -35;

/// The portable transport the client drives (Linux: `linux_net::LinuxWire`; the tests: a fake).
pub trait Wire {
    /// A non-blocking TCP connection to `address`, or the errno of the failed `socket` or `connect`.
    fn connect(&mut self, address: &InetAddress) -> Result<(ConnId, Connecting), i32>;
    /// The pending error of a connecting socket once it is writable (`Ok` when established).
    fn connect_result(&mut self, conn: ConnId) -> Result<(), i32>;
    /// One receive, never waiting.
    fn recv(&mut self, conn: ConnId, buffer: &mut [u8]) -> Transfer;
    /// One send, never waiting.
    fn send(&mut self, conn: ConnId, bytes: &[u8]) -> Transfer;
    /// The write-side shutdown (not used by the observer's exchanges, which end with `close_notify` and the close).
    fn shutdown_write(&mut self, conn: ConnId) -> bool;
    /// Closes the connection (which leaves the poller with it).
    fn close(&mut self, conn: ConnId);
    /// Watches exactly `interests`, and the I01 descriptors `peers` names, and waits until one is ready or `until` (the
    /// monotonic clock) has come; the I01 readiness and watch failures come back apart from the connections' (HE-004-I01a).
    fn wait(&mut self, interests: &[(ConnId, Interest)], peers: PeerWatch, until: Instant) -> Result<Woken, PollError>;
    /// The monotonic clock.
    fn now(&self) -> Instant;
    /// The wall clock in whole seconds since the epoch, or `None` before the epoch.
    fn wall_seconds(&self) -> Option<u64>;
}

/// A link's handle (a counter, never reused within the client).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Handle(pub u64);

/// What a link reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A complete answer whose decoded body is at most this many bytes.
    Answer(usize),
    /// The `/metrics` exposition.
    Scrape,
    /// A watch stream.
    Watch,
}

/// Why a link ended without its result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The connect, the TCP connection or TLS failed, or the server closed before the answer was complete.
    Transport,
    /// The connect, handshake or exchange deadline passed.
    Deadline,
    /// A watch stream sent no byte for 300 s.
    Idle,
    /// The answer's framing was refused.
    Framing(http::Refusal),
    /// A 200 answer's media type is not the one the request needs (a framing refusal).
    Media,
}

/// The `/metrics` result: another status (the body is not read), or the 200 exposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scraped {
    Status(u16),
    Exposition(Result<Exposition, ExpositionError>),
}

/// A link's event. `Established` and `Line` keep the link open; every other event ends it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A complete answer.
    Answer(Answer),
    /// The `/metrics` result.
    Scraped(Scraped),
    /// A watch stream's 200 head with the JSON media type.
    Established,
    /// A watch stream's complete line (without its LF).
    Line(Vec<u8>),
    /// A watch stream's line that grew past 64 KiB (a change).
    LongLine,
    /// A watch open answered with another status.
    Refused(u16),
    /// A watch stream's final chunk.
    Final,
    /// The link failed.
    Failed(Failure),
}

impl Event {
    /// Whether the event ends its link.
    pub fn ends(&self) -> bool {
        !matches!(self, Event::Established | Event::Line(_))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Phase {
    Connecting,
    Handshaking,
    Exchanging,
}

/// What a link reads, with its reader's state.
enum Reading {
    Answer(AnswerReader),
    Scrape { reader: StreamReader, exposition: ExpositionReader, headed: bool },
    Watch { reader: StreamReader, lines: Lines, established: bool },
}

/// One connection's state.
struct Link {
    reading: Reading,
    conn: Option<ConnId>,
    phase: Phase,
    tls: Option<ClientConnection>,
    request: Vec<u8>,
    sent: usize,
    deadline: Instant,
}

/// `std::io::Read` over the wire, at most `budget` bytes in all.
struct WireRead<'a, W: Wire> {
    wire: &'a mut W,
    conn: ConnId,
    budget: &'a mut usize,
}

impl<W: Wire> io::Read for WireRead<'_, W> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let room = buffer.len().min(*self.budget);
        let Some(slice) = buffer.get_mut(..room).filter(|slice| !slice.is_empty()) else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        match self.wire.recv(self.conn, slice) {
            Transfer::Data(count) => {
                *self.budget = self.budget.saturating_sub(count);
                Ok(count.min(room))
            }
            Transfer::WouldBlock => Err(io::ErrorKind::WouldBlock.into()),
            Transfer::Eof => Ok(0),
            Transfer::Failed(_) => Err(io::ErrorKind::ConnectionReset.into()),
        }
    }
}

/// `std::io::Write` over the wire.
struct WireWrite<'a, W: Wire> {
    wire: &'a mut W,
    conn: ConnId,
}

impl<W: Wire> io::Write for WireWrite<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.wire.send(self.conn, bytes) {
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
fn flush<W: Wire>(wire: &mut W, conn: ConnId, tls: &mut ClientConnection) -> Result<(), ()> {
    while tls.wants_write() {
        match tls.write_tls(&mut WireWrite { wire: &mut *wire, conn }) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

/// Once the handshake is done, gives rustls the request bytes it has not taken and writes them out.
fn write_out<W: Wire>(wire: &mut W, link: &mut Link) -> Result<(), ()> {
    let (Some(conn), Some(tls)) = (link.conn, link.tls.as_mut()) else { return Err(()) };
    if !tls.is_handshaking() {
        while link.sent < link.request.len() {
            let rest = link.request.get(link.sent..).unwrap_or(&[]);
            match io::Write::write(&mut tls.writer(), rest) {
                Ok(0) => break,
                Ok(count) => link.sent = link.sent.saturating_add(count.min(rest.len())),
                Err(_) => return Err(()),
            }
            match tls.write_tls(&mut WireWrite { wire: &mut *wire, conn }) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return Err(()),
            }
        }
    }
    flush(wire, conn, tls)
}

fn after(now: Instant, by: Duration) -> Instant {
    now.checked_add(by).unwrap_or(now)
}

/// The decrypted bytes rustls holds, through `reading`; the events they produce. `closed` tells whether the server's
/// side has ended (close_notify or EOF): then an incomplete answer is a transport failure.
fn feed(reading: &mut Reading, tls: &mut ClientConnection, closed: bool, events: &mut Vec<Event>) -> bool {
    let mut chunk = [0u8; 4096];
    let mut ended = closed;
    loop {
        let count = match io::Read::read(&mut tls.reader(), &mut chunk) {
            Ok(0) => {
                ended = true;
                break;
            }
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => {
                ended = true;
                break;
            }
        };
        let bytes = chunk.get(..count).unwrap_or(&[]);
        if let Some(event) = consume(reading, bytes, events) {
            events.push(event);
            return true;
        }
    }
    // The answer read so far: complete answers end their link at once; a server close before then is a failure.
    if let Some(event) = settle(reading, ended) {
        events.push(event);
        return true;
    }
    false
}

/// Feeds one plaintext chunk to the reader; a terminal event when the link must end now.
fn consume(reading: &mut Reading, bytes: &[u8], events: &mut Vec<Event>) -> Option<Event> {
    match reading {
        Reading::Answer(reader) => match reader.push(bytes) {
            Progress::Refused(refusal) => Some(Event::Failed(Failure::Framing(refusal))),
            Progress::NeedMore | Progress::Complete => None,
        },
        Reading::Scrape { reader, exposition, headed } => {
            let mut out = Vec::new();
            let progress = reader.push(bytes, &mut out);
            if let Progress::Refused(refusal) = progress {
                return Some(Event::Failed(Failure::Framing(refusal)));
            }
            if !*headed {
                if let Some(status) = reader.status() {
                    *headed = true;
                    if status != 200 {
                        return Some(Event::Scraped(Scraped::Status(status)));
                    }
                    if !http::media_is_exposition(reader.content_type()) {
                        return Some(Event::Failed(Failure::Media));
                    }
                }
            }
            if let Err(error) = exposition.push(&out) {
                return Some(Event::Scraped(Scraped::Exposition(Err(error))));
            }
            None
        }
        Reading::Watch { reader, lines, established } => {
            let mut out = Vec::new();
            let progress = reader.push(bytes, &mut out);
            if let Progress::Refused(refusal) = progress {
                return Some(Event::Failed(Failure::Framing(refusal)));
            }
            if !*established {
                match reader.status() {
                    None => return None,
                    Some(200) if http::media_is(reader.content_type(), http::ACCEPT_JSON) => {
                        *established = true;
                        events.push(Event::Established);
                    }
                    Some(200) => return Some(Event::Failed(Failure::Media)),
                    Some(status) => return Some(Event::Refused(status)),
                }
            }
            let mut complete = Vec::new();
            let pushed = lines.push(&out, &mut complete);
            events.extend(complete.into_iter().map(Event::Line));
            if pushed.is_err() {
                return Some(Event::LongLine);
            }
            None
        }
    }
}

/// The link's end once the plaintext is read: a complete answer, or (when `ended`) a failure or a watch's end.
fn settle(reading: &mut Reading, ended: bool) -> Option<Event> {
    match reading {
        Reading::Answer(reader) => match reader.progress() {
            Progress::Complete => {
                let finished = std::mem::replace(reader, AnswerReader::new(0));
                Some(finished.answer().map_or(Event::Failed(Failure::Transport), Event::Answer))
            }
            Progress::Refused(refusal) => Some(Event::Failed(Failure::Framing(refusal))),
            Progress::NeedMore => ended.then_some(Event::Failed(Failure::Transport)),
        },
        Reading::Scrape { reader, exposition, .. } => match reader.progress() {
            Progress::Complete => {
                let finished = std::mem::take(exposition);
                Some(Event::Scraped(Scraped::Exposition(finished.finish())))
            }
            Progress::Refused(refusal) => Some(Event::Failed(Failure::Framing(refusal))),
            Progress::NeedMore => ended.then_some(Event::Failed(Failure::Transport)),
        },
        Reading::Watch { reader, .. } => match reader.progress() {
            Progress::Complete => Some(Event::Final),
            Progress::Refused(refusal) => Some(Event::Failed(Failure::Framing(refusal))),
            Progress::NeedMore => ended.then_some(Event::Failed(Failure::Transport)),
        },
    }
}

/// The apiserver client: the wire, the one TLS configuration, the address and authority, and its open links; since
/// HE-004-I01a also the I01 service its waits serve, when the epoch attaches one, and whether the listener failed.
pub struct Client<W: Wire> {
    wire: W,
    config: Arc<ClientConfig>,
    address: InetAddress,
    authority: String,
    links: BTreeMap<u64, Link>,
    next: u64,
    queued: Vec<(Handle, Event)>,
    service: Option<Box<dyn PeerService>>,
    listener_failed: bool,
}

impl<W: Wire + PeerOps> Client<W> {
    /// The client over `wire`, for the apiserver at `address` whose configured literal is `authority`.
    pub fn new(wire: W, config: Arc<ClientConfig>, address: InetAddress, authority: &str) -> Client<W> {
        Client { wire, config, address, authority: authority.to_string(), links: BTreeMap::new(), next: 1,
                 queued: Vec::new(), service: None, listener_failed: false }
    }

    /// Attaches the I01 service every later wait serves (HE-004-I01a; the epoch's, built from the server identity).
    pub fn serve_peers(&mut self, service: Box<dyn PeerService>) {
        self.service = Some(service);
    }

    /// Whether a wait ended because the I01 listener failed persistently (status 35, not 95).
    pub fn listener_failed(&self) -> bool {
        self.listener_failed
    }

    /// The observer's one wire wait (DESIGN-I01A section 5; G-I01-2): `poll` and `pause` wait only through it. With an
    /// I01 service attached, the wait also watches the service's listener and peer and ends no later than the
    /// service's earliest deadline; the connections' readiness goes back to the caller as before; each ready I01
    /// descriptor is one `serve_peer_step` (the wall second and the monotonic clock passed in, so the tests drive them),
    /// and the service's due deadlines are served once after them. A fatal listener outcome ends the wait with an error
    /// that [`Client::listener_failed`] names.
    fn wait_serving(&mut self, interests: &[(ConnId, Interest)], until: Instant)
                    -> Result<Vec<(ConnId, Ready)>, PollError> {
        let now = self.wire.now();
        let plan = self.service.as_deref().map(|service| service.peer_plan(now));
        let watch = plan.map(|plan| plan.watch).unwrap_or_default();
        let wake = plan.and_then(|plan| plan.deadline).map_or(until, |deadline| deadline.min(until));
        let woken = self.wire.wait(interests, watch, wake)?;
        let Some(service) = self.service.as_deref_mut() else { return Ok(woken.conns) };
        let (wall, now) = (self.wire.wall_seconds(), self.wire.now());
        let mut ready = Vec::new();
        if woken.listener_fault {
            ready.push(PeerReady::ListenerFault);
        } else if let Some(found) = woken.listener {
            ready.push(PeerReady::Listener(found));
        }
        ready.extend(woken.peers.iter().map(|(peer, found)| PeerReady::Peer(*peer, *found)));
        ready.extend(woken.peer_faults.iter().map(|peer| PeerReady::PeerFault(*peer)));
        for step in ready {
            if service.serve_peer_step(&mut self.wire, wall, now, step) == PeerOutcome::ListenerFailed {
                self.listener_failed = true;
                return Err(PollError(LISTENER_FAILED_ERRNO));
            }
        }
        service.serve_peer_deadlines(&mut self.wire, wall, now);
        Ok(woken.conns)
    }

    /// The monotonic clock.
    pub fn now(&self) -> Instant {
        self.wire.now()
    }

    /// The wall clock in whole seconds, or `None` before the epoch.
    pub fn wall_seconds(&self) -> Option<u64> {
        self.wire.wall_seconds()
    }

    /// The open links.
    pub fn open_links(&self) -> usize {
        self.links.len()
    }

    /// The wire (for the tests' inspection).
    pub fn wire(&self) -> &W {
        &self.wire
    }

    /// Starts a link for `request` reading `kind`; its handle. A connect that fails at once reports its failure at
    /// the next poll.
    pub fn open(&mut self, request: &Request, kind: Kind) -> Handle {
        let handle = Handle(self.next);
        self.next = self.next.saturating_add(1);
        let now = self.wire.now();
        let reading = match kind {
            Kind::Answer(body) => Reading::Answer(AnswerReader::new(body)),
            Kind::Scrape => Reading::Scrape { reader: StreamReader::new(Bounds::exposition()),
                                              exposition: ExpositionReader::new(), headed: false },
            Kind::Watch => Reading::Watch { reader: StreamReader::new(Bounds::stream()), lines: Lines::new(),
                                            established: false },
        };
        let mut link = Link { reading, conn: None, phase: Phase::Connecting, tls: None,
                              request: http::render(request, &self.authority), sent: 0,
                              deadline: after(now, CONNECT_DEADLINE) };
        match self.wire.connect(&self.address) {
            Err(_) => {
                self.queued.push((handle, Event::Failed(Failure::Transport)));
                return handle;
            }
            Ok((conn, Connecting::InProgress)) => link.conn = Some(conn),
            Ok((conn, Connecting::Connected)) => {
                link.conn = Some(conn);
                if self.handshake(&mut link, now).is_err() {
                    self.wire.close(conn);
                    self.queued.push((handle, Event::Failed(Failure::Transport)));
                    return handle;
                }
            }
        }
        self.links.insert(handle.0, link);
        handle
    }

    /// The TLS client for a connected link, its first flight sent.
    fn handshake(&mut self, link: &mut Link, now: Instant) -> Result<(), ()> {
        let tls = ClientConnection::new(self.config.clone(), server_name(&self.address)).map_err(|_| ())?;
        link.tls = Some(tls);
        link.phase = Phase::Handshaking;
        link.deadline = after(now, HANDSHAKE_DEADLINE);
        write_out(&mut self.wire, link)
    }

    /// Ends a link: `close_notify` first when the handshake is done (one best-effort flush), then the close.
    fn end(&mut self, mut link: Link) {
        if let (Some(conn), Some(tls)) = (link.conn, link.tls.as_mut()) {
            if !tls.is_handshaking() {
                tls.send_close_notify();
                let _best_effort = flush(&mut self.wire, conn, tls);
            }
        }
        if let Some(conn) = link.conn {
            self.wire.close(conn);
        }
    }

    /// Closes a link without an event (a watch the epoch no longer needs, an abandoned exchange).
    pub fn close(&mut self, handle: Handle) {
        self.queued.retain(|(queued, _)| *queued != handle);
        if let Some(link) = self.links.remove(&handle.0) {
            self.end(link);
        }
    }

    /// Closes every link.
    pub fn close_all(&mut self) {
        self.queued.clear();
        let handles: Vec<u64> = self.links.keys().copied().collect();
        for handle in handles {
            if let Some(link) = self.links.remove(&handle) {
                self.end(link);
            }
        }
    }

    fn interest(link: &Link) -> Option<Interest> {
        match link.phase {
            Phase::Connecting => Some(Interest { readable: false, writable: true }),
            Phase::Handshaking | Phase::Exchanging => link.tls.as_ref().map(|tls| Interest {
                readable: tls.wants_read(),
                writable: tls.wants_write() || (!tls.is_handshaking() && link.sent < link.request.len()),
            }),
        }
    }

    /// One wait (until `until` or the earliest link deadline) and the events of the links it woke or whose deadline
    /// passed. Readiness is handled before deadlines, so bytes that arrived are read before an idle stream ends.
    pub fn poll(&mut self, until: Instant) -> Result<Vec<(Handle, Event)>, PollError> {
        if !self.queued.is_empty() {
            return Ok(std::mem::take(&mut self.queued));
        }
        let mut interests = Vec::with_capacity(self.links.len());
        let mut wake = until;
        for link in self.links.values() {
            wake = wake.min(link.deadline);
            if let (Some(conn), Some(wanted)) = (link.conn, Client::<W>::interest(link)) {
                interests.push((conn, wanted));
            }
        }
        let ready = self.wait_serving(&interests, wake)?;
        let mut events = Vec::new();
        for (conn, readiness) in ready {
            let Some(handle) = self.links.iter().find(|(_, link)| link.conn == Some(conn)).map(|(handle, _)| *handle) else {
                continue; // a closed link's connection
            };
            let Some(mut link) = self.links.remove(&handle) else { continue };
            let mut produced = Vec::new();
            let ended = self.drive(&mut link, readiness, &mut produced);
            events.extend(produced.into_iter().map(|event| (Handle(handle), event)));
            if ended {
                self.end(link);
            } else {
                self.links.insert(handle, link);
            }
        }
        let now = self.wire.now();
        let due: Vec<u64> = self.links.iter().filter(|(_, link)| link.deadline <= now).map(|(handle, _)| *handle).collect();
        for handle in due {
            if let Some(link) = self.links.remove(&handle) {
                let established = matches!(link.reading, Reading::Watch { established: true, .. });
                let failure = if established { Failure::Idle } else { Failure::Deadline };
                events.push((Handle(handle), Event::Failed(failure)));
                self.end(link);
            }
        }
        Ok(events)
    }

    /// One readiness of a link: the connect result, or the TLS records and the plaintext they carry. Whether the link
    /// ended (its terminal event is the last one pushed).
    fn drive(&mut self, link: &mut Link, readiness: Ready, events: &mut Vec<Event>) -> bool {
        let Some(conn) = link.conn else {
            events.push(Event::Failed(Failure::Transport));
            return true;
        };
        if link.phase == Phase::Connecting {
            if readiness.error || readiness.hangup {
                events.push(Event::Failed(Failure::Transport));
                return true;
            }
            if !readiness.writable {
                return false;
            }
            let now = self.wire.now();
            if self.wire.connect_result(conn).is_err() || self.handshake(link, now).is_err() {
                events.push(Event::Failed(Failure::Transport));
                return true;
            }
            return false;
        }
        if write_out(&mut self.wire, link).is_err() {
            events.push(Event::Failed(Failure::Transport));
            return true;
        }
        let mut budget = READ_BUDGET;
        let mut received = false;
        loop {
            let Some(tls) = link.tls.as_mut() else {
                events.push(Event::Failed(Failure::Transport));
                return true;
            };
            let closed = match tls.read_tls(&mut WireRead { wire: &mut self.wire, conn, budget: &mut budget }) {
                Ok(0) => true,
                Ok(_) => {
                    received = true;
                    false
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    events.push(Event::Failed(Failure::Transport));
                    return true;
                }
            };
            if tls.process_new_packets().is_err() {
                // rustls queued its alert: flushed once, best effort.
                let _best_effort = flush(&mut self.wire, conn, tls);
                events.push(Event::Failed(Failure::Transport));
                return true;
            }
            if link.phase == Phase::Handshaking && !tls.is_handshaking() {
                // Defence in depth: the configuration offers TLS 1.3 only.
                if tls.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
                    events.push(Event::Failed(Failure::Transport));
                    return true;
                }
                link.phase = Phase::Exchanging;
                link.deadline = after(self.wire.now(), EXCHANGE_DEADLINE);
            }
            if feed(&mut link.reading, tls, closed, events) {
                return true;
            }
            if closed {
                events.push(Event::Failed(Failure::Transport));
                return true;
            }
            if write_out(&mut self.wire, link).is_err() {
                events.push(Event::Failed(Failure::Transport));
                return true;
            }
        }
        // A watch stream: its 200 head moves the deadline to the idle bound; every byte after it renews the bound.
        if let Reading::Watch { established: true, .. } = link.reading {
            if received || events.iter().any(|event| *event == Event::Established) {
                link.deadline = after(self.wire.now(), IDLE_DEADLINE);
            }
        }
        if readiness.error {
            events.push(Event::Failed(Failure::Transport));
            return true;
        }
        false
    }

    /// Drives one link for `request` to its end, or to `outer` (a phase's own deadline, such as OR07's 300 s or the
    /// snapshot's 120 s), whichever comes first: its terminal event. Used while no other link is open.
    pub fn run(&mut self, request: &Request, kind: Kind, outer: Instant) -> Result<Event, PollError> {
        let handle = self.open(request, kind);
        loop {
            if self.wire.now() >= outer {
                self.close(handle);
                return Ok(Event::Failed(Failure::Deadline));
            }
            for (owner, event) in self.poll(outer)? {
                if owner == handle && event.ends() {
                    self.close(handle);
                    return Ok(event);
                }
            }
        }
    }

    /// Waits until `until` with no link watched (the 1 s pauses between attempts); the I01 service is served meanwhile.
    pub fn pause(&mut self, until: Instant) -> Result<(), PollError> {
        while self.wire.now() < until {
            self.wait_serving(&[], until)?;
        }
        Ok(())
    }
}
