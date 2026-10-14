//! The channel substrate (HE-003A DESIGN §4-§6): a single-threaded event loop over one [`PolicyGate`] (which holds the
//! I05 `Gate`), generic over an [`Os`] (gate-sys's channel calls, the monotonic and realtime clocks) and over two ports
//! ([`I04Port`], [`UpstreamPort`]) through which HE-003B's I04 events and HE-003C's upstream events enter the same
//! loop. Safe, portable and host-tested with a fake `Os` and fake ports; the Linux `Os` is `linux_os` (its constructor
//! takes `&Sealed`).
//!
//! - State (§5.1). The substrate keeps no channel state of its own beyond the connections it holds: whether the I05
//!   channel is unopened, open or closed, the bound execution and its expiry, and whether a writer session exists are
//!   read from the model after every event, and a held connection the model no longer holds is closed.
//! - I05 connections (§5.2, §5.3). At most one is held, pending before its first frame or open. A connection accepted
//!   while the model's channel is UNOPENED and none is held is qualified (§4.2); qualified, it is held; not qualified,
//!   it is a deviation before the first frame: `PeerChanged` (the model answers nothing) then `ChannelLost`, so the
//!   generation's one channel is used (`["CHANNEL_ENDED", "BEFORE_FIRST_FRAME"]`, owner decision Q-HE3A-4 (a)). A
//!   second connection while one is pending is closed unfed; one while the channel is OPEN or CLOSED is fed
//!   `SecondChannel` and closed.
//! - Custody (§4.3), on every datagram before the model sees it: the control rules (`peer_wire`), the frame's
//!   credentials pid (and uid and gid) equal the qualified ones, its SCM_SECURITY equals the accept-time SO_PEERSEC
//!   bytes, the retained process directory still reads the same start time, the expected (I05) or recorded (I07)
//!   cgroup and the expected label, and the pidfd has not fired. A failure after the first frame is `PeerChanged`
//!   (fatal PEER_CHANGED, HELD); before it, as at accept; on the writer channel `WPeerChanged`.
//! - The wake (§5.6), in this order: the expiry, then the ports' due deadlines (the port with the earlier deadline
//!   first, all of its due events before the other's; see [`Port`]); the I05 connection (every datagram until it
//!   would block); the I07 connection; the pidfds (a connection still held after its datagrams were read, whose
//!   process exited, is a deviation); the ports' ready descriptors (I04, then upstream); the listeners (I05, then
//!   I07); then the ports register their descriptors. The wait's timeout is the earliest deadline, rounded up to
//!   milliseconds, and at most one second while an expiry is pending; EINTR is an empty wake.
//! - Expiry (§5.6, owner decision Q-HE3A-5 (a)). The deadline is the bound run's signed lifetime end from the
//!   [`Lifetimes`] input, by the realtime clock, read afresh at every check: at the start of every wake and right before
//!   any I05 frame or I04 request is fed, `Expire` is fed first when the clock has reached it. A bound run with no
//!   lifetime, or a realtime clock that cannot be read, is expired at once (fail closed).
//! - The 2-second bound (§5.7, owner decision Q-HE3A-2 (b)), measured on the monotonic clock from the receive that
//!   returned a request: an I05 answer, and an I07 answer to MAINTENANCE_STATUS, WRITE_BEGIN or WRITE_END, that would
//!   leave it is never sent; `AnswerLate` or `WAnswerLate` is fed instead (fatal ANSWER_LATE, HELD).
//! - A failed send (B1) closes the connection and feeds `ChannelLost` or `WChannelLost`; nothing is retried.
//! - An event the model refuses (`EventError`) is a substrate defect: the connection concerned is closed and the loop
//!   returns [`LoopExit`], as for a failed accept or poller call (§5.5); HE-003D exits the process.
//!
//! The executable of a peer is not read (§4.3): Q-HE2S-10 leaves the broker's artifact identity to HE-004's record,
//! and the writer's executable check (owner decisions Q-HE3A-1 (c), Q-HE3A-1b (a)) lands in a later R10 packet.

use std::collections::BTreeMap;
use std::time::Duration;
use std::time::Instant;

pub use gate_sys::peer_wire::ProcIdentity;
use gate_sys::peer_wire::{control_capacity, label_matches, parse_control, same_lines, FRAME_BUFFER_BYTES};
use i05_protocol::json;

use crate::gate::{ChannelState, Event, FrameInput, Output, OutputKind};
use crate::peers::{ExpectedPeer, ExpectedPeers};
use crate::policy_gate::{PolicyEvent, PolicyGate, PolicyOutput, PolicyOutputKind};

/// The 2-second answer bound (I05 Channel item 4; I07 v1 Channel 4).
pub const ANSWER_BOUND: Duration = Duration::from_secs(2);

/// The longest wait while an expiry is pending, so a forward step of the realtime clock is acted on within a second.
pub const EXPIRY_WAIT_CAP: Duration = Duration::from_secs(1);

/// The bits of a token a port defines (the top byte is the owner's).
pub const PORT_VALUE_BITS: u32 = 56;
const PORT_VALUE_MASK: u64 = (1 << PORT_VALUE_BITS) - 1;

/// The substrate's own tokens (owner byte 0).
pub const I05_LISTENER_TOKEN: u64 = 1;
pub const I07_LISTENER_TOKEN: u64 = 2;
pub const I05_CONN_TOKEN: u64 = 3;
pub const I07_CONN_TOKEN: u64 = 4;
pub const I05_PIDFD_TOKEN: u64 = 5;
pub const I07_PIDFD_TOKEN: u64 = 6;

/// One of the two listeners, and the channel it serves.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Listen {
    I05,
    I07,
}

/// A connection the `Os` holds; the substrate only names it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnId(pub u64);

/// A port's descriptor as the poller knows it: an identifier the port's `Os` gave it (HE-003B and HE-003C add the
/// Linux sources; the tests' fakes make their own).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceId(pub u64);

/// The events a watch asks for (error and hang-up are always reported).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Interest {
    pub readable: bool,
    pub writable: bool,
}

/// The events one wake reported for a token.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Readiness {
    pub readable: bool,
    pub writable: bool,
    pub error: bool,
    pub hangup: bool,
}

/// What the kernel recorded about a connection's peer at `connect` (SO_PEERCRED and SO_PEERSEC); the `Os` keeps the
/// pidfd (SO_PEERPIDFD) with the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
    /// SO_PEERSEC's bytes, exactly as delivered (the NUL included).
    pub label: Vec<u8>,
}

/// One receive on a held connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Received {
    WouldBlock,
    /// End of file (no data, no control data, no flags).
    Eof,
    /// Any other error (ECONNRESET among them), as its errno.
    Error(i32),
    /// One datagram (its first 16,385 bytes at most) and its control bytes, with MSG_TRUNC and MSG_CTRUNC.
    Datagram { bytes: Vec<u8>, truncated: bool, control: Vec<u8>, control_truncated: bool },
}

/// What the substrate asks the poller to watch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Watch {
    Listener(Listen),
    Conn(ConnId),
    PidFd(ConnId),
}

/// A failed `Os` call the loop cannot continue after (a failed `accept4` other than EAGAIN or ECONNABORTED).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OsFailure;

/// Who owns a port token: `token = (owner << 56) | port-defined 56-bit value`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Owner {
    I04,
    Upstream,
}

impl Owner {
    fn code(self) -> u64 {
        match self {
            Owner::I04 => 1,
            Owner::Upstream => 2,
        }
    }

    /// The full token for a port-defined value; `None` past 56 bits.
    pub fn token(self, value: u64) -> Option<u64> {
        (value <= PORT_VALUE_MASK).then_some((self.code() << PORT_VALUE_BITS) | value)
    }
}

/// The poller's port side: what a [`Registry`] reaches. The owner is passed so that an `Os` lets a port change only
/// the sources it added.
pub trait PortPoll {
    fn port_add(&mut self, owner: Owner, source: SourceId, token: u64, interest: Interest) -> bool;
    fn port_modify(&mut self, owner: Owner, source: SourceId, token: u64, interest: Interest) -> bool;
    fn port_delete(&mut self, owner: Owner, source: SourceId) -> bool;
}

/// The system calls of HE-003A DESIGN §3 as the substrate uses them, and the two clocks. The Linux implementation is
/// `linux_os::LinuxOs`; descriptors stay inside it.
pub trait Os: PortPoll {
    /// One accept on a listener: a connection, `None` when none is queued (or it died in the queue), or a failure.
    fn accept(&mut self, listener: Listen) -> Result<Option<ConnId>, OsFailure>;
    /// SO_PEERCRED, SO_PEERSEC and SO_PEERPIDFD of a connection (the pidfd kept with it); `None` on any failure.
    fn peer(&mut self, conn: ConnId) -> Option<PeerCredentials>;
    /// Opens and keeps the process directory of `pid` for the connection; false on failure.
    fn open_proc(&mut self, conn: ConnId, pid: i32) -> bool;
    /// The identity read through the connection's kept process directory; `None` on any failure.
    fn read_proc(&mut self, conn: ConnId) -> Option<ProcIdentity>;
    /// Whether the connection's pidfd reports an exit (an error counts as one).
    fn peer_exited(&mut self, conn: ConnId) -> bool;
    /// One receive with a control buffer of `control_capacity` bytes.
    fn recv(&mut self, conn: ConnId, control_capacity: usize) -> Received;
    /// One send of a whole datagram; false on any failure.
    fn send(&mut self, conn: ConnId, bytes: &[u8]) -> bool;
    /// Closes the connection and everything kept with it (closing removes them from the poller). Closing a connection
    /// already closed does nothing: the accept paths close a fresh connection again after an output's row may have
    /// closed it (HE-003A PR review round 1, R1-6), and no descriptor is ever closed twice.
    fn close(&mut self, conn: ConnId);
    /// Watches a listener, a connection or its pidfd for reading with `token`; false on failure.
    fn watch(&mut self, watch: Watch, token: u64) -> bool;
    /// One wait of at most `timeout_ms` (-1: no limit): the ready tokens, empty on EINTR; `None` on failure.
    fn wait(&mut self, timeout_ms: i32) -> Option<Vec<(u64, Readiness)>>;
    /// The monotonic clock.
    fn monotonic(&self) -> Instant;
    /// The realtime clock in milliseconds since the epoch; `None` when it cannot be read.
    fn realtime_ms(&self) -> Option<i64>;
}

/// Why the loop stopped (HE-003A DESIGN §5.5). HE-003D exits the process with a distinct status; the restart is
/// deny-first (`PolicyGate::open`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoopExit {
    /// The model refused an event (`EventError`): a substrate defect. The connection concerned was closed first.
    ModelPrecondition(&'static str),
    /// An output the loop never expects (a restart output inside the loop).
    UnexpectedOutput(&'static str),
    /// `accept4` failed with an error other than EAGAIN or ECONNABORTED.
    Accept(Listen),
    /// A poller call (`epoll_ctl`, `epoll_pwait`) failed, or a wake named a token nobody registered.
    Poll,
    /// A port asked for a token value past its 56 bits.
    PortToken(Owner),
}

/// A port's access to the poller during [`Port::register`]: its own tokens only.
pub struct Registry<'a> {
    poll: &'a mut dyn PortPoll,
    owner: Owner,
}

impl Registry<'_> {
    pub fn owner(&self) -> Owner {
        self.owner
    }

    /// Watches `source` with the port's token `value`.
    pub fn add(&mut self, source: SourceId, value: u64, interest: Interest) -> Result<(), LoopExit> {
        let token = self.owner.token(value).ok_or(LoopExit::PortToken(self.owner))?;
        if self.poll.port_add(self.owner, source, token, interest) { Ok(()) } else { Err(LoopExit::Poll) }
    }

    /// Changes the token or interest of a source the port added.
    pub fn modify(&mut self, source: SourceId, value: u64, interest: Interest) -> Result<(), LoopExit> {
        let token = self.owner.token(value).ok_or(LoopExit::PortToken(self.owner))?;
        if self.poll.port_modify(self.owner, source, token, interest) { Ok(()) } else { Err(LoopExit::Poll) }
    }

    /// Stops watching a source the port added.
    pub fn delete(&mut self, source: SourceId) -> Result<(), LoopExit> {
        if self.poll.port_delete(self.owner, source) { Ok(()) } else { Err(LoopExit::Poll) }
    }
}

/// A read-only view of the model for a port's `sync` (HE-003A DESIGN §6), so that no port serialises the model.
pub trait GateView {
    /// Whether the gate holds the I04 connection `conn` open.
    fn connection_open(&self, conn: &str) -> bool;
    /// The forwarded write awaiting its outcome, if any.
    fn pending_write(&self) -> Option<u16>;
}

impl GateView for PolicyGate {
    fn connection_open(&self, conn: &str) -> bool {
        PolicyGate::connection_open(self, conn)
    }

    fn pending_write(&self) -> Option<u16> {
        PolicyGate::pending_write(self)
    }
}

/// A source of events for the loop other than the two channels (HE-003A DESIGN §6). Events are fed one at a time in
/// the order returned; every output goes to `apply` of the I04 port and then of the upstream port, and `sync` runs
/// after every event.
///
/// Deadlines (HE-003A PR review round 1, R1-9): at a wake the loop orders the due events across the two ports by each
/// port's earliest deadline (`next_deadline`), and feeds all of one port's `due` events before the other port's; the
/// two ports' deadlines are not interleaved. That suits HE-003A's ports, whose deadlines concern different
/// connections; HE-003B and HE-003C confirm it for theirs.
pub trait Port {
    /// Adds, modifies or deletes the port's own descriptors (at the start and at the end of every wake).
    fn register(&mut self, registry: &mut Registry<'_>) -> Result<(), LoopExit>;
    /// The port's earliest deadline, on the monotonic clock.
    fn next_deadline(&self) -> Option<Instant>;
    /// Events for the deadlines that fell due by `now` (the bounds of Decision 12, I07's write bound, I04's bounds).
    /// It must clear or advance every deadline at or before `now`, so that `next_deadline` is then `None` or later
    /// than `now`: a deadline left in the past would give every wait a zero timeout, and the loop would spin.
    fn due(&mut self, now: Instant) -> Vec<PolicyEvent>;
    /// Events for a ready descriptor (`value` is the 56-bit value the port registered).
    fn ready(&mut self, value: u64, readiness: Readiness) -> Vec<PolicyEvent>;
    /// Acts on an output that concerns the port's connections (others are ignored).
    fn apply(&mut self, output: &PolicyOutput);
    /// Closes what the model holds closed.
    fn sync(&mut self, view: &dyn GateView);
}

/// The I04 port (HE-003B).
pub trait I04Port: Port {
    /// `accept4` on the I04 listener until EAGAIN, as `Backlog` events: called before every I05 frame, so a connection
    /// queued after the wake's readiness cannot escape an ARM's flush (Decision 5, C2).
    fn drain_backlog(&mut self) -> Vec<PolicyEvent>;
}

/// The upstream port (HE-003C).
pub trait UpstreamPort: Port {}

/// The signed lifetime of each run (owner decision Q-HE3A-5 (a)): run nonce to lifetime end in seconds since the
/// epoch. HE-003D builds it from the gate's own copy of the signed capacity inputs and refuses a configuration with a
/// run that has none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lifetimes {
    ends: BTreeMap<String, i64>,
}

impl Lifetimes {
    pub fn new(ends: BTreeMap<String, i64>) -> Lifetimes {
        Lifetimes { ends }
    }

    /// The lifetime end of a run, in seconds since the epoch.
    pub fn end(&self, run_nonce: &str) -> Option<i64> {
        self.ends.get(run_nonce).copied()
    }
}

/// The identity a connection was qualified with at accept (HE-003A DESIGN §4.2), kept read only; HE-003D defines how
/// the mutual qualification record relates to it (§4.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualifiedIdentity {
    pid: i32,
    uid: u32,
    gid: u32,
    socket_label: Vec<u8>,
    process_label: Vec<u8>,
    start_time: u64,
    cgroup: Vec<u8>,
}

impl QualifiedIdentity {
    pub fn pid(&self) -> i32 {
        self.pid
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// SO_PEERSEC's bytes at accept (with the NUL).
    pub fn socket_label(&self) -> &[u8] {
        &self.socket_label
    }

    /// `attr/current` at accept (with the NUL).
    pub fn process_label(&self) -> &[u8] {
        &self.process_label
    }

    /// `stat` field 22.
    pub fn start_time(&self) -> u64 {
        self.start_time
    }

    /// The `cgroup` file at accept.
    pub fn cgroup(&self) -> &[u8] {
        &self.cgroup
    }
}

/// A held connection: its qualified identity and the control buffer size its label fixes.
struct Held {
    conn: ConnId,
    identity: QualifiedIdentity,
    control_capacity: usize,
}

/// The connection an event is about: closed when the model refuses the event, and "the connection just fed" of the
/// output tables.
#[derive(Copy, Clone)]
enum Concern {
    Nothing,
    Held(Listen),
    Fresh(Listen, ConnId),
}

/// An event the loop feeds after acting on an output (a channel loss after a failed send, a late answer).
type FollowUp = Option<(PolicyEvent, Concern)>;

/// Rounds a wait up to whole milliseconds, at most `i32::MAX`.
fn ceil_ms(wait: Duration) -> i32 {
    i32::try_from(wait.as_nanos().div_ceil(1_000_000)).unwrap_or(i32::MAX)
}

/// Whether an I07 answer frame carries the 2-second bound: answers to MAINTENANCE_STATUS, WRITE_BEGIN and WRITE_END
/// do (I07 v1 Channel 4); a WRITE_OBJECT answer (a refusal here, or the deferred outcome) is bounded by the write bound
/// instead. A frame whose operation cannot be read is bounded.
fn writer_answer_is_bounded(frame: Option<&[u8]>) -> bool {
    let operation = frame
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .and_then(|text| json::parse(text).ok())
        .and_then(|value| value.get("operation").and_then(|operation| operation.as_str().map(str::to_string)));
    operation.as_deref() != Some("WRITE_OBJECT")
}

/// The channel substrate over one PolicyGate.
pub struct Substrate<O: Os, I: I04Port, U: UpstreamPort> {
    gate: PolicyGate,
    os: O,
    i04: I,
    upstream: U,
    expected: ExpectedPeers,
    lifetimes: Lifetimes,
    i05: Option<Held>,
    i07: Option<Held>,
}

impl<O: Os, I: I04Port, U: UpstreamPort> Substrate<O, I, U> {
    /// The substrate over `gate` (new, or as `PolicyGate::open` left it): it watches both listeners and lets both
    /// ports register. No event is fed here; the first wake checks the expiry first.
    pub fn new(gate: PolicyGate, os: O, i04: I, upstream: U, expected: ExpectedPeers, lifetimes: Lifetimes)
               -> Result<Substrate<O, I, U>, LoopExit> {
        let mut substrate = Substrate { gate, os, i04, upstream, expected, lifetimes, i05: None, i07: None };
        if !substrate.os.watch(Watch::Listener(Listen::I05), I05_LISTENER_TOKEN)
            || !substrate.os.watch(Watch::Listener(Listen::I07), I07_LISTENER_TOKEN)
        {
            return Err(LoopExit::Poll);
        }
        substrate.register_ports()?;
        Ok(substrate)
    }

    /// The model (read only).
    pub fn gate(&self) -> &PolicyGate {
        &self.gate
    }

    pub fn os(&self) -> &O {
        &self.os
    }

    pub fn i04(&self) -> &I {
        &self.i04
    }

    pub fn upstream(&self) -> &U {
        &self.upstream
    }

    /// The connection held on a channel, if any.
    pub fn held(&self, side: Listen) -> Option<ConnId> {
        self.slot(side).map(|held| held.conn)
    }

    /// The qualified identity of the connection held on a channel (read only; §4.4).
    pub fn identity(&self, side: Listen) -> Option<&QualifiedIdentity> {
        self.slot(side).map(|held| &held.identity)
    }

    /// Runs wakes until one fails.
    pub fn run(&mut self) -> LoopExit {
        loop {
            if let Err(exit) = self.turn() {
                return exit;
            }
        }
    }

    /// One wake (§5.6): wait, then the deadlines, the I05 and I07 connections, the pidfds, the ports' descriptors and
    /// the listeners, in this order, then the ports' registrations.
    pub fn turn(&mut self) -> Result<(), LoopExit> {
        let timeout = self.timeout_ms();
        let ready = self.os.wait(timeout).ok_or(LoopExit::Poll)?;
        let mut own = [false; 7];
        let mut i04_ready = Vec::new();
        let mut upstream_ready = Vec::new();
        for (token, readiness) in ready {
            match token >> PORT_VALUE_BITS {
                0 => match own.get_mut(usize::try_from(token).unwrap_or(0)) {
                    Some(flag) if token >= I05_LISTENER_TOKEN => *flag = true,
                    _ => return Err(LoopExit::Poll),
                },
                1 => i04_ready.push((token & PORT_VALUE_MASK, readiness)),
                2 => upstream_ready.push((token & PORT_VALUE_MASK, readiness)),
                _ => return Err(LoopExit::Poll),
            }
        }
        let flag = |token: u64| own.get(usize::try_from(token).unwrap_or(0)).copied().unwrap_or(false);
        // 1. Due deadlines first: the expiry, then the ports' deadlines.
        self.check_expiry()?;
        self.port_deadlines()?;
        // 2 and 3. The connections.
        if flag(I05_CONN_TOKEN) {
            self.read_conn(Listen::I05)?;
        }
        if flag(I07_CONN_TOKEN) {
            self.read_conn(Listen::I07)?;
        }
        // 4. The pidfds.
        if flag(I05_PIDFD_TOKEN) {
            self.pidfd_fired(Listen::I05)?;
        }
        if flag(I07_PIDFD_TOKEN) {
            self.pidfd_fired(Listen::I07)?;
        }
        // 5. The ports' descriptors.
        for (value, readiness) in i04_ready {
            let events = self.i04.ready(value, readiness);
            self.feed_port_events(events)?;
        }
        for (value, readiness) in upstream_ready {
            let events = self.upstream.ready(value, readiness);
            self.feed_port_events(events)?;
        }
        // 6. The listeners.
        if flag(I05_LISTENER_TOKEN) {
            self.accept_all(Listen::I05)?;
        }
        if flag(I07_LISTENER_TOKEN) {
            self.accept_all(Listen::I07)?;
        }
        // 7. The ports' registrations for the next wait.
        self.register_ports()
    }

    // ------------------------------------------------------------------------------------------ helpers

    fn slot(&self, side: Listen) -> Option<&Held> {
        match side {
            Listen::I05 => self.i05.as_ref(),
            Listen::I07 => self.i07.as_ref(),
        }
    }

    fn expected(&self, side: Listen) -> &ExpectedPeer {
        match side {
            Listen::I05 => &self.expected.i05,
            Listen::I07 => &self.expected.i07,
        }
    }

    /// Closes the connection held on a channel, if any.
    fn drop_held(&mut self, side: Listen) {
        let held = match side {
            Listen::I05 => self.i05.take(),
            Listen::I07 => self.i07.take(),
        };
        if let Some(held) = held {
            self.os.close(held.conn);
        }
    }

    fn close_concerned(&mut self, concern: Concern) {
        match concern {
            Concern::Nothing => {}
            Concern::Held(side) => self.drop_held(side),
            Concern::Fresh(_, conn) => self.os.close(conn),
        }
    }

    /// The connection just fed on `side`: a fresh one, or the held one.
    fn close_fed(&mut self, concern: Concern, side: Listen) {
        match concern {
            Concern::Fresh(fed, conn) if fed == side => self.os.close(conn),
            Concern::Held(fed) if fed == side => self.drop_held(side),
            _ => {}
        }
    }

    fn register_ports(&mut self) -> Result<(), LoopExit> {
        self.i04.register(&mut Registry { poll: &mut self.os, owner: Owner::I04 })?;
        self.upstream.register(&mut Registry { poll: &mut self.os, owner: Owner::Upstream })
    }

    /// The model no longer holds what the substrate holds: close it (§5.1).
    fn reconcile(&mut self) {
        if self.i05.is_some() && self.gate.channel_state() == ChannelState::Closed {
            self.drop_held(Listen::I05);
        }
        if self.i07.is_some() && !self.gate.session_held() {
            self.drop_held(Listen::I07);
        }
    }

    /// Feeds one event and acts on its output (§5.4): the ports' `apply`, the wire, the ports' `sync`, then any
    /// follow-up event. An `EventError` closes the connection concerned and stops the loop (§5.5).
    fn deliver(&mut self, event: PolicyEvent, concern: Concern, received_at: Option<Instant>)
               -> Result<PolicyOutput, LoopExit> {
        let output = match self.gate.handle(event) {
            Ok(output) => output,
            Err(error) => {
                self.close_concerned(concern);
                return Err(LoopExit::ModelPrecondition(error.0));
            }
        };
        self.i04.apply(&output);
        self.upstream.apply(&output);
        let follow_up = self.wire(&output, concern, received_at)?;
        self.i04.sync(&self.gate);
        self.upstream.sync(&self.gate);
        self.reconcile();
        if let Some((event, concern)) = follow_up {
            self.deliver(event, concern, None)?;
        }
        Ok(output)
    }

    /// The output tables of §5.4. Every variant is named, so a new one fails the build.
    fn wire(&mut self, output: &PolicyOutput, concern: Concern, received_at: Option<Instant>)
            -> Result<FollowUp, LoopExit> {
        match &output.kind {
            PolicyOutputKind::Base(base) => self.wire_i05(base, concern, received_at),
            PolicyOutputKind::Restart { .. } => Err(LoopExit::UnexpectedOutput("a restart output inside the loop")),
            // The accept path holds the qualified writer connection when it sees this answer.
            PolicyOutputKind::Session => Ok(None),
            PolicyOutputKind::RefusedSession => {
                self.close_fed(concern, Listen::I07);
                Ok(None)
            }
            PolicyOutputKind::Response(_) => {
                let bounded = writer_answer_is_bounded(output.response_frame.as_deref());
                Ok(self.answer(Listen::I07, output.response_frame.as_deref(), bounded, received_at))
            }
            // The upstream port takes the write from `apply`; its outcome returns as WUpstream.
            PolicyOutputKind::Forwarded(_) => Ok(None),
            PolicyOutputKind::Upstream { response: Some(_), .. } => {
                Ok(self.answer(Listen::I07, output.response_frame.as_deref(), false, None))
            }
            // HE-002B R1-1: an upstream output with no response (R13's fallback) closes the writer connection.
            PolicyOutputKind::Upstream { response: None, .. } | PolicyOutputKind::SessionEnd { .. } => {
                self.drop_held(Listen::I07);
                Ok(None)
            }
            PolicyOutputKind::LateUpstream | PolicyOutputKind::Empty => Ok(None),
        }
    }

    fn wire_i05(&mut self, output: &Output, concern: Concern, received_at: Option<Instant>) -> Result<FollowUp, LoopExit> {
        match &output.kind {
            OutputKind::Nothing => Ok(None),
            OutputKind::Response(_) => Ok(self.answer(Listen::I05, output.response_frame.as_deref(), true, received_at)),
            OutputKind::Fatal(_) | OutputKind::ChannelEnd(_) => {
                self.close_fed(concern, Listen::I05);
                self.drop_held(Listen::I05);
                Ok(None)
            }
            OutputKind::RefusedChannel(_) => {
                self.close_fed(concern, Listen::I05);
                Ok(None)
            }
            // Nothing on the I05 wire: the ports act on these through `apply` and `sync`.
            OutputKind::Denied(_)
            | OutputKind::Stamp(_)
            | OutputKind::Close(_)
            | OutputKind::Forward { .. }
            | OutputKind::Upstream { .. }
            | OutputKind::LateUpstream => Ok(None),
            OutputKind::RestartState(_) => Err(LoopExit::UnexpectedOutput("a restart state inside the loop")),
        }
    }

    /// Sends an answer on a channel's held connection (§5.7, B1): with the 2-second bound measured from the receive
    /// that returned its request, a late answer is never sent and the late event follows; a failed send closes the
    /// connection and the loss follows.
    fn answer(&mut self, side: Listen, frame: Option<&[u8]>, bounded: bool, received_at: Option<Instant>) -> FollowUp {
        let conn = self.slot(side).map(|held| held.conn)?;
        let (late, lost) = match side {
            Listen::I05 => (PolicyEvent::Base(Event::AnswerLate), PolicyEvent::Base(Event::ChannelLost)),
            Listen::I07 => (PolicyEvent::WAnswerLate, PolicyEvent::WChannelLost),
        };
        if bounded {
            let now = self.os.monotonic();
            let within = received_at.is_some_and(|at| now.saturating_duration_since(at) < ANSWER_BOUND);
            if !within {
                return Some((late, Concern::Held(side)));
            }
        }
        let sent = match frame {
            Some(bytes) => self.os.send(conn, bytes),
            None => false,
        };
        if sent {
            return None;
        }
        self.drop_held(side);
        Some((lost, Concern::Held(side)))
    }

    // ------------------------------------------------------------------------------------------ expiry and deadlines

    /// The time left to the bound run's lifetime end (zero once reached), or `None` without an unexpired bound run.
    fn expiry_remaining(&self) -> Option<Duration> {
        let run = self.gate.bound_run().filter(|run| !run.expired)?;
        let (Some(end), Some(now)) = (self.lifetimes.end(&run.run_nonce), self.os.realtime_ms()) else {
            return Some(Duration::ZERO);
        };
        let left = end.saturating_mul(1000).saturating_sub(now);
        Some(Duration::from_millis(u64::try_from(left).unwrap_or(0)))
    }

    /// Feeds `Expire` when the realtime clock has reached the bound run's lifetime end.
    fn check_expiry(&mut self) -> Result<(), LoopExit> {
        if self.expiry_remaining().is_some_and(|left| left.is_zero()) {
            self.deliver(PolicyEvent::Base(Event::Expire), Concern::Nothing, None)?;
        }
        Ok(())
    }

    /// The wait's timeout: the earliest port deadline and the expiry (at most one second away while it is pending),
    /// rounded up to milliseconds; -1 for none.
    fn timeout_ms(&self) -> i32 {
        let now = self.os.monotonic();
        let mut wait: Option<Duration> = None;
        let deadlines = [self.i04.next_deadline(), self.upstream.next_deadline()];
        for left in deadlines.into_iter().flatten().map(|deadline| deadline.saturating_duration_since(now)) {
            wait = Some(wait.map_or(left, |earliest| earliest.min(left)));
        }
        if let Some(left) = self.expiry_remaining() {
            let left = left.min(EXPIRY_WAIT_CAP);
            wait = Some(wait.map_or(left, |earliest| earliest.min(left)));
        }
        wait.map_or(-1, ceil_ms)
    }

    /// The ports' deadlines that fell due, the port with the earlier deadline first: all of its `due` events, then the
    /// other port's (the order the `Port` docs state, R1-9).
    fn port_deadlines(&mut self) -> Result<(), LoopExit> {
        let now = self.os.monotonic();
        let i04 = self.i04.next_deadline().filter(|deadline| *deadline <= now);
        let upstream = self.upstream.next_deadline().filter(|deadline| *deadline <= now);
        let order = match (i04, upstream) {
            (Some(first), Some(second)) if second < first => [Some(Owner::Upstream), Some(Owner::I04)],
            (Some(_), Some(_)) => [Some(Owner::I04), Some(Owner::Upstream)],
            (Some(_), None) => [Some(Owner::I04), None],
            (None, Some(_)) => [Some(Owner::Upstream), None],
            (None, None) => [None, None],
        };
        for owner in order.into_iter().flatten() {
            let events = match owner {
                Owner::I04 => self.i04.due(now),
                Owner::Upstream => self.upstream.due(now),
            };
            self.feed_port_events(events)?;
        }
        Ok(())
    }

    /// A port's events, one at a time in the order returned, with the expiry check before every request.
    fn feed_port_events(&mut self, events: Vec<PolicyEvent>) -> Result<(), LoopExit> {
        for event in events {
            if matches!(event, PolicyEvent::Base(Event::Request { .. })) {
                self.check_expiry()?;
            }
            self.deliver(event, Concern::Nothing, None)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------------------------------ peers

    /// §4.2: SO_PEERCRED, SO_PEERSEC and SO_PEERPIDFD, the process directory opened by the pid and read, the pidfd not
    /// fired after the open (so the directory is the recorded process's), then the expected label (process and
    /// socket), uid, and for a pinned gid and cgroup those too. The identity and the connection's control buffer size,
    /// or `None`.
    fn qualify(&mut self, conn: ConnId, side: Listen) -> Option<(QualifiedIdentity, usize)> {
        let peer = self.os.peer(conn)?;
        if peer.pid <= 0 || !self.os.open_proc(conn, peer.pid) {
            return None;
        }
        let process = self.os.read_proc(conn)?;
        if self.os.peer_exited(conn) {
            return None;
        }
        let expected = self.expected(side);
        let matches = label_matches(&process.label, &expected.label)
            && label_matches(&peer.label, &expected.label)
            && peer.uid == expected.uid
            && expected.gid.is_none_or(|gid| peer.gid == gid)
            && expected.cgroup.as_deref().is_none_or(|cgroup| same_lines(&process.cgroup, cgroup));
        if !matches {
            return None;
        }
        let capacity = control_capacity(peer.label.len())?;
        let identity = QualifiedIdentity {
            pid: peer.pid,
            uid: peer.uid,
            gid: peer.gid,
            socket_label: peer.label,
            process_label: process.label,
            start_time: process.start_time,
            cgroup: process.cgroup,
        };
        Some((identity, capacity))
    }

    /// §4.3, in order: the control rules, the credentials, the socket label, the process directory's start time,
    /// cgroup and label, and the pidfd.
    fn custody(&mut self, side: Listen, control: &[u8], control_truncated: bool) -> bool {
        let Some(held) = self.slot(side) else { return false };
        let conn = held.conn;
        let Ok(delivered) = parse_control(control, control_truncated) else { return false };
        let identity = &held.identity;
        if delivered.credentials.pid != identity.pid
            || delivered.credentials.uid != identity.uid
            || delivered.credentials.gid != identity.gid
            || delivered.security != identity.socket_label
        {
            return false;
        }
        let expected = self.expected(side);
        let cgroup = expected.cgroup.clone().unwrap_or_else(|| identity.cgroup.clone());
        let label = expected.label.clone();
        let start_time = identity.start_time;
        let Some(process) = self.os.read_proc(conn) else { return false };
        if process.start_time != start_time || !same_lines(&process.cgroup, &cgroup) || !label_matches(&process.label, &label) {
            return false;
        }
        !self.os.peer_exited(conn)
    }

    /// A deviation of a channel's held peer (§5.3): after the first frame `PeerChanged` (fatal, HELD); before it
    /// `PeerChanged` (nothing) then `ChannelLost` (the generation's channel used, BEFORE_FIRST_FRAME); on the writer
    /// channel `WPeerChanged`. The connection is closed whatever the model answered.
    fn deviation(&mut self, side: Listen) -> Result<(), LoopExit> {
        match side {
            Listen::I05 => match self.gate.channel_state() {
                ChannelState::Open => {
                    self.deliver(PolicyEvent::Base(Event::PeerChanged), Concern::Held(side), None)?;
                }
                ChannelState::Unopened => {
                    self.deliver(PolicyEvent::Base(Event::PeerChanged), Concern::Held(side), None)?;
                    self.deliver(PolicyEvent::Base(Event::ChannelLost), Concern::Held(side), None)?;
                }
                ChannelState::Closed => {}
            },
            Listen::I07 => {
                self.deliver(PolicyEvent::WPeerChanged, Concern::Held(side), None)?;
            }
        }
        self.drop_held(side);
        Ok(())
    }

    // ------------------------------------------------------------------------------------------ connections

    /// Every datagram of a channel's held connection until it would block (§5.2, §5.8).
    fn read_conn(&mut self, side: Listen) -> Result<(), LoopExit> {
        loop {
            let Some((conn, capacity)) = self.slot(side).map(|held| (held.conn, held.control_capacity)) else {
                return Ok(());
            };
            let received = self.os.recv(conn, capacity);
            let received_at = self.os.monotonic();
            let (mut bytes, control, control_truncated) = match received {
                Received::WouldBlock => return Ok(()),
                Received::Eof | Received::Error(_) => {
                    self.drop_held(side);
                    let lost = match side {
                        Listen::I05 => PolicyEvent::Base(Event::ChannelLost),
                        Listen::I07 => PolicyEvent::WChannelLost,
                    };
                    self.deliver(lost, Concern::Held(side), None)?;
                    return Ok(());
                }
                Received::Datagram { bytes, truncated: _, control, control_truncated } => {
                    (bytes, control, control_truncated)
                }
            };
            if !self.custody(side, &control, control_truncated) {
                return self.deviation(side);
            }
            // A truncated datagram is passed as its first 16,385 bytes, so the decoder refuses its size.
            bytes.truncate(FRAME_BUFFER_BYTES);
            match side {
                Listen::I05 => {
                    // The pre-frame steps: the expiry, then the I04 backlog.
                    self.check_expiry()?;
                    let backlog = self.i04.drain_backlog();
                    self.feed_port_events(backlog)?;
                    if self.i05.is_none() {
                        return Ok(());
                    }
                    let frame = PolicyEvent::Base(Event::Frame(FrameInput::Bytes(bytes)));
                    self.deliver(frame, Concern::Held(side), Some(received_at))?;
                }
                Listen::I07 => {
                    let frame = PolicyEvent::WFrame(FrameInput::Bytes(bytes));
                    self.deliver(frame, Concern::Held(side), Some(received_at))?;
                }
            }
        }
    }

    /// A channel's pidfd fired: its datagrams are read first; a connection still held after that whose process has
    /// exited (another holder, or frames sent before the exit) is a deviation.
    fn pidfd_fired(&mut self, side: Listen) -> Result<(), LoopExit> {
        if self.slot(side).is_none() {
            return Ok(());
        }
        self.read_conn(side)?;
        match self.slot(side).map(|held| held.conn) {
            Some(conn) if self.os.peer_exited(conn) => self.deviation(side),
            _ => Ok(()),
        }
    }

    /// Accepts until the listener has nothing queued.
    fn accept_all(&mut self, side: Listen) -> Result<(), LoopExit> {
        loop {
            let conn = match self.os.accept(side) {
                Ok(Some(conn)) => conn,
                Ok(None) => return Ok(()),
                Err(OsFailure) => return Err(LoopExit::Accept(side)),
            };
            match side {
                Listen::I05 => self.accept_i05(conn)?,
                Listen::I07 => self.accept_i07(conn)?,
            }
        }
    }

    /// Holds a qualified connection and watches it and its pidfd.
    fn hold(&mut self, side: Listen, conn: ConnId, identity: QualifiedIdentity, control_capacity: usize)
            -> Result<(), LoopExit> {
        let held = Held { conn, identity, control_capacity };
        let (conn_token, pidfd_token) = match side {
            Listen::I05 => {
                self.i05 = Some(held);
                (I05_CONN_TOKEN, I05_PIDFD_TOKEN)
            }
            Listen::I07 => {
                self.i07 = Some(held);
                (I07_CONN_TOKEN, I07_PIDFD_TOKEN)
            }
        };
        if !self.os.watch(Watch::Conn(conn), conn_token) || !self.os.watch(Watch::PidFd(conn), pidfd_token) {
            self.drop_held(side);
            return Err(LoopExit::Poll);
        }
        Ok(())
    }

    /// §5.2's table for one accepted I05 connection.
    fn accept_i05(&mut self, conn: ConnId) -> Result<(), LoopExit> {
        match (self.gate.channel_state(), self.i05.is_some()) {
            (ChannelState::Unopened, false) => match self.qualify(conn, Listen::I05) {
                Some((identity, capacity)) => self.hold(Listen::I05, conn, identity, capacity)?,
                None => {
                    let fresh = Concern::Fresh(Listen::I05, conn);
                    self.deliver(PolicyEvent::Base(Event::PeerChanged), fresh, None)?;
                    self.deliver(PolicyEvent::Base(Event::ChannelLost), fresh, None)?;
                    self.os.close(conn);
                }
            },
            // A second connection while the first is pending: closed without feeding the model (the model has no
            // answer before the first frame, R3).
            (ChannelState::Unopened, true) => self.os.close(conn),
            (ChannelState::Open | ChannelState::Closed, _) => {
                self.deliver(PolicyEvent::Base(Event::SecondChannel), Concern::Fresh(Listen::I05, conn), None)?;
                self.os.close(conn);
            }
        }
        Ok(())
    }

    /// §5.8 for one accepted I07 connection: refused while a session exists; otherwise qualified (closed unfed when
    /// not) and fed `WConnect` (its challenge is unused by the model), the session's connection when it answers
    /// `Session`.
    fn accept_i07(&mut self, conn: ConnId) -> Result<(), LoopExit> {
        let connect = PolicyEvent::WConnect { challenge: String::new() };
        if self.gate.session_held() {
            self.deliver(connect, Concern::Fresh(Listen::I07, conn), None)?;
            self.os.close(conn);
            return Ok(());
        }
        let Some((identity, capacity)) = self.qualify(conn, Listen::I07) else {
            self.os.close(conn);
            return Ok(());
        };
        let output = self.deliver(connect, Concern::Fresh(Listen::I07, conn), None)?;
        if output.kind == PolicyOutputKind::Session {
            self.hold(Listen::I07, conn, identity, capacity)?;
        } else {
            self.os.close(conn);
        }
        Ok(())
    }
}

/// The rows of the output tables no valid event sequence reaches (HE-002B R18 and R13 make an upstream output without
/// a response unreachable; the loop never feeds a restart), and the close of the connection concerned by an
/// `EventError`, driven on a constructed state.
#[cfg(test)]
mod tests {
    use i05_protocol::json;

    use super::*;
    use crate::types::{Classification, SessionEnd, State};

    const VECTORS: &str = include_str!("../../../contracts/i07-v3/vectors.json");
    const KINDS: &str = include_str!("../../../contracts/i07-v3/policy-kinds.json");

    /// An `Os` that records closes (each connection once) and sends and reports nothing else.
    struct Quiet {
        at: Instant,
        closed: Vec<u64>,
        sent: Vec<u64>,
    }

    impl PortPoll for Quiet {
        fn port_add(&mut self, _: Owner, _: SourceId, _: u64, _: Interest) -> bool {
            true
        }

        fn port_modify(&mut self, _: Owner, _: SourceId, _: u64, _: Interest) -> bool {
            true
        }

        fn port_delete(&mut self, _: Owner, _: SourceId) -> bool {
            true
        }
    }

    impl Os for Quiet {
        fn accept(&mut self, _: Listen) -> Result<Option<ConnId>, OsFailure> {
            Ok(None)
        }

        fn peer(&mut self, _: ConnId) -> Option<PeerCredentials> {
            None
        }

        fn open_proc(&mut self, _: ConnId, _: i32) -> bool {
            false
        }

        fn read_proc(&mut self, _: ConnId) -> Option<ProcIdentity> {
            None
        }

        fn peer_exited(&mut self, _: ConnId) -> bool {
            true
        }

        fn recv(&mut self, _: ConnId, _: usize) -> Received {
            Received::WouldBlock
        }

        fn send(&mut self, conn: ConnId, _: &[u8]) -> bool {
            self.sent.push(conn.0);
            true
        }

        fn close(&mut self, conn: ConnId) {
            // A second close of a connection does nothing (`Os::close`).
            if !self.closed.contains(&conn.0) {
                self.closed.push(conn.0);
            }
        }

        fn watch(&mut self, _: Watch, _: u64) -> bool {
            true
        }

        fn wait(&mut self, _: i32) -> Option<Vec<(u64, Readiness)>> {
            Some(Vec::new())
        }

        fn monotonic(&self) -> Instant {
            self.at
        }

        fn realtime_ms(&self) -> Option<i64> {
            Some(0)
        }
    }

    /// A port with nothing to do.
    struct Still;

    impl Port for Still {
        fn register(&mut self, _: &mut Registry<'_>) -> Result<(), LoopExit> {
            Ok(())
        }

        fn next_deadline(&self) -> Option<Instant> {
            None
        }

        fn due(&mut self, _: Instant) -> Vec<PolicyEvent> {
            Vec::new()
        }

        fn ready(&mut self, _: u64, _: Readiness) -> Vec<PolicyEvent> {
            Vec::new()
        }

        fn apply(&mut self, _: &PolicyOutput) {}

        fn sync(&mut self, _: &dyn GateView) {}
    }

    impl I04Port for Still {
        fn drain_backlog(&mut self) -> Vec<PolicyEvent> {
            Vec::new()
        }
    }

    impl UpstreamPort for Still {}

    fn substrate() -> Substrate<Quiet, Still, Still> {
        let vectors = json::parse(VECTORS).unwrap_or(json::Value::Null);
        let config = vectors.get("configs").and_then(|configs| configs.get("ACTIVE")).cloned().unwrap_or(json::Value::Null);
        let kinds = json::parse(KINDS).unwrap_or(json::Value::Null);
        let gate = match PolicyGate::new(&config, &kinds) {
            Ok(gate) => gate,
            Err(error) => panic!("the ACTIVE configuration builds a PolicyGate: {error:?}"),
        };
        let os = Quiet { at: Instant::now(), closed: Vec::new(), sent: Vec::new() };
        match Substrate::new(gate, os, Still, Still, ExpectedPeers::r10(), Lifetimes::default()) {
            Ok(substrate) => substrate,
            Err(exit) => panic!("the substrate starts: {exit:?}"),
        }
    }

    fn held(conn: u64) -> Held {
        let identity = QualifiedIdentity {
            pid: 1,
            uid: 0,
            gid: 0,
            socket_label: b"l\0".to_vec(),
            process_label: b"l\0".to_vec(),
            start_time: 1,
            cgroup: b"0::/\n".to_vec(),
        };
        Held { conn: ConnId(conn), identity, control_capacity: 64 }
    }

    fn output(kind: PolicyOutputKind) -> PolicyOutput {
        PolicyOutput { kind, drain: None, response_frame: None }
    }

    #[test]
    fn an_upstream_output_without_a_response_closes_the_writer() {
        let mut substrate = substrate();
        substrate.i07 = Some(held(7));
        let upstream = output(PolicyOutputKind::Upstream { classification: Classification::IoAmbiguous, response: None });
        assert!(matches!(substrate.wire(&upstream, Concern::Nothing, None), Ok(None)));
        assert!(substrate.i07.is_none());
        assert_eq!(substrate.os.closed, vec![7]);
        assert!(substrate.os.sent.is_empty());
    }

    #[test]
    fn a_session_end_closes_the_writer_and_late_or_empty_outputs_touch_nothing() {
        let mut substrate = substrate();
        substrate.i07 = Some(held(8));
        for quiet in [PolicyOutputKind::LateUpstream, PolicyOutputKind::Empty, PolicyOutputKind::Forwarded(1)] {
            assert!(matches!(substrate.wire(&output(quiet), Concern::Nothing, None), Ok(None)));
        }
        assert!(substrate.os.closed.is_empty());
        let end = output(PolicyOutputKind::SessionEnd {
            how: SessionEnd::Ended,
            maintenance: crate::types::Maintenance::NotBegun,
            fatal: None,
        });
        assert!(matches!(substrate.wire(&end, Concern::Nothing, None), Ok(None)));
        assert_eq!(substrate.os.closed, vec![8]);
    }

    #[test]
    fn restart_outputs_stop_the_loop() {
        let mut substrate = substrate();
        let base = Output { kind: OutputKind::RestartState(State::Held), drain: None, response_frame: None };
        let restart = output(PolicyOutputKind::Restart { output: base.clone(), maintenance: crate::types::Maintenance::Ended });
        assert!(matches!(substrate.wire(&restart, Concern::Nothing, None),
                         Err(LoopExit::UnexpectedOutput("a restart output inside the loop"))));
        assert!(matches!(substrate.wire(&output(PolicyOutputKind::Base(base)), Concern::Nothing, None),
                         Err(LoopExit::UnexpectedOutput("a restart state inside the loop"))));
    }

    #[test]
    fn an_event_error_closes_the_connection_concerned() {
        let mut substrate = substrate();
        substrate.i05 = Some(held(3));
        let refused = substrate.deliver(PolicyEvent::Base(Event::SecondChannel), Concern::Held(Listen::I05), None);
        assert_eq!(refused.map(|output| output.kind), Err(LoopExit::ModelPrecondition("second channel before the first")));
        assert!(substrate.i05.is_none());
        let refused = substrate.deliver(PolicyEvent::Base(Event::AnswerLate), Concern::Fresh(Listen::I05, ConnId(4)), None);
        assert_eq!(refused.map(|output| output.kind),
                   Err(LoopExit::ModelPrecondition("answer late without an open channel")));
        assert_eq!(substrate.os.closed, vec![3, 4]);
    }

    #[test]
    fn an_answer_without_a_receive_time_is_late() {
        let mut substrate = substrate();
        substrate.i05 = Some(held(5));
        let follow_up = substrate.answer(Listen::I05, Some(b"{}"), true, None);
        assert!(matches!(follow_up, Some((PolicyEvent::Base(Event::AnswerLate), _))));
        assert!(substrate.os.sent.is_empty(), "never sent when its timing is unknown");
        let at = substrate.os.at;
        assert!(substrate.answer(Listen::I05, Some(b"{}"), true, Some(at)).is_none());
        assert_eq!(substrate.os.sent, vec![5]);
    }

    #[test]
    fn writer_answers_carry_the_bound_except_write_object() {
        let frame = |operation: &str| format!("{{\"operation\":\"{operation}\",\"sequence\":2}}").into_bytes();
        for operation in ["MAINTENANCE_STATUS", "WRITE_BEGIN", "WRITE_END"] {
            assert!(writer_answer_is_bounded(Some(&frame(operation))), "{operation}");
        }
        assert!(!writer_answer_is_bounded(Some(&frame("WRITE_OBJECT"))));
        assert!(writer_answer_is_bounded(None) && writer_answer_is_bounded(Some(b"not json")));
        assert_eq!((ceil_ms(Duration::from_nanos(1)), ceil_ms(Duration::from_millis(3))), (1, 3));
        assert_eq!(ceil_ms(Duration::from_secs(u64::MAX)), i32::MAX);
    }
}
