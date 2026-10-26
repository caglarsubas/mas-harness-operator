//! The I01 service (HE-004-I01a DESIGN-I01A sections 5-8; owner decisions Q-HE4I1-11 (a), Q-HE4I1-12 (a),
//! Q-I01A-3 (a), Q-I01A-5 (a) and Q-I01A-8; MODEL_DEFINED's HE-004-I01a section): one session at a time on the I01
//! listener, served from the epoch's waits through the peer operations handed to it at each call. Since HE-004-I01B5 it
//! sends one thing: an answer `respond` built and checked, through its one `peer_send`.
//!
//! - The plan: the listener is watched while no session is open and no backoff runs; the open session's peer is
//!   watched; the earliest deadline is the session's idle bound (2 s from the accept or the last answer), its outer
//!   bound (900 s), a pending request's exchange deadline in the idle bound's place, the backoff's re-add, or `now` while
//!   an answer is ready.
//! - A listener step: EPOLLERR or EPOLLHUP, a failed watch or an accept error is a fault (`ListenerBackoff`: 5 s out of
//!   the wait, the twelfth fault in a row fatal, status 35); otherwise one accept, whose peer is admitted or closed.
//! - Admission, in order: the record's window, then custody in HS43's race-free order through the kept process
//!   directory: SO_PEERCRED's uid and gid equal the record's and SO_PEERSEC matches its label (gate-sys's
//!   `label_matches`, which strips the kernel's one trailing NUL); the process directory opened; the pidfd alive, so the
//!   directory is that process's; `stat`'s start time kept as the accept-time reference, `cgroup` equal to the SERVER
//!   line `0::/<cgroup_rel>` (`same_lines`) and `attr/current` matching the label; then, from the record's capture class,
//!   an OBSERVED server's `exe` equal to `interpreterPath` byte for byte, while a LABEL_BOUND server's is never read.
//! - A peer step reads one request: the window; the pidfd alive and the process unchanged (start time, cgroup and
//!   label); one receive, whose SCM_CREDENTIALS must give the accept's pid, uid and gid and whose SCM_SECURITY must
//!   equal SO_PEERSEC's bytes exactly; the process unchanged again; then `i01_request`'s checks and the binding gate
//!   against the configuration's [`I01Binding`] (HE-004-I01B2, handed to [`I01Service::new`] by `observe::run`). A
//!   refused request closes at its step. HE-004-I01B5 (DESIGN-I01B5 rev 5 section 4): a request that passes is held
//!   pending with its receipt; while one is pending any datagram read closes the session ([`Closed::Pipelined`]).
//! - The answer (HE-004-I01B5, sections 4.2 and 4.3): the epoch's views are held as pushed (the snapshot's
//!   [`SnapshotView`], the [`Availability`] and the [`CaptureGate`]). Each wake's deadlines run in order: the window; the
//!   exchange deadline (at or after the receipt plus [`I01_EXCHANGE_DEADLINE`] the session closes, not served) and the
//!   bounds; then, when the request is ready (before its exchange deadline and the outer bound, with an availability
//!   holding a round that passed at or after the receipt, a snapshot view of that phase and a capture set), one call of
//!   `respond`: the process unchanged; freshness and the views; one wall reading; the capture facts; the answer
//!   `i01_answer::answer` builds; those exact bytes parsed back and passed by the public `i01_answer::self_check` with the
//!   session's previous sent observation; then the one send. Every outcome other than a send closes the session; after
//!   a send it stays open, its idle bound renewed and its chain continued.
//! - The window: the wall second (the wall reading in milliseconds, divided) must lie in `[validFrom, expiresAt - 3 s)`
//!   (the capture engine's margin). Before `validFrom` the session closes with no latch; from `expiresAt - 3 s` on the
//!   service latches closed until the process ends, whatever the clock says later. No wall clock closes without a latch.
//! - Every failure closes the session; none is a status.

use std::time::{Duration, Instant};

use gate_sys::peer_wire::{label_matches, same_lines, FRAME_BUFFER_BYTES};
use i05_protocol::json::Value;
use i05_protocol::sha256;

use crate::capture::EXPIRY_MARGIN_MS;
use crate::client::{AcceptResult, Availability, CaptureGate, ListenerBackoff, Passed, PeerId, PeerOps, PeerOutcome, PeerPlan,
                    PeerReady, PeerRecv, PeerSent, PeerService, PeerWatch, ProcIdentity, Round, SnapshotView};
use crate::enrolled::{ServerClass, ServerIdentity};
use crate::i01_request::{check_request, Chain, I01Binding, I01Request, RequestRefusal};

/// A session's idle bound, from its accept (or its last answer) to its next request.
pub const IDLE_BOUND: Duration = Duration::from_secs(2);
/// A session's outer bound.
pub const OUTER_BOUND: Duration = Duration::from_secs(900);
/// R10-defined (DESIGN-I01B5 rev 5 section 4.2; I5E-7): no answer later than the request's receipt plus this, on the
/// monotonic clock: i01_gate.rs's EXCHANGE_DEADLINE_SECONDS (2 s, the monitor's Q-I01B-21 (a)), checked equal by
/// gate.py, and named apart from client.rs's 30 s `EXCHANGE_DEADLINE`.
pub const I01_EXCHANGE_DEADLINE: Duration = Duration::from_secs(2);

/// Why the service closed a session (the tests' reading; none is a status).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closed {
    /// The record's window: no wall clock, before `validFrom`, or from `expiresAt - 3 s` on (latched).
    Window,
    /// A custody check at the accept.
    Custody,
    /// The pidfd shows an exit, or the start time, cgroup or label differs from the accept's.
    Changed,
    /// A message's SCM_CREDENTIALS or SCM_SECURITY differs from the accept's.
    Credentials,
    /// A cut-short datagram, other control data, the peer's close or a receive error.
    Receive,
    /// The request checks or the binding gate.
    Request(RequestRefusal),
    /// HE-004-I01B5 (Q-11 (a)): not served, nothing sent: the exchange deadline passed, the round or a view was not
    /// current, the send failed, or the answer's bytes did not parse back.
    NotServed,
    /// HE-004-I01B5 (Q-11 (a)): `answer`'s or `self_check`'s refusal; nothing sent.
    Answer(&'static str),
    /// HE-004-I01B5 (I5D-1 (a)): a datagram read while a request was pending; nothing sent.
    Pipelined,
    /// The idle or the outer bound.
    Bound,
    /// The peer's watch failed.
    Watch,
}

/// The open session: its peer, what the accept fixed, its bounds and its chain; since HE-004-I01B5 its pending request
/// with its receipt, the last answer's `observedAt` second and sent observation, and the monotonic reading of the wake
/// that serves its deadlines.
struct Session {
    peer: PeerId,
    pid: i32,
    uid: u32,
    gid: u32,
    socket_label: Vec<u8>,
    process: ProcIdentity,
    idle: Instant,
    outer: Instant,
    chain: Chain,
    pending: Option<(I01Request, Instant)>,
    last_observed: Option<u64>,
    previous: Option<Value>,
    woke: Instant,
}

impl Session {
    /// The session's earliest bound (I5D-2): its outer bound, and its idle bound, which a pending request's receipt plus
    /// `I01_EXCHANGE_DEADLINE` replaces.
    fn bound(&self) -> Instant {
        let first = match &self.pending {
            Some((_, received)) => after(*received, I01_EXCHANGE_DEADLINE),
            None => self.idle,
        };
        first.min(self.outer)
    }

    /// The answer sent (DESIGN-I01B5 rev 5 section 4.3 step 7): its second the last `observedAt`, its observation the
    /// previous one for the next self-check, the chain advanced to the answered request with the digest of the bytes
    /// sent, the pending request cleared and the idle bound renewed from this wake.
    fn sent(&mut self, checked: &I01Request, bytes: &[u8], observation: Value, wall_ms: u64) {
        self.last_observed = Some(wall_ms / 1_000);
        self.previous = Some(observation);
        self.chain.answered(checked.sequence, &checked.challenge, &sha256::prefixed(bytes));
        self.pending = None;
        self.idle = after(self.woke, IDLE_BOUND);
    }
}

/// The I01 service: the server's identity, the configuration's binding, the expiry latch, the listener's backoff, the
/// one session and (HE-004-I01B5) the epoch's latest views.
pub struct I01Service {
    server: ServerIdentity,
    binding: I01Binding,
    cgroup: Vec<u8>,
    latched: bool,
    backoff: ListenerBackoff,
    session: Option<Session>,
    buffer: Vec<u8>,
    accepted: u64,
    last_closed: Option<Closed>,
    /// HE-004-I01B5 (DESIGN-I01B5 rev 5 section 4.1): the epoch's latest views, each replaced by its push.
    snapshot: Option<SnapshotView>,
    availability: Option<Availability>,
    capture: Option<CaptureGate>,
}

fn after(now: Instant, by: Duration) -> Instant {
    now.checked_add(by).unwrap_or(now)
}

/// A duration in whole milliseconds, saturating.
fn ms(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// The pidfd alive and the process's start time, cgroup and label as the accept read them.
fn unchanged(ops: &mut dyn PeerOps, session: &Session) -> bool {
    ops.peer_alive(session.peer) && ops.peer_proc_read(session.peer).is_ok_and(|read| read == session.process)
}

impl I01Service {
    /// The service for the enrolled server (`serve`'s identity, built by the epoch) and the configuration's binding
    /// (`serve`'s one `I01Binding::from_config`, HE-004-I01B2).
    pub fn new(server: ServerIdentity, binding: I01Binding) -> I01Service {
        let cgroup = format!("0::/{}\n", server.cgroup_rel).into_bytes();
        I01Service {
            server,
            binding,
            cgroup,
            latched: false,
            backoff: ListenerBackoff::default(),
            session: None,
            buffer: vec![0u8; FRAME_BUFFER_BYTES],
            accepted: 0,
            last_closed: None,
            snapshot: None,
            availability: None,
            capture: None,
        }
    }

    /// Whether a session is open.
    pub fn session_open(&self) -> bool {
        self.session.is_some()
    }

    /// Whether the record's window has latched closed.
    pub fn latched(&self) -> bool {
        self.latched
    }

    /// The peers accepted so far.
    pub fn accepted(&self) -> u64 {
        self.accepted
    }

    /// Why the last session closed.
    pub fn last_closed(&self) -> Option<Closed> {
        self.last_closed
    }

    /// The listener's faults in a row.
    pub fn faults(&self) -> u32 {
        self.backoff.faults()
    }

    /// Whether the wall second of `wall_ms` lies in the record's window; from `expiresAt - 3 s` on the latch holds the
    /// answer at no.
    fn inside_window(&mut self, wall_ms: Option<u64>) -> bool {
        let Some(wall) = wall_ms.map(|ms| ms / 1_000) else { return false };
        let cut = self.server.expires_at.saturating_sub(EXPIRY_MARGIN_MS / 1_000);
        if self.latched || wall >= cut {
            self.latched = true;
            return false;
        }
        wall >= self.server.valid_from
    }

    fn holds(&self, peer: PeerId) -> bool {
        self.session.as_ref().is_some_and(|session| session.peer == peer)
    }

    fn fault(&mut self, now: Instant) -> PeerOutcome {
        if self.backoff.fault(now) { PeerOutcome::ListenerFailed } else { PeerOutcome::Served }
    }

    fn end(&mut self, ops: &mut dyn PeerOps, peer: PeerId, why: Closed) {
        ops.peer_close(peer);
        self.last_closed = Some(why);
    }

    /// An accepted peer: the window, then custody; a session, or the peer closed.
    fn admit(&mut self, ops: &mut dyn PeerOps, wall_ms: Option<u64>, now: Instant, peer: PeerId) {
        self.accepted = self.accepted.saturating_add(1);
        if !self.inside_window(wall_ms) {
            return self.end(ops, peer, Closed::Window);
        }
        match self.custody(ops, peer, now) {
            Some(session) => self.session = Some(session),
            None => self.end(ops, peer, Closed::Custody),
        }
    }

    /// Custody at the accept, in its order (see the module documentation); the session it opens.
    fn custody(&self, ops: &mut dyn PeerOps, peer: PeerId, now: Instant) -> Option<Session> {
        let label = self.server.process_label.as_bytes();
        let creds = ops.peer_creds(peer).ok()?;
        if creds.pid <= 0 || creds.uid != self.server.uid || creds.gid != self.server.gid || !label_matches(&creds.label, label) {
            return None;
        }
        ops.peer_proc_open(peer).ok()?;
        if !ops.peer_alive(peer) {
            return None;
        }
        let process = ops.peer_proc_read(peer).ok()?;
        if !same_lines(&process.cgroup, &self.cgroup) || !label_matches(&process.label, label) {
            return None;
        }
        if self.server.class == ServerClass::Observed && ops.peer_exe(peer).ok()?.0 != self.server.interpreter.as_bytes() {
            return None;
        }
        Some(Session {
            peer,
            pid: creds.pid,
            uid: creds.uid,
            gid: creds.gid,
            socket_label: creds.label,
            process,
            idle: after(now, IDLE_BOUND),
            outer: after(now, OUTER_BOUND),
            chain: Chain::default(),
            pending: None,
            last_observed: None,
            previous: None,
            woke: now,
        })
    }

    /// A readable peer: the window, then one request; the session stays open while nothing was queued or a request
    /// passed and is pending.
    fn read(&mut self, ops: &mut dyn PeerOps, wall_ms: Option<u64>, now: Instant) {
        let inside = self.inside_window(wall_ms);
        let Some(mut session) = self.session.take() else { return };
        let closed = if inside { self.request(ops, &mut session, now) } else { Some(Closed::Window) };
        match closed {
            None => self.session = Some(session),
            Some(why) => self.end(ops, session.peer, why),
        }
    }

    /// One request read and checked: `None` when nothing was queued or the request passed and is now pending (its
    /// receipt `now`), otherwise why the session closes.
    fn request(&mut self, ops: &mut dyn PeerOps, session: &mut Session, now: Instant) -> Option<Closed> {
        if !unchanged(ops, session) {
            return Some(Closed::Changed);
        }
        match ops.peer_recv(session.peer, &mut self.buffer) {
            PeerRecv::WouldBlock => None,
            PeerRecv::Data { length, pid, uid, gid, security } => {
                // HE-004-I01B5 (I5D-1 (a)): one request at a time; a datagram while one is pending closes.
                if session.pending.is_some() {
                    return Some(Closed::Pipelined);
                }
                if (pid, uid, gid) != (session.pid, session.uid, session.gid) || security != session.socket_label {
                    return Some(Closed::Credentials);
                }
                if !unchanged(ops, session) {
                    return Some(Closed::Changed);
                }
                let bytes = self.buffer.get(..length).unwrap_or_default();
                // The configuration's binding gates the request (HE-004-I01B2); a request that passes waits for its
                // answer (HE-004-I01B5).
                match check_request(bytes, false, &mut session.chain, Some(&self.binding)) {
                    Ok(checked) => {
                        session.pending = Some((checked, now));
                        None
                    }
                    Err(refusal) => Some(Closed::Request(refusal)),
                }
            }
            PeerRecv::Truncated | PeerRecv::Ancillary | PeerRecv::Eof | PeerRecv::Failed(_) => Some(Closed::Receive),
        }
    }

    /// Whether the session's pending request can be answered at `now` (DESIGN-I01B5 rev 5 section 4.2; I5E-1): before
    /// its receipt plus `I01_EXCHANGE_DEADLINE` and before the outer bound, with an availability holding a round that
    /// passed at or after the receipt, a snapshot view of that availability's phase, and a capture set.
    fn ready(&self, session: &Session, now: Instant) -> bool {
        let Some((_, received)) = &session.pending else { return false };
        let passed = self.availability.as_ref().is_some_and(|availability| {
            matches!(availability.round, Some(Round::Passed(Passed { started, .. })) if started >= *received)
                && self.snapshot.as_ref().is_some_and(|view| view.phase == availability.phase)
        });
        now < after(*received, I01_EXCHANGE_DEADLINE) && now < session.outer && passed && self.capture.is_some()
    }

    /// The answer to the pending request (DESIGN-I01B5 rev 5 section 4.3; SR-1 amend; I5D-13 (ii), I5D-15), in order,
    /// each refusal closing: (1) the process unchanged; (2) freshness, then the views (the snapshot view derived and of
    /// the availability's phase, every stream established, the fresh mark within its bound); (3) one wall reading, `now`
    /// the wake's monotonic one; (4) the capture facts from the latest capture set; (5) `answer`'s bytes; (6) those
    /// exact bytes parsed back and passed by the public `self_check` with the previous sent observation, so VPO's
    /// observer-knowable observation rules, chain included, pass on every byte sent; (7) the one send. `None` after the
    /// send: the session stays open.
    fn respond(&self, ops: &mut dyn PeerOps, session: &mut Session, wall_ms: Option<u64>, now: Instant) -> Option<Closed> {
        if !unchanged(ops, session) {
            return Some(Closed::Changed);
        }
        let Some((checked, received)) = session.pending.take() else { return Some(Closed::NotServed) };
        if now >= after(received, I01_EXCHANGE_DEADLINE) || now >= session.outer {
            return Some(Closed::NotServed);
        }
        let (Some(view), Some(availability), Some(gate)) = (&self.snapshot, &self.availability, &self.capture) else {
            return Some(Closed::NotServed);
        };
        let Ok(derived) = &view.derived else { return Some(Closed::NotServed) };
        if availability.phase != view.phase || !availability.established || !availability.fresh {
            return Some(Closed::NotServed);
        }
        let wall_ms = match wall_ms { Some(ms) => ms, None => return Some(Closed::Window) };
        let facts = crate::i01_answer::CaptureFacts {
            completed: gate.scheduled.is_some(),
            expired: gate.expired,
            scheduled_after_now: gate.scheduled > Some(now),
            slots: gate.slots.clone(),
            mono_age_ms: gate.scheduled.filter(|at| *at <= now).map_or(0, |at| ms(now - at)),
            wall_age_ms: wall_ms as i64 - gate.set_started_ms as i64,
            record_digest: gate.record_digest.clone(),
        };
        let bytes = match crate::i01_answer::answer(derived, &checked, &facts, wall_ms, session.last_observed) {
            Ok(bytes) => bytes,
            Err(refusal) => return Some(Closed::Answer(refusal)),
        };
        let observation = match ::std::str::from_utf8(&bytes).ok().and_then(|text| ::i05_protocol::json::parse(text).ok()) {
            Some(observation) => match crate::i01_answer::self_check(&observation, &checked, derived.binding_member(),
                                                                     wall_ms / 1000, session.previous.as_ref()) {
                Ok(()) => observation,
                Err(refusal) => return Some(Closed::Answer(refusal)),
            },
            None => return Some(Closed::NotServed),
        };
        match ops.peer_send(session.peer, &bytes) {
            PeerSent::Sent => session.sent(&checked, &bytes, observation, wall_ms),
            PeerSent::Failed(_) => return Some(Closed::NotServed),
        }
        None
    }
}

impl PeerService for I01Service {
    fn peer_plan(&self, now: Instant) -> PeerPlan {
        let session = self.session.as_ref();
        let bound = session.map(|session| if self.ready(session, now) { now } else { session.bound() });
        let deadline = match (bound, self.backoff.until()) {
            (Some(bound), Some(until)) => Some(bound.min(until)),
            (bound, until) => bound.or(until),
        };
        let listener = session.is_none() && self.backoff.until().is_none();
        PeerPlan { watch: PeerWatch { listener, peer: session.map(|session| session.peer) }, deadline }
    }

    fn serve_peer_step(&mut self, ops: &mut dyn PeerOps, wall_ms: Option<u64>, now: Instant, ready: PeerReady) -> PeerOutcome {
        match ready {
            PeerReady::ListenerFault => return self.fault(now),
            PeerReady::Listener(found) if found.error || found.hangup => return self.fault(now),
            PeerReady::Listener(found) => {
                if found.readable && self.session.is_none() && self.backoff.until().is_none() {
                    match ops.accept_peer() {
                        AcceptResult::Peer(peer) => {
                            self.backoff.accepted();
                            self.admit(ops, wall_ms, now, peer);
                        }
                        AcceptResult::Nothing => {}
                        AcceptResult::Fault(_) => return self.fault(now),
                    }
                }
            }
            PeerReady::Peer(peer, _) => {
                if self.holds(peer) {
                    self.read(ops, wall_ms, now);
                }
            }
            PeerReady::PeerFault(peer) => {
                if self.holds(peer) {
                    self.session = None;
                    self.end(ops, peer, Closed::Watch);
                }
            }
        }
        PeerOutcome::Served
    }

    /// The order (DESIGN-I01B5 rev 5 section 4.2; I5E-1, B3-4, B3-10): the backoff; the window; then the exchange
    /// deadline (at or after the receipt plus `I01_EXCHANGE_DEADLINE`, not served) and the bounds; then, when ready, the
    /// one call of `respond`, every outcome of which but a send closes the session.
    fn serve_peer_deadlines(&mut self, ops: &mut dyn PeerOps, wall_ms: Option<u64>, now: Instant) {
        self.backoff.settle(now);
        let inside = self.inside_window(wall_ms);
        let Some(mut session) = self.session.take() else { return };
        session.woke = now;
        let closed = if !inside {
            Some(Closed::Window)
        } else if session.pending.as_ref().is_some_and(|(_, received)| now >= after(*received, I01_EXCHANGE_DEADLINE)) {
            Some(Closed::NotServed)
        } else if now >= session.outer || (session.pending.is_none() && now >= session.idle) {
            Some(Closed::Bound)
        } else {
            None
        };
        if let Some(why) = closed {
            return self.end(ops, session.peer, why);
        }
        let closed = if self.ready(&session, now) { self.respond(ops, &mut session, wall_ms, now) } else { None };
        match closed {
            None => self.session = Some(session),
            Some(why) => self.end(ops, session.peer, why),
        }
    }

    fn peer_snapshot_view(&mut self, view: SnapshotView) {
        self.snapshot = Some(view);
    }

    fn peer_availability(&mut self, availability: Availability) {
        self.availability = Some(availability);
    }

    fn peer_capture_view(&mut self, gate: CaptureGate) {
        self.capture = Some(gate);
    }

    fn peer_pending(&self) -> Option<Instant> {
        self.session.as_ref().and_then(|session| session.pending.as_ref().map(|(_, received)| *received))
    }
}
