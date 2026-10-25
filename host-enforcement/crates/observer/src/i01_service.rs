//! The I01 service (HE-004-I01a DESIGN-I01A sections 5-8; owner decisions Q-HE4I1-11 (a), Q-HE4I1-12 (a),
//! Q-I01A-3 (a), Q-I01A-5 (a) and Q-I01A-8; MODEL_DEFINED's HE-004-I01a section): one session at a time on the I01
//! listener, served from the epoch's waits through the peer operations handed to it at each call. It sends nothing.
//!
//! - The plan: the listener is watched while no session is open and no backoff runs; the open session's peer is
//!   watched; the earliest deadline is the session's idle bound (2 s from the accept), its outer bound (900 s) or the
//!   backoff's re-add.
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
//!   equal SO_PEERSEC's bytes exactly; the process unchanged again; then `i01_request`'s checks and the binding gate,
//!   which in I01a refused every request (no binding existed before HE-008), so every session closed there.
//!   HE-004-I01B2 (DESIGN-I01B2 rev 3 section 6): the service holds the configuration's [`I01Binding`], handed to
//!   [`I01Service::new`] by `observe::run`, and the gate compares each request with it; a refused request closes at its
//!   step, as before, and a request that passes closes as [`Closed::NotAnswered`]: nothing is answered or sent before
//!   HE-004-I01B3.
//! - The window: the wall second passed in (`None`, a clock before the epoch, closes without a latch) must lie in
//!   `[validFrom, expiresAt - 3 s)` (the capture engine's margin). Before `validFrom` the session closes with no latch;
//!   from `expiresAt - 3 s` on the service latches closed until the process ends, whatever the clock says later.
//! - Every failure closes the session; none is a status.

use std::time::{Duration, Instant};

use gate_sys::peer_wire::{label_matches, same_lines, FRAME_BUFFER_BYTES};

use crate::capture::EXPIRY_MARGIN_MS;
use crate::client::{AcceptResult, ListenerBackoff, PeerId, PeerOps, PeerOutcome, PeerPlan, PeerReady, PeerRecv, PeerService,
                    PeerWatch, ProcIdentity};
use crate::enrolled::{ServerClass, ServerIdentity};
use crate::i01_request::{check_request, Chain, I01Binding, RequestRefusal};

/// A session's idle bound, from its accept to its first request.
pub const IDLE_BOUND: Duration = Duration::from_secs(2);
/// A session's outer bound.
pub const OUTER_BOUND: Duration = Duration::from_secs(900);

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
    /// HE-004-I01B2: a request that passed the checks and the binding gate; nothing is answered before HE-004-I01B3.
    NotAnswered,
    /// The idle or the outer bound.
    Bound,
    /// The peer's watch failed.
    Watch,
}

/// The open session: its peer, what the accept fixed, its bounds and its chain.
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
}

/// The I01 service: the server's identity, the configuration's binding, the expiry latch, the listener's backoff and
/// the one session.
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
}

fn after(now: Instant, by: Duration) -> Instant {
    now.checked_add(by).unwrap_or(now)
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

    /// Whether `wall` lies in the record's window; from `expiresAt - 3 s` on the latch holds the answer at no.
    fn inside_window(&mut self, wall: Option<u64>) -> bool {
        let Some(wall) = wall else { return false };
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
    fn admit(&mut self, ops: &mut dyn PeerOps, wall: Option<u64>, now: Instant, peer: PeerId) {
        self.accepted = self.accepted.saturating_add(1);
        if !self.inside_window(wall) {
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
        })
    }

    /// A readable peer: the window, then one request; the session stays open only when nothing was queued.
    fn read(&mut self, ops: &mut dyn PeerOps, wall: Option<u64>) {
        let inside = self.inside_window(wall);
        let Some(mut session) = self.session.take() else { return };
        let closed = if inside { self.request(ops, &mut session) } else { Some(Closed::Window) };
        match closed {
            None => self.session = Some(session),
            Some(why) => self.end(ops, session.peer, why),
        }
    }

    /// One request read and checked: `None` when nothing was queued, otherwise why the session closes.
    fn request(&mut self, ops: &mut dyn PeerOps, session: &mut Session) -> Option<Closed> {
        if !unchanged(ops, session) {
            return Some(Closed::Changed);
        }
        match ops.peer_recv(session.peer, &mut self.buffer) {
            PeerRecv::WouldBlock => None,
            PeerRecv::Data { length, pid, uid, gid, security } => {
                if (pid, uid, gid) != (session.pid, session.uid, session.gid) || security != session.socket_label {
                    return Some(Closed::Credentials);
                }
                if !unchanged(ops, session) {
                    return Some(Closed::Changed);
                }
                let bytes = self.buffer.get(..length).unwrap_or_default();
                // HE-004-I01B2: the configuration's binding gates the request. A refusal closes at its step; a request
                // that passes is not answered before HE-004-I01B3, so it closes too, and nothing is sent.
                match check_request(bytes, false, &mut session.chain, Some(&self.binding)) {
                    Ok(_) => Some(Closed::NotAnswered),
                    Err(refusal) => Some(Closed::Request(refusal)),
                }
            }
            PeerRecv::Truncated | PeerRecv::Ancillary | PeerRecv::Eof | PeerRecv::Failed(_) => Some(Closed::Receive),
        }
    }
}

impl PeerService for I01Service {
    fn peer_plan(&self, _now: Instant) -> PeerPlan {
        let session = self.session.as_ref();
        let bound = session.map(|session| session.idle.min(session.outer));
        let deadline = match (bound, self.backoff.until()) {
            (Some(bound), Some(until)) => Some(bound.min(until)),
            (bound, until) => bound.or(until),
        };
        let listener = session.is_none() && self.backoff.until().is_none();
        PeerPlan { watch: PeerWatch { listener, peer: session.map(|session| session.peer) }, deadline }
    }

    fn serve_peer_step(&mut self, ops: &mut dyn PeerOps, wall: Option<u64>, now: Instant, ready: PeerReady) -> PeerOutcome {
        match ready {
            PeerReady::ListenerFault => return self.fault(now),
            PeerReady::Listener(found) if found.error || found.hangup => return self.fault(now),
            PeerReady::Listener(found) => {
                if found.readable && self.session.is_none() && self.backoff.until().is_none() {
                    match ops.accept_peer() {
                        AcceptResult::Peer(peer) => {
                            self.backoff.accepted();
                            self.admit(ops, wall, now, peer);
                        }
                        AcceptResult::Nothing => {}
                        AcceptResult::Fault(_) => return self.fault(now),
                    }
                }
            }
            PeerReady::Peer(peer, _) => {
                if self.holds(peer) {
                    self.read(ops, wall);
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

    fn serve_peer_deadlines(&mut self, ops: &mut dyn PeerOps, wall: Option<u64>, now: Instant) {
        self.backoff.settle(now);
        let inside = self.inside_window(wall);
        let Some(session) = self.session.take() else { return };
        let closed = if !inside {
            Some(Closed::Window)
        } else if now >= session.idle || now >= session.outer {
            Some(Closed::Bound)
        } else {
            None
        };
        match closed {
            None => self.session = Some(session),
            Some(why) => self.end(ops, session.peer, why),
        }
    }
}
