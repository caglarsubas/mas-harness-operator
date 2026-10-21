//! The observer's I01 listener (HE-004-I01a DESIGN-I01A sections 4 and 5; owner decisions Q-HE4I1-5 (a) and
//! Q-I01A-5 (a); MODEL_DEFINED's HE-004-I01a section), Linux only: [`I01Socket`] owns the listener at the I01 path and
//! the one accepted peer, with that peer's pidfd and kept process directory, all in private fields. Its `pub(crate)`
//! methods name only `client.rs`'s portable types, the seal's token and gate-sys's data type `Watched` (the socket-item
//! rule, Q-HE3D-R1 (a)). It is built only inside `LinuxWire::new(&Sealed)`, which keeps it in a private field and
//! serves the `PeerOps` operations through it (G-I01-6); this file is pinned whole (`OBSERVER_HOME_PINS`).
//!
//! - The listener is gate-sys's `listen_seqpacket_plain` at the one I01 path: no socket context (the observer's socket
//!   object is its own domain), SO_PASSCRED and SO_PASSSEC, a backlog of one. It binds after the seal and never removes
//!   the path: an existing one fails `bind` (status 32), and the unit's `ExecStartPre=` clears it as `init_t` (HS53).
//! - One peer at a time: while a peer is held, `accept` takes nothing, and a queued connection waits in the backlog.
//! - `creds` reads SO_PEERCRED, SO_PEERSEC and SO_PEERPIDFD and keeps the pidfd and the control buffer's size (one
//!   credentials and one security message of the accepted label's length); `proc_open` opens and keeps the peer's process
//!   directory by SO_PEERCRED's number and reads nothing; `proc_read` reads `stat`, `cgroup` and `attr/current` through
//!   it and `exe` its `exe` link; `alive` is the pidfd's zero-timeout poll; `recv` is one `recvmsg` into the frame
//!   buffer; `close` drops the peer with everything kept for it (the close also takes it off the poller).
//! - Nothing is sent: this file calls no send operation (G-I01-5).

use std::fmt;
use std::io;

use gate_sys::channel::{self, ListenStep};
use gate_sys::peer_wire::{control_capacity, FRAME_BUFFER_BYTES};

use crate::client::{AcceptResult, ExeLink, ListenerSetup, PeerCreds, PeerId, PeerRecv, ProcIdentity};
use crate::seal::Sealed;

/// The I01 path (HS53, DESIGN-I01A section 4): written here and nowhere else (G-I01-4).
const I01_PATH: &str = "/run/planeon/live-proxy/policy-observer.sock";

/// The `exe` link buffer: a link that fills it may be longer and is refused.
const EXE_BUFFER: usize = 4_096;

/// The errno for a peer the listener does not hold (EBADF) and for a buffer of another size (EINVAL).
const NO_PEER: i32 = 9;
const BAD_INPUT: i32 = 22;

/// The accepted peer and what is kept for it.
struct Held {
    id: u64,
    conn: channel::Conn,
    pid: i32,
    pidfd: Option<channel::PidFd>,
    proc_dir: Option<channel::ProcDir>,
    control: usize,
}

/// The I01 listener and its one accepted peer (see the module documentation). It derives no `Debug`; the manual impl
/// prints the type name only, as gate-sys's types do.
pub(crate) struct I01Socket {
    listener: channel::Listener,
    held: Option<Held>,
    next: u64,
}

impl fmt::Debug for I01Socket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("I01Socket")
    }
}

fn errno(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(-1)
}

/// gate-sys's listener step as the observer's setup step (statuses 31-33). The plain listener never reaches the
/// sockcreate steps; they read as the socket's.
fn setup_step(step: ListenStep) -> ListenerSetup {
    match step {
        ListenStep::Address => ListenerSetup::Address,
        ListenStep::Socket | ListenStep::SockCreate | ListenStep::SockCreateClear => ListenerSetup::Socket,
        ListenStep::PassCred | ListenStep::PassSec => ListenerSetup::Options,
        ListenStep::Bind => ListenerSetup::Bind,
        ListenStep::Listen => ListenerSetup::Listen,
    }
}

impl I01Socket {
    /// The I01 listener, after the seal, or the step that failed.
    pub(crate) fn open(_sealed: &Sealed) -> Result<I01Socket, ListenerSetup> {
        let listener = channel::listen_seqpacket_plain(I01_PATH).map_err(|error| setup_step(error.step))?;
        Ok(I01Socket { listener, held: None, next: 1 })
    }

    /// The listener as the poller watches it.
    pub(crate) fn watched_listener(&self) -> channel::Watched<'_> {
        channel::Watched::Listener(&self.listener)
    }

    /// The held peer's connection as the poller watches it, when `peer` is the one held.
    pub(crate) fn watched_peer(&self, peer: PeerId) -> Option<channel::Watched<'_>> {
        self.held_peer(peer).map(|held| channel::Watched::Conn(&held.conn))
    }

    fn held_peer(&self, peer: PeerId) -> Option<&Held> {
        self.held.as_ref().filter(|held| held.id == peer.0)
    }

    fn held_peer_mut(&mut self, peer: PeerId) -> Option<&mut Held> {
        self.held.as_mut().filter(|held| held.id == peer.0)
    }

    /// One accept: a new peer; nothing when none is queued, the queued one died or a peer is already held; or a fault.
    pub(crate) fn accept(&mut self) -> AcceptResult {
        if self.held.is_some() {
            return AcceptResult::Nothing;
        }
        match channel::accept(&self.listener) {
            Ok(Some(conn)) => {
                let id = self.next;
                self.next = self.next.saturating_add(1);
                self.held = Some(Held { id, conn, pid: 0, pidfd: None, proc_dir: None, control: 0 });
                AcceptResult::Peer(PeerId(id))
            }
            Ok(None) => AcceptResult::Nothing,
            Err(error) => AcceptResult::Fault(errno(&error)),
        }
    }

    /// SO_PEERCRED, SO_PEERSEC and SO_PEERPIDFD of the held peer; the pidfd, the number and the control buffer's size
    /// are kept.
    pub(crate) fn creds(&mut self, peer: PeerId) -> Result<PeerCreds, i32> {
        let held = self.held_peer_mut(peer).ok_or(NO_PEER)?;
        let channel::PeerCreds { pid, uid, gid, label, pidfd } = channel::peer(&held.conn).map_err(|error| errno(&error))?;
        held.control = control_capacity(label.len()).ok_or(BAD_INPUT)?;
        held.pid = pid;
        held.pidfd = Some(pidfd);
        Ok(PeerCreds { pid, uid, gid, label })
    }

    /// Opens and keeps the held peer's process directory by SO_PEERCRED's number; reads nothing.
    pub(crate) fn proc_open(&mut self, peer: PeerId) -> Result<(), i32> {
        let held = self.held_peer_mut(peer).ok_or(NO_PEER)?;
        let directory = channel::ProcDir::open(held.pid).map_err(|error| errno(&error))?;
        held.proc_dir = Some(directory);
        Ok(())
    }

    /// `stat`'s start time, `cgroup` and `attr/current`, through the kept directory.
    pub(crate) fn proc_read(&self, peer: PeerId) -> Result<ProcIdentity, i32> {
        let directory = self.held_peer(peer).and_then(|held| held.proc_dir.as_ref()).ok_or(NO_PEER)?;
        let identity = directory.read().map_err(|error| errno(&error))?;
        Ok(ProcIdentity { start_time: identity.start_time, cgroup: identity.cgroup, label: identity.label })
    }

    /// The `exe` link, through the kept directory.
    pub(crate) fn exe(&self, peer: PeerId) -> Result<ExeLink, i32> {
        let directory = self.held_peer(peer).and_then(|held| held.proc_dir.as_ref()).ok_or(NO_PEER)?;
        let mut buffer = vec![0u8; EXE_BUFFER];
        let count = directory.exe(&mut buffer).map_err(|error| errno(&error))?;
        buffer.truncate(count);
        Ok(ExeLink(buffer))
    }

    /// Whether the held peer's pidfd shows its process alive (a zero-timeout poll; an error counts as an exit).
    pub(crate) fn alive(&self, peer: PeerId) -> bool {
        self.held_peer(peer).and_then(|held| held.pidfd.as_ref()).is_some_and(|pidfd| !pidfd.exited())
    }

    /// One receive of the held peer into `buffer`, which must be the frame buffer's 16,385 bytes, with a control buffer
    /// of the size kept at `creds` (none before it, so any control data is cut short and refused).
    pub(crate) fn recv(&self, peer: PeerId, buffer: &mut [u8]) -> PeerRecv {
        let Some(held) = self.held_peer(peer) else { return PeerRecv::Failed(NO_PEER) };
        let Ok(frame) = <&mut [u8; FRAME_BUFFER_BYTES]>::try_from(buffer) else { return PeerRecv::Failed(BAD_INPUT) };
        let mut control = vec![0u8; held.control];
        match channel::recv(&held.conn, frame, &mut control) {
            channel::Recv::WouldBlock => PeerRecv::WouldBlock,
            channel::Recv::Eof => PeerRecv::Eof,
            channel::Recv::Error(code) => PeerRecv::Failed(code),
            channel::Recv::Datagram { length, truncated, control_length, control_truncated } => {
                PeerRecv::datagram(length, truncated, control.get(..control_length).unwrap_or_default(), control_truncated)
            }
        }
    }

    /// Closes the held peer and everything kept for it (the close also takes it off the poller).
    pub(crate) fn close(&mut self, peer: PeerId) {
        if self.held_peer(peer).is_some() {
            self.held = None;
        }
    }
}
