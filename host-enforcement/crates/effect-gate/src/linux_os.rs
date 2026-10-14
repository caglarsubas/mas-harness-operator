//! The Linux [`Os`] of the channel substrate (HE-003A DESIGN §3, §5): gate-sys's channel calls behind the substrate's
//! trait. Its constructor takes `&Sealed`, so no socket exists before the process seal in the types as well as in
//! HE-003D's source check (design review round 1, A17). Every descriptor stays inside gate-sys's opaque types, held
//! here per connection and closed by drop; effect-gate names no descriptor.
//!
//! HE-003A's ports have no Linux sources (HE-003B and HE-003C add theirs), so the port side of the poller refuses
//! every request, which stops the loop (fail closed).

use std::collections::BTreeMap;
use std::io;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use gate_sys::channel::{Conn, ListenError, Listener, PidFd, Poller, ProcDir, Recv, Watched};
use gate_sys::peer_wire::FRAME_BUFFER_BYTES;

use crate::peers::ListenerPlan;
use crate::seal::Sealed;
use crate::substrate::{ConnId, Interest, Listen, Os, OsFailure, Owner, PeerCredentials, PortPoll, ProcIdentity,
                       Readiness, Received, SourceId, Watch};

/// Why the Linux `Os` could not be set up: the poller, or one listener (its step and error).
#[derive(Debug)]
pub enum SetupError {
    Poller(io::Error),
    Listener { side: Listen, error: ListenError },
}

/// One accepted connection with what the substrate keeps for it.
struct Slot {
    conn: Conn,
    pidfd: Option<PidFd>,
    proc_dir: Option<ProcDir>,
}

/// The Linux `Os`: the poller, the two listeners and the connections, by number.
pub struct LinuxOs {
    poller: Poller,
    i05: Listener,
    i07: Listener,
    slots: BTreeMap<u64, Slot>,
    next: u64,
}

/// Every watch of the substrate's own descriptors is for reading.
const READABLE: gate_sys::channel::Interest = gate_sys::channel::Interest { readable: true, writable: false };

impl LinuxOs {
    /// The poller and both listeners (each created inside its sockcreate context, then SO_PASSCRED, SO_PASSSEC, bind
    /// and listen), after the seal.
    pub fn new(_sealed: &Sealed, i05: &ListenerPlan, i07: &ListenerPlan) -> Result<LinuxOs, SetupError> {
        let poller = Poller::new().map_err(SetupError::Poller)?;
        let listen = |side: Listen, plan: &ListenerPlan| {
            gate_sys::channel::listen_seqpacket(&plan.path, &plan.context)
                .map_err(|error| SetupError::Listener { side, error })
        };
        let i05 = listen(Listen::I05, i05)?;
        let i07 = listen(Listen::I07, i07)?;
        Ok(LinuxOs { poller, i05, i07, slots: BTreeMap::new(), next: 1 })
    }
}

impl PortPoll for LinuxOs {
    fn port_add(&mut self, _owner: Owner, _source: SourceId, _token: u64, _interest: Interest) -> bool {
        false
    }

    fn port_modify(&mut self, _owner: Owner, _source: SourceId, _token: u64, _interest: Interest) -> bool {
        false
    }

    fn port_delete(&mut self, _owner: Owner, _source: SourceId) -> bool {
        false
    }
}

impl Os for LinuxOs {
    fn accept(&mut self, listener: Listen) -> Result<Option<ConnId>, OsFailure> {
        let listening = match listener {
            Listen::I05 => &self.i05,
            Listen::I07 => &self.i07,
        };
        match gate_sys::channel::accept(listening) {
            Ok(Some(conn)) => {
                let number = self.next;
                self.next = self.next.saturating_add(1);
                self.slots.insert(number, Slot { conn, pidfd: None, proc_dir: None });
                Ok(Some(ConnId(number)))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(OsFailure),
        }
    }

    fn peer(&mut self, conn: ConnId) -> Option<PeerCredentials> {
        let slot = self.slots.get_mut(&conn.0)?;
        let peer = gate_sys::channel::peer(&slot.conn).ok()?;
        slot.pidfd = Some(peer.pidfd);
        Some(PeerCredentials { pid: peer.pid, uid: peer.uid, gid: peer.gid, label: peer.label })
    }

    fn open_proc(&mut self, conn: ConnId, pid: i32) -> bool {
        let Some(slot) = self.slots.get_mut(&conn.0) else { return false };
        match ProcDir::open(pid) {
            Ok(dir) => {
                slot.proc_dir = Some(dir);
                true
            }
            Err(_) => false,
        }
    }

    fn read_proc(&mut self, conn: ConnId) -> Option<ProcIdentity> {
        self.slots.get(&conn.0)?.proc_dir.as_ref()?.read().ok()
    }

    fn peer_exited(&mut self, conn: ConnId) -> bool {
        // No connection or no pidfd counts as exited (fail closed).
        self.slots.get(&conn.0).and_then(|slot| slot.pidfd.as_ref()).is_none_or(PidFd::exited)
    }

    fn recv(&mut self, conn: ConnId, control_capacity: usize) -> Received {
        let Some(slot) = self.slots.get(&conn.0) else { return Received::Error(-1) };
        let mut buffer = Box::new([0u8; FRAME_BUFFER_BYTES]);
        let mut control = vec![0u8; control_capacity];
        match gate_sys::channel::recv(&slot.conn, &mut buffer, &mut control) {
            Recv::WouldBlock => Received::WouldBlock,
            Recv::Eof => Received::Eof,
            Recv::Error(errno) => Received::Error(errno),
            Recv::Datagram { length, truncated, control_length, control_truncated } => {
                control.truncate(control_length);
                Received::Datagram {
                    bytes: buffer.get(..length).map(<[u8]>::to_vec).unwrap_or_default(),
                    truncated,
                    control,
                    control_truncated,
                }
            }
        }
    }

    fn send(&mut self, conn: ConnId, bytes: &[u8]) -> bool {
        self.slots.get(&conn.0).is_some_and(|slot| gate_sys::channel::send(&slot.conn, bytes).is_ok())
    }

    fn close(&mut self, conn: ConnId) {
        // Dropping the slot closes the connection, its pidfd and its process directory; closing a descriptor no other
        // descriptor shares removes it from the poller.
        self.slots.remove(&conn.0);
    }

    fn watch(&mut self, watch: Watch, token: u64) -> bool {
        let watched = match watch {
            Watch::Listener(Listen::I05) => Watched::Listener(&self.i05),
            Watch::Listener(Listen::I07) => Watched::Listener(&self.i07),
            Watch::Conn(conn) => match self.slots.get(&conn.0) {
                Some(slot) => Watched::Conn(&slot.conn),
                None => return false,
            },
            Watch::PidFd(conn) => match self.slots.get(&conn.0).and_then(|slot| slot.pidfd.as_ref()) {
                Some(pidfd) => Watched::PidFd(pidfd),
                None => return false,
            },
        };
        self.poller.add(watched, token, READABLE).is_ok()
    }

    fn wait(&mut self, timeout_ms: i32) -> Option<Vec<(u64, Readiness)>> {
        let mut ready = Vec::new();
        self.poller.wait(timeout_ms, &mut ready).ok()?;
        Some(
            ready
                .into_iter()
                .map(|(token, events)| {
                    (token, Readiness {
                        readable: events.readable,
                        writable: events.writable,
                        error: events.error,
                        hangup: events.hangup,
                    })
                })
                .collect(),
        )
    }

    fn monotonic(&self) -> Instant {
        Instant::now()
    }

    fn realtime_ms(&self) -> Option<i64> {
        let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        i64::try_from(since.as_millis()).ok()
    }
}
