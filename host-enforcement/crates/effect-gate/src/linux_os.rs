//! The Linux [`Os`] of the channel substrate (HE-003A DESIGN §3, §5): gate-sys's channel calls behind the substrate's
//! trait. Its constructor takes `&Sealed`, so no socket exists before the process seal in the types as well as in
//! HE-003D's source check (design review round 1, A17). Every descriptor stays inside gate-sys's opaque types, held
//! here per connection and closed by drop; effect-gate names no descriptor.
//!
//! HE-003A's ports have no Linux sources, so `LinuxOs::new` refuses every port request, which stops the loop (fail
//! closed). HE-003B (DESIGN §4.1) adds `LinuxOs::with_net`: the port side of the poller looks the source up in the
//! shared stream table (`linux_net`), refuses one another owner holds, and watches its `TcpListener` or `TcpConn`.
//!
//! HE-003A2 (DESIGN §4, owner decision Q-A2-6 (a)): both constructors take the enrolled writer executable (the signed
//! configuration's `enrolledWriter.executable`) as a required argument, held privately, so no production `Os` exists
//! without it. `writer_exe_ok` reads the peer's `exe` link through the connection's kept process directory
//! (`ProcDir::exe`, gate-sys's `readlinkat` on that directory's descriptor) into a buffer one byte longer than the
//! enrolled path and compares it exactly (`peers::writer_exe_buffer_len`, `peers::writer_exe_matches`); a connection
//! without a kept directory, a refused read and any other bytes are false.
//!
//! HE-003A3 (DESIGN section 5, owner decisions Q-A3-5, Q-A3-6, Q-A3-9, Q-A3-14 and Q-A3-15 (a)) adds the observation's
//! Linux calls. [`KernelRoots::open_after_seal`] takes `&Sealed` and opens the two root handles, the cgroup2 mount's
//! and the proc filesystem's, each a gate-sys `KernelRoot` (`O_PATH`); `serve` calls it once, right after the socket
//! setup and before the stores, and exits with `OBSERVER_ROOTS` when it fails. [`LinuxKernelReads`] holds exactly
//! those two roots and implements the observation's four kernel calls: the probe-worker leaf's member file and a
//! process's `stat` file, each opened afresh relative to its root (a gate-sys `FixedPath`) and read with the bounded
//! plain-`read` helper; `pidfd_open` and the zero-timeout poll through gate-sys's `PidFd`. It caches nothing (this file
//! holds no static or thread-local state) and maps every failure to its errno or marker; the steps and the mapping to
//! causes are the portable driver's. Every descriptor is an owned handle, closed on every path. Its associated
//! `Pidfd` is gate-sys's `PidFd` (the one type alias `tools/gate.py` exempts here, D3-1): it creates no socket, and a
//! `LinuxKernelReads` exists only after `open_after_seal(&Sealed)`.

use std::collections::BTreeMap;
use std::io;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use gate_sys::channel::{Conn, ListenError, Listener, PidFd, Poller, ProcDir, Recv, Watched};
use gate_sys::openat::{read_bounded, FixedPath, KernelRoot};
use gate_sys::peer_wire::FRAME_BUFFER_BYTES;

use crate::linux_net::SharedNet;
use crate::observation::{KernelFail, KernelReads, PidState, LEAF_PROCS_LIMIT, STAT_LIMIT};
use crate::peers::{writer_exe_buffer_len, writer_exe_matches, ListenerPlan};
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
    /// The stream table the ports' sources live in (`with_net`); `None` refuses every port request.
    net: Option<SharedNet>,
    /// The enrolled writer executable's path, compared exactly with an I07 peer's `exe` link (HE-003A2).
    writer_executable: Vec<u8>,
}

/// Every watch of the substrate's own descriptors is for reading.
const READABLE: gate_sys::channel::Interest = gate_sys::channel::Interest { readable: true, writable: false };

impl LinuxOs {
    /// The poller and both listeners (each created inside its sockcreate context, then SO_PASSCRED, SO_PASSSEC, bind
    /// and listen), after the seal, with the enrolled writer executable the I07 check compares (HE-003A2, required).
    pub fn new(_sealed: &Sealed, i05: &ListenerPlan, i07: &ListenerPlan, writer_executable: Vec<u8>)
               -> Result<LinuxOs, SetupError> {
        let poller = Poller::new().map_err(SetupError::Poller)?;
        let listen = |side: Listen, plan: &ListenerPlan| {
            gate_sys::channel::listen_seqpacket(&plan.path, &plan.context)
                .map_err(|error| SetupError::Listener { side, error })
        };
        let i05 = listen(Listen::I05, i05)?;
        let i07 = listen(Listen::I07, i07)?;
        Ok(LinuxOs { poller, i05, i07, slots: BTreeMap::new(), next: 1, net: None, writer_executable })
    }

    /// As [`LinuxOs::new`], with the ports' sources resolved through the shared stream table `net` (HE-003B DESIGN
    /// §4.1, §4.4).
    pub fn with_net(sealed: &Sealed, i05: &ListenerPlan, i07: &ListenerPlan, net: SharedNet, writer_executable: Vec<u8>)
                    -> Result<LinuxOs, SetupError> {
        let mut os = LinuxOs::new(sealed, i05, i07, writer_executable)?;
        os.net = Some(net);
        Ok(os)
    }

    /// One poller request for a port's source: the table borrowed, the source owned by `owner`, then `request`.
    fn port_request(&self, owner: Owner, source: SourceId,
                    request: impl FnOnce(&Poller, Watched<'_>) -> io::Result<()>) -> bool {
        let Some(net) = self.net.as_ref() else { return false };
        let Ok(table) = net.try_borrow() else { return false };
        match table.watched(owner, source) {
            Some(watched) => request(&self.poller, watched).is_ok(),
            None => false,
        }
    }
}

fn interest_of(interest: Interest) -> gate_sys::channel::Interest {
    gate_sys::channel::Interest { readable: interest.readable, writable: interest.writable }
}

impl PortPoll for LinuxOs {
    fn port_add(&mut self, owner: Owner, source: SourceId, token: u64, interest: Interest) -> bool {
        self.port_request(owner, source, |poller, watched| poller.add(watched, token, interest_of(interest)))
    }

    fn port_modify(&mut self, owner: Owner, source: SourceId, token: u64, interest: Interest) -> bool {
        self.port_request(owner, source, |poller, watched| poller.modify(watched, token, interest_of(interest)))
    }

    fn port_delete(&mut self, owner: Owner, source: SourceId) -> bool {
        self.port_request(owner, source, |poller, watched| poller.delete(watched))
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

    fn writer_exe_ok(&mut self, conn: ConnId) -> bool {
        // No connection or no kept process directory is a mismatch (fail closed).
        let Some(directory) = self.slots.get(&conn.0).and_then(|slot| slot.proc_dir.as_ref()) else { return false };
        let mut buffer = vec![0u8; writer_exe_buffer_len(&self.writer_executable)];
        match directory.exe(&mut buffer) {
            Ok(count) => buffer.get(..count).is_some_and(|link| writer_exe_matches(link, &self.writer_executable)),
            Err(_) => false,
        }
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

// ------------------------------------------------------------------------------------------ the observation (HE-003A3)

/// The observation's two root handles: the cgroup2 mount's and the proc filesystem's.
pub struct KernelRoots {
    cgroup: KernelRoot,
    proc_root: KernelRoot,
}

impl KernelRoots {
    /// Opens both roots, after the seal (I05 v4 rule 9: at start; HE-003A3 DESIGN section 5).
    pub fn open_after_seal(_sealed: &Sealed) -> io::Result<KernelRoots> {
        let cgroup = KernelRoot::open_kernel_root("/sys/fs/cgroup")?;
        let proc_root = KernelRoot::open_kernel_root("/proc")?;
        Ok(KernelRoots { cgroup, proc_root })
    }
}

/// The observation's four kernel calls on Linux (see the module documentation); its only fields are the two roots.
pub struct LinuxKernelReads {
    cgroup: KernelRoot,
    proc_root: KernelRoot,
}

impl LinuxKernelReads {
    pub fn new(roots: KernelRoots) -> LinuxKernelReads {
        LinuxKernelReads { cgroup: roots.cgroup, proc_root: roots.proc_root }
    }
}

/// A failed call's errno, or the marker of a failure without one.
fn kernel_fail(error: io::Error) -> KernelFail {
    error.raw_os_error().map_or(KernelFail::NoErrno, KernelFail::Os)
}

/// One file opened afresh relative to `root` and read whole within `limit` bytes.
fn read_fixed(root: &KernelRoot, path: io::Result<FixedPath>, limit: usize) -> Result<Vec<u8>, KernelFail> {
    let path = path.map_err(kernel_fail)?;
    let file = root.open_fixed(&path).map_err(kernel_fail)?;
    match read_bounded(&file, limit) {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(KernelFail::TooLong),
        Err(error) => Err(kernel_fail(error)),
    }
}

impl KernelReads for LinuxKernelReads {
    type Pidfd = PidFd;

    fn read_leaf_procs(&mut self) -> Result<Vec<u8>, KernelFail> {
        let leaf = FixedPath::from_constant("planeon.slice/planeon-capacity-broker.service/probe-worker/cgroup.procs");
        read_fixed(&self.cgroup, leaf, LEAF_PROCS_LIMIT)
    }

    fn pidfd_open(&mut self, pid: i32) -> Result<PidFd, KernelFail> {
        PidFd::open(pid).map_err(kernel_fail)
    }

    fn read_stat(&mut self, pid: i32) -> Result<Vec<u8>, KernelFail> {
        read_fixed(&self.proc_root, FixedPath::pid_stat(pid), STAT_LIMIT)
    }

    fn poll_zero(&mut self, pidfd: &PidFd) -> Result<PidState, KernelFail> {
        match pidfd.poll_zero() {
            Ok(false) => Ok(PidState::Alive),
            Ok(true) => Ok(PidState::Exited),
            Err(error) => Err(kernel_fail(error)),
        }
    }
}
