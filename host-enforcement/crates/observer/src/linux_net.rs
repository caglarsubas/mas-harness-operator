//! The observer's socket module (HE-004C DESIGN-C section 4.4; MODEL_DEFINED R109), Linux only: [`LinuxWire`]
//! implements the portable `client::Wire` over gate-sys's existing calls, `tcp::connect_tcp` (one `socket` and one
//! `connect`), `tcp::connect_result` (`getsockopt(SO_ERROR)`), `TcpConn`'s `recv`, `send` and `shutdown_write`, and
//! `channel::Poller` (`epoll_create1`, `epoll_ctl`, `epoll_pwait`). No new raw call, foreign item or file is added; every
//! call is in the OBSERVER row (seccomp allowlists v4 = v3) and T04's trace is the proof.
//!
//! Its only constructor takes the observer's `&Sealed`, so no socket or poller exists before the seal (as the gate's
//! `NetTable::connect(&Sealed, ..)`); that is code review's, and `main`'s grammar already makes the wire unreachable
//! before the second stage. A connection number is a counter never reused within the process; closing drops the
//! `TcpConn`, whose close also removes it from the poller (a closed connection is never deleted explicitly). The
//! interests of each wait are applied with `epoll_ctl` add or modify; a registered connection that the wait does not
//! name is set to no interest. An `epoll_ctl` or `epoll_pwait` failure other than an interrupted wait is a
//! `PollError` (status 95). gate-sys types appear only in private fields.
//!
//! HE-004-I01a (DESIGN-I01A sections 4 and 5; MODEL_DEFINED's HE-004-I01a section): the constructor also opens the I01
//! listener (`linux_listen::I01Socket`, kept in a private field) and registers it, so its error is `client::WireSetup`
//! (24 for the poller, 31-34 for the listener). `LinuxWire` implements `client::PeerOps` by handing each operation to
//! that listener. Each wait also applies the I01 watch it is given, on tokens disjoint from the connections' (the
//! listener's `u64::MAX`, a peer's its number with the top bit set; connection numbers count from 1 and never reach
//! it): the listener is added when wanted and removed when not (a failure is a listener fault, reported in `Woken`,
//! never status 95), the session's peer is added (a failure is that peer's), and a watch failure makes that wait a
//! zero-timeout one, so the fault is handled at once. The I01 readiness comes back apart from the connections'.
//! The seccomp-v5 OBSERVER row allows the listener's `bind`, `listen` and `accept4`.

use std::collections::BTreeMap;
use std::io;
use std::time::Instant;

use gate_sys::channel;
use gate_sys::inet::InetAddress;
use gate_sys::tcp;

use crate::client::{AcceptResult, ConnId, Connecting, ExeLink, Interest, ListenerSetup, PeerCreds, PeerId, PeerOps,
                    PeerRecv, PeerWatch, PollError, ProcIdentity, Ready, Transfer, Wire, WireSetup, Woken, NO_CONNECTION};
use crate::linux_listen::I01Socket;
use crate::seal::Sealed;
use crate::utc;

/// The I01 listener's poller token, and the bit that marks a peer's (disjoint from the connections' numbers).
const LISTENER_TOKEN: u64 = u64::MAX;
const PEER_TOKEN: u64 = 1 << 63;

/// The observer's Linux transport: the poller, the open connections and the I01 listener.
pub struct LinuxWire {
    poller: channel::Poller,
    conns: BTreeMap<u64, tcp::TcpConn>,
    registered: BTreeMap<u64, Interest>,
    next: u64,
    i01: I01Socket,
    listener_watched: bool,
    peer_watched: Option<PeerId>,
}

fn errno(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(-1)
}

fn transfer(result: tcp::Transfer) -> Transfer {
    match result {
        tcp::Transfer::Data(count) => Transfer::Data(count),
        tcp::Transfer::WouldBlock => Transfer::WouldBlock,
        tcp::Transfer::Eof => Transfer::Eof,
        tcp::Transfer::Failed(errno) => Transfer::Failed(errno),
    }
}

/// The milliseconds from `now` until `until`, rounded up and capped at `i32::MAX` (0 when it has come).
fn timeout_ms(now: Instant, until: Instant) -> i32 {
    let left = until.saturating_duration_since(now);
    let whole = left.as_millis().saturating_add(u128::from(left.subsec_nanos() % 1_000_000 != 0));
    i32::try_from(whole).unwrap_or(i32::MAX)
}

impl LinuxWire {
    /// The wire, after the seal: its poller (`epoll_create1`; status 24), then the I01 listener (31-33) and its
    /// registration with the poller (34).
    pub fn new(sealed: &Sealed) -> Result<LinuxWire, WireSetup> {
        let poller = channel::Poller::new().map_err(|error| WireSetup::Poller(errno(&error)))?;
        let i01 = I01Socket::open(sealed).map_err(WireSetup::Listener)?;
        let readable = channel::Interest { readable: true, writable: false };
        poller
            .add(i01.watched_listener(), LISTENER_TOKEN, readable)
            .map_err(|_| WireSetup::Listener(ListenerSetup::Register))?;
        Ok(LinuxWire { poller, conns: BTreeMap::new(), registered: BTreeMap::new(), next: 1, i01, listener_watched: true,
                       peer_watched: None })
    }

    fn watch(&mut self, number: u64, wanted: Interest) -> Result<(), PollError> {
        let Some(conn) = self.conns.get(&number) else { return Ok(()) };
        let interest = channel::Interest { readable: wanted.readable, writable: wanted.writable };
        let result = match self.registered.get(&number) {
            None => self.poller.add(channel::Watched::TcpConn(conn), number, interest),
            Some(current) if *current != wanted => self.poller.modify(channel::Watched::TcpConn(conn), number, interest),
            Some(_) => Ok(()),
        };
        result.map_err(|error| PollError(errno(&error)))?;
        self.registered.insert(number, wanted);
        Ok(())
    }

    /// The I01 watch a wait is given, applied before it: the listener added or removed as `peers` says (a failure is a
    /// listener fault; a failed removal counts the listener as removed, so a later add that finds it fails again), the
    /// session's peer added (a failure is that peer's fault) and a peer no longer named removed when still held.
    fn watch_i01(&mut self, peers: PeerWatch, woken: &mut Woken) {
        let readable = channel::Interest { readable: true, writable: false };
        if peers.listener != self.listener_watched {
            let result = if peers.listener {
                self.poller.add(self.i01.watched_listener(), LISTENER_TOKEN, readable)
            } else {
                self.poller.delete(self.i01.watched_listener())
            };
            self.listener_watched = peers.listener && result.is_ok();
            woken.listener_fault = result.is_err();
        }
        if peers.peer != self.peer_watched {
            if let Some(old) = self.peer_watched.take() {
                if let Some(watched) = self.i01.watched_peer(old) {
                    let _removed_or_closed_later = self.poller.delete(watched);
                }
            }
            if let Some(peer) = peers.peer {
                let added = self.i01.watched_peer(peer).map(|watched| self.poller.add(watched, PEER_TOKEN | peer.0, readable));
                match added {
                    Some(Ok(())) => self.peer_watched = Some(peer),
                    _ => woken.peer_faults.push(peer),
                }
            }
        }
    }
}

impl Wire for LinuxWire {
    fn connect(&mut self, address: &InetAddress) -> Result<(ConnId, Connecting), i32> {
        let (conn, started) = tcp::connect_tcp(address)?;
        let number = self.next;
        self.next = self.next.saturating_add(1);
        self.conns.insert(number, conn);
        let started = match started {
            tcp::Connecting::Connected => Connecting::Connected,
            tcp::Connecting::InProgress => Connecting::InProgress,
        };
        Ok((ConnId(number), started))
    }

    fn connect_result(&mut self, conn: ConnId) -> Result<(), i32> {
        match self.conns.get(&conn.0) {
            Some(open) => tcp::connect_result(open),
            None => Err(NO_CONNECTION),
        }
    }

    fn recv(&mut self, conn: ConnId, buffer: &mut [u8]) -> Transfer {
        match self.conns.get(&conn.0) {
            Some(open) => transfer(open.recv(buffer)),
            None => Transfer::Failed(NO_CONNECTION),
        }
    }

    fn send(&mut self, conn: ConnId, bytes: &[u8]) -> Transfer {
        match self.conns.get(&conn.0) {
            Some(open) => transfer(open.send(bytes)),
            None => Transfer::Failed(NO_CONNECTION),
        }
    }

    fn shutdown_write(&mut self, conn: ConnId) -> bool {
        self.conns.get(&conn.0).is_some_and(|open| open.shutdown_write().is_ok())
    }

    fn close(&mut self, conn: ConnId) {
        self.registered.remove(&conn.0);
        self.conns.remove(&conn.0);
    }

    fn wait(&mut self, interests: &[(ConnId, Interest)], peers: PeerWatch, until: Instant) -> Result<Woken, PollError> {
        for (conn, wanted) in interests {
            self.watch(conn.0, *wanted)?;
        }
        let quiet: Vec<u64> = self
            .registered
            .iter()
            .filter(|(number, current)| {
                !interests.iter().any(|(conn, _)| conn.0 == **number) && (current.readable || current.writable)
            })
            .map(|(number, _)| *number)
            .collect();
        for number in quiet {
            self.watch(number, Interest { readable: false, writable: false })?;
        }
        let mut woken = Woken::default();
        self.watch_i01(peers, &mut woken);
        let now = Instant::now();
        let until = if woken.listener_fault || !woken.peer_faults.is_empty() { now } else { until };
        let mut ready = Vec::new();
        self.poller.wait(timeout_ms(now, until), &mut ready).map_err(|error| PollError(errno(&error)))?;
        for (token, found) in ready {
            let found = Ready { readable: found.readable, writable: found.writable, error: found.error, hangup: found.hangup };
            if token == LISTENER_TOKEN {
                if self.listener_watched {
                    woken.listener = Some(found);
                }
            } else if token & PEER_TOKEN != 0 {
                let peer = PeerId(token & !PEER_TOKEN);
                if self.peer_watched == Some(peer) {
                    woken.peers.push((peer, found));
                }
            } else {
                woken.conns.push((ConnId(token), found));
            }
        }
        Ok(woken)
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall_seconds(&self) -> Option<u64> {
        utc::wall_seconds()
    }
}

impl PeerOps for LinuxWire {
    fn accept_peer(&mut self) -> AcceptResult {
        self.i01.accept()
    }

    fn peer_creds(&mut self, peer: PeerId) -> Result<PeerCreds, i32> {
        self.i01.creds(peer)
    }

    fn peer_proc_open(&mut self, peer: PeerId) -> Result<(), i32> {
        self.i01.proc_open(peer)
    }

    fn peer_proc_read(&mut self, peer: PeerId) -> Result<ProcIdentity, i32> {
        self.i01.proc_read(peer)
    }

    fn peer_exe(&mut self, peer: PeerId) -> Result<ExeLink, i32> {
        self.i01.exe(peer)
    }

    fn peer_alive(&mut self, peer: PeerId) -> bool {
        self.i01.alive(peer)
    }

    fn peer_recv(&mut self, peer: PeerId, buffer: &mut [u8]) -> PeerRecv {
        self.i01.recv(peer, buffer)
    }

    fn peer_close(&mut self, peer: PeerId) {
        if self.peer_watched == Some(peer) {
            self.peer_watched = None;
        }
        self.i01.close(peer);
    }
}
