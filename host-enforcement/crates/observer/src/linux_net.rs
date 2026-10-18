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

use std::collections::BTreeMap;
use std::io;
use std::time::Instant;

use gate_sys::channel;
use gate_sys::inet::InetAddress;
use gate_sys::tcp;

use crate::client::{ConnId, Connecting, Interest, PollError, Ready, Transfer, Wire, NO_CONNECTION};
use crate::seal::Sealed;
use crate::utc;

/// The observer's Linux transport: the poller and the open connections.
pub struct LinuxWire {
    poller: channel::Poller,
    conns: BTreeMap<u64, tcp::TcpConn>,
    registered: BTreeMap<u64, Interest>,
    next: u64,
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
    /// The wire, after the seal: its poller (`epoll_create1`), or the errno of the failed call (status 24).
    pub fn new(_sealed: &Sealed) -> Result<LinuxWire, i32> {
        let poller = channel::Poller::new().map_err(|error| errno(&error))?;
        Ok(LinuxWire { poller, conns: BTreeMap::new(), registered: BTreeMap::new(), next: 1 })
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

    fn wait(&mut self, interests: &[(ConnId, Interest)], until: Instant) -> Result<Vec<(ConnId, Ready)>, PollError> {
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
        let mut ready = Vec::new();
        self.poller.wait(timeout_ms(Instant::now(), until), &mut ready).map_err(|error| PollError(errno(&error)))?;
        Ok(ready
            .into_iter()
            .map(|(token, found)| {
                (ConnId(token), Ready { readable: found.readable, writable: found.writable, error: found.error,
                                        hangup: found.hangup })
            })
            .collect())
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall_seconds(&self) -> Option<u64> {
        utc::wall_seconds()
    }
}
