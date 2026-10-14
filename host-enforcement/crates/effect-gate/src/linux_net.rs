//! The Linux stream table (HE-003B DESIGN §4.1, Q-HE3B-13 (a)): one single-threaded table, shared by `LinuxOs` (which
//! resolves a port's `SourceId` to the descriptor it watches) and the I04 port's [`LinuxStreams`] (which does the
//! port's I/O). A source number is a counter never reused within the process; each entry has its owner and a
//! `TcpListener` or `TcpConn` of gate-sys, closed by drop. Closing removes the entry, and the descriptor's close
//! removes it from the poller (no descriptor is ever duplicated), so a port never deletes a closed source. Every
//! `RefCell` borrow is `try_borrow` or `try_borrow_mut`; a failed borrow refuses (no panic). Linux only.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::rc::Rc;
use std::time::Instant;

use gate_sys::channel::Watched;
use gate_sys::inet::InetAddress;
use gate_sys::tcp::{TcpConn, TcpListenError, TcpListener};

use crate::net::{Accepted, StreamNet, Transfer};
use crate::seal::Sealed;
use crate::substrate::{Owner, SourceId};

/// The I04 listen backlog (DESIGN §7.1, Q-HE3B-21 (a)).
pub const I04_BACKLOG: u16 = 16;

enum Stream {
    Listener(TcpListener),
    Conn(TcpConn),
}

/// The stream table.
pub struct NetTable {
    entries: BTreeMap<u64, (Owner, Stream)>,
    next: u64,
}

impl fmt::Debug for NetTable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NetTable")
    }
}

/// The table, shared by `LinuxOs` and the ports.
pub type SharedNet = Rc<RefCell<NetTable>>;

impl NetTable {
    /// An empty table (a new process starts with fresh connection names, C6).
    pub fn new() -> SharedNet {
        Rc::new(RefCell::new(NetTable { entries: BTreeMap::new(), next: 1 }))
    }

    /// Creates the I04 listener on `address` (after the seal, as `LinuxOs::new` is), owned by the I04 port; its source.
    pub fn listen_i04(net: &SharedNet, _sealed: &Sealed, address: &InetAddress) -> Result<SourceId, TcpListenError> {
        let listener = gate_sys::tcp::listen_tcp(address, I04_BACKLOG)?;
        match net.try_borrow_mut() {
            Ok(mut table) => Ok(table.insert(Owner::I04, Stream::Listener(listener))),
            Err(_) => Err(TcpListenError {
                step: gate_sys::tcp::TcpStep::Listen,
                error: std::io::Error::other("the stream table is busy"),
            }),
        }
    }

    fn insert(&mut self, owner: Owner, stream: Stream) -> SourceId {
        let number = self.next;
        self.next = self.next.saturating_add(1);
        self.entries.insert(number, (owner, stream));
        SourceId(number)
    }

    /// The descriptor of `source` for the poller, when `owner` owns it.
    pub(crate) fn watched(&self, owner: Owner, source: SourceId) -> Option<Watched<'_>> {
        match self.entries.get(&source.0) {
            Some((entry_owner, Stream::Listener(listener))) if *entry_owner == owner => Some(Watched::TcpListener(listener)),
            Some((entry_owner, Stream::Conn(conn))) if *entry_owner == owner => Some(Watched::TcpConn(conn)),
            _ => None,
        }
    }

    fn listener_of(&self, owner: Owner) -> Option<SourceId> {
        self.entries
            .iter()
            .find(|(_, (entry_owner, stream))| *entry_owner == owner && matches!(stream, Stream::Listener(_)))
            .map(|(number, _)| SourceId(*number))
    }

    fn conn(&self, owner: Owner, source: SourceId) -> Option<&TcpConn> {
        match self.entries.get(&source.0) {
            Some((entry_owner, Stream::Conn(conn))) if *entry_owner == owner => Some(conn),
            _ => None,
        }
    }
}

/// A port's [`StreamNet`] over the shared table.
pub struct LinuxStreams {
    net: SharedNet,
    owner: Owner,
}

impl fmt::Debug for LinuxStreams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LinuxStreams")
    }
}

impl LinuxStreams {
    pub fn new(net: SharedNet, owner: Owner) -> LinuxStreams {
        LinuxStreams { net, owner }
    }
}

/// The errno reported when the table cannot be borrowed or names no such source.
const NO_SOURCE: i32 = -1;

impl StreamNet for LinuxStreams {
    fn listener(&self) -> SourceId {
        self.net.try_borrow().ok().and_then(|table| table.listener_of(self.owner)).unwrap_or(SourceId(0))
    }

    fn accept(&mut self) -> Accepted {
        let Ok(mut table) = self.net.try_borrow_mut() else { return Accepted::Failed(NO_SOURCE) };
        let Some(listener) = table.listener_of(self.owner) else { return Accepted::Failed(NO_SOURCE) };
        let accepted = match table.entries.get(&listener.0) {
            Some((_, Stream::Listener(listening))) => gate_sys::tcp::accept_tcp(listening),
            _ => return Accepted::Failed(NO_SOURCE),
        };
        match accepted {
            gate_sys::tcp::Accepted::Conn(conn) => Accepted::Conn(table.insert(self.owner, Stream::Conn(conn))),
            gate_sys::tcp::Accepted::Empty => Accepted::Empty,
            gate_sys::tcp::Accepted::Skip => Accepted::Skip,
            gate_sys::tcp::Accepted::Failed(errno) => Accepted::Failed(errno),
        }
    }

    fn recv(&mut self, source: SourceId, buffer: &mut [u8]) -> Transfer {
        let Ok(table) = self.net.try_borrow() else { return Transfer::Failed(NO_SOURCE) };
        match table.conn(self.owner, source) {
            Some(conn) => transfer(conn.recv(buffer)),
            None => Transfer::Failed(NO_SOURCE),
        }
    }

    fn send(&mut self, source: SourceId, bytes: &[u8]) -> Transfer {
        let Ok(table) = self.net.try_borrow() else { return Transfer::Failed(NO_SOURCE) };
        match table.conn(self.owner, source) {
            Some(conn) => transfer(conn.send(bytes)),
            None => Transfer::Failed(NO_SOURCE),
        }
    }

    fn shutdown_write(&mut self, source: SourceId) -> bool {
        let Ok(table) = self.net.try_borrow() else { return false };
        table.conn(self.owner, source).is_some_and(|conn| conn.shutdown_write().is_ok())
    }

    fn close(&mut self, source: SourceId) {
        if let Ok(mut table) = self.net.try_borrow_mut()
            && table.conn(self.owner, source).is_some()
        {
            table.entries.remove(&source.0);
        }
    }

    fn monotonic(&self) -> Instant {
        Instant::now()
    }
}

fn transfer(result: gate_sys::tcp::Transfer) -> Transfer {
    match result {
        gate_sys::tcp::Transfer::Data(count) => Transfer::Data(count),
        gate_sys::tcp::Transfer::WouldBlock => Transfer::WouldBlock,
        gate_sys::tcp::Transfer::Eof => Transfer::Eof,
        gate_sys::tcp::Transfer::Failed(errno) => Transfer::Failed(errno),
    }
}
