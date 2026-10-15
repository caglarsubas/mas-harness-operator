//! The ports' stream I/O, portable and without descriptors: the [`StreamNet`] trait the I04 port is generic over
//! (HE-003B DESIGN §4.1, Q-HE3B-13 (a)), and the [`ConnectNet`] trait the upstream port is generic over (HE-003C
//! DESIGN §6), a second trait so that `StreamNet` and HE-003A/B's test fakes stay as they are. On Linux they are
//! `linux_net::LinuxStreams` and `linux_net::LinuxConnector` over the shared stream table, the same table
//! `linux_os::LinuxOs` reads when a port registers a source; the tests give the ports fakes with a fake clock. The
//! literal address types of gate-sys's `inet` are re-exported here for the upstream port's crate.

use std::time::Instant;

pub use gate_sys::inet::{InetAddress, IpLiteral};

use crate::substrate::SourceId;

/// One accept on the port's listener.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Accepted {
    /// A new connection, with a source number never used before in this process.
    Conn(SourceId),
    /// Nothing queued (EAGAIN).
    Empty,
    /// The queued connection died (ECONNABORTED or a network error accept(2) names): accept again.
    Skip,
    /// Any other failure, as its errno.
    Failed(i32),
}

/// One receive or send on a connection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Transfer {
    /// The bytes received (at least 1) or sent (a partial count is normal on a stream).
    Data(usize),
    /// Nothing to receive, or no room to send (EAGAIN).
    WouldBlock,
    /// The peer closed its side (a receive of 0 bytes).
    Eof,
    /// Any other failure, as its errno.
    Failed(i32),
}

/// The I04 port's view of its listener and connections.
pub trait StreamNet {
    /// The listener's source.
    fn listener(&self) -> SourceId;
    /// One accept on the listener.
    fn accept(&mut self) -> Accepted;
    /// One receive into `buffer` (never empty) without waiting.
    fn recv(&mut self, source: SourceId, buffer: &mut [u8]) -> Transfer;
    /// One send of `bytes` without waiting.
    fn send(&mut self, source: SourceId, bytes: &[u8]) -> Transfer;
    /// Shuts the connection's write side (after the relayed response and `close_notify`, DESIGN §7.1); false on
    /// failure.
    fn shutdown_write(&mut self, source: SourceId) -> bool;
    /// Closes a connection (closing removes it from the poller; a source is never reused).
    fn close(&mut self, source: SourceId);
    /// The monotonic clock the substrate uses (the port's `ready` and `drain_backlog` receive no time).
    fn monotonic(&self) -> Instant;
}

/// How a non-blocking connect started (gate-sys's `tcp::Connecting`, portable).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Connecting {
    /// Connected at once (`connect` returned 0).
    Connected,
    /// In progress (EINPROGRESS): wait for writability, then [`ConnectNet::connect_result`].
    InProgress,
}

/// The upstream port's view of its outgoing connections (HE-003C DESIGN §2 step 2, §6).
pub trait ConnectNet {
    /// A non-blocking TCP connect to `address`: the new source (a number never used before in this process) and how
    /// it started, or the errno of the failed `socket` or `connect` (no source then).
    fn connect(&mut self, address: &InetAddress) -> Result<(SourceId, Connecting), i32>;
    /// SO_ERROR of a connecting source once it is writable: `Ok(())` when connected, otherwise the errno.
    fn connect_result(&mut self, source: SourceId) -> Result<(), i32>;
    /// One receive into `buffer` (never empty) without waiting.
    fn recv(&mut self, source: SourceId, buffer: &mut [u8]) -> Transfer;
    /// One send of `bytes` without waiting.
    fn send(&mut self, source: SourceId, bytes: &[u8]) -> Transfer;
    /// Shuts the connection's write side; false on failure.
    fn shutdown_write(&mut self, source: SourceId) -> bool;
    /// Closes a connection (closing removes it from the poller; a source is never reused).
    fn close(&mut self, source: SourceId);
    /// The monotonic clock the substrate uses.
    fn monotonic(&self) -> Instant;
}
