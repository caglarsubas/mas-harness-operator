//! The I04 port's stream I/O (HE-003B DESIGN §4.1, Q-HE3B-13 (a)): the [`StreamNet`] trait the I04 port is generic
//! over, portable and without descriptors. On Linux it is `linux_net::LinuxStreams` over the shared stream table, the
//! same table `linux_os::LinuxOs` reads when the port registers a source; the tests give the port a fake with a fake
//! clock. HE-003C extends it with `connect`.

use std::time::Instant;

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
