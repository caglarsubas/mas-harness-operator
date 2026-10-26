//! The broker's I02 listener (HE-005A: DESIGN-HE005 revision 5 sections 1 (O12) and 4, HE-005A; owner decision
//! Q-HE5A-3 (a), MON-HE005A-PLAN2), Linux only: the one broker file that names gate-sys's channel module, and it
//! re-exports nothing. [`LinuxI02`] holds the listener at the I02 path, its poller and the one accepted connection, all in
//! private fields; it is built only from `&Sealed`, and its only operations are [`crate::I02Listener`]'s.
//!
//! - The listener is gate-sys's `listen_seqpacket_plain` at the one I02 path: an AF_UNIX SOCK_SEQPACKET socket with no
//!   socket context, SO_PASSCRED and SO_PASSSEC, a backlog of one. It binds after the seal and never removes the path:
//!   an existing one fails `bind`, and HE-008's unit clears it before the start (owner: systemd cleans sockets).
//! - A wait is one `epoll_pwait` on the poller, which watches only the listener, for readability, with no timeout.
//! - An accept is gate-sys's `accept` (`accept4` through `syscall`): one connection, or none queued. While one is kept,
//!   nothing more is accepted.
//! - A close drops the kept connection: its descriptor is closed with no `sendmsg` and no `recvmsg` made on it.
//!
//! Nothing here reads a peer's credentials or bytes, and nothing writes a frame (HE-005B and HE-005D's).

use gate_sys::channel;

use crate::seal::Sealed;
use crate::{I02Listener, ListenerError};

/// The I02 path (DESIGN-HE005 O12; the HS53 path list): written here and nowhere else.
const I02_PATH: &str = "/run/planeon/live-proxy/capacity-broker.sock";

/// The listener's token with the poller, which watches nothing else.
const LISTENER_TOKEN: u64 = 0;

/// The I02 listener, its poller and the one accepted connection, kept until it is closed. It derives no `Debug`.
pub struct LinuxI02 {
    listener: Option<channel::Listener>,
    poller: Option<channel::Poller>,
    held: Option<(u64, channel::Conn)>,
    next: u64,
    ready: Vec<(u64, channel::Ready)>,
}

impl LinuxI02 {
    /// The listener's state after the seal: nothing is created until `listen`.
    pub fn new(_sealed: &Sealed) -> LinuxI02 {
        LinuxI02 { listener: None, poller: None, held: None, next: 1, ready: Vec::new() }
    }
}

impl I02Listener for LinuxI02 {
    fn listen(&mut self) -> Result<(), ListenerError> {
        let listener = channel::listen_seqpacket_plain(I02_PATH).map_err(|_| ListenerError::Listen)?;
        let poller = channel::Poller::new().map_err(|_| ListenerError::Register)?;
        let readable = channel::Interest { readable: true, writable: false };
        poller.add(channel::Watched::Listener(&listener), LISTENER_TOKEN, readable).map_err(|_| ListenerError::Register)?;
        self.listener = Some(listener);
        self.poller = Some(poller);
        Ok(())
    }

    fn wait(&mut self) -> Result<(), ListenerError> {
        let poller = self.poller.as_ref().ok_or(ListenerError::Wait)?;
        poller.wait(-1, &mut self.ready).map_err(|_| ListenerError::Wait)
    }

    fn accept(&mut self) -> Result<Option<u64>, ListenerError> {
        let listener = self.listener.as_ref().ok_or(ListenerError::Accept)?;
        if self.held.is_some() {
            return Ok(None);
        }
        match channel::accept(listener) {
            Ok(Some(conn)) => {
                let connection = self.next;
                self.next = self.next.saturating_add(1);
                self.held = Some((connection, conn));
                Ok(Some(connection))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(ListenerError::Accept),
        }
    }

    fn close(&mut self, connection: u64) {
        if self.held.as_ref().is_some_and(|(held, _)| *held == connection) {
            self.held = None;
        }
    }
}
