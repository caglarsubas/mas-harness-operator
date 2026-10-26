//! The capacity broker's library (HE-005A: DESIGN-HE005 revision 5 section 4, HE-005A, with the scope notes; owner
//! decisions Q-HE5A-1..3 (a), MON-HE005A-PLAN2): what the binary's `main` needs, beside it in the same package, in the
//! observer's form. Std only and safe Rust (the root forbids `unsafe_code`).
//!
//! - `seal`: the BROKER role's specification over role-seal (bounding = kept = {CAP_NET_ADMIN, CAP_BPF, CAP_SETUID,
//!   CAP_SETGID}, the two embedded BROKER programs), the broker's start-state pre-check (the filesystem uid and gid and
//!   the `Groups:` line, one read of the process's own status, no write) and the two stage wrappers. role-seal's
//!   engine stays crate-private there, and its Linux stages are the only makers of the `Stage1` and `Sealed` tokens.
//! - `status`: the exit statuses (the observer's seal table, NOT_LINUX, NOT_YET_SERVING, the pre-check's 36-39 and the
//!   I02 listener's 24).
//! - `linux_listen` (Linux only): the one file that names gate-sys's channel module and the I02 path (DESIGN-HE005
//!   O12), the I02 listener bound after the seal and never removed.
//! - The seam below: [`I02Listener`], the listener's four operations, and [`serve_unanswered`], the single-threaded
//!   loop over them that closes every accepted connection with no frame written and nothing read (Q-HE5A-3 (a)), so a
//!   host test drives the loop over a fake.
//!
//! The configuration, the HOLD derivation, the lifecycle and every I02, I03 and I05 frame are later packets' (HE-005B
//! to HE-005D); nothing that they guard is reachable here. The R10-defined behaviour is listed in
//! `crates/effect-gate/MODEL_DEFINED.md` (the HE-005A section).
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod linux_listen;
pub mod seal;
pub mod status;

#[cfg(target_os = "linux")]
pub use seal::{seal_stage1, seal_stage2};
pub use seal::{SealError, Sealed, Stage1, StartCheck};

/// Where the I02 listener failed. Every failure ends [`serve_unanswered`], and the binary exits with the listener's
/// one status (`status::LISTENER`, 24).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerError {
    /// The socket, its options, `bind` (an existing path among the causes: the broker never removes it) or `listen`.
    Listen,
    /// The poller, or the listener's registration with it.
    Register,
    /// A wait, or a wait before the listener exists.
    Wait,
    /// An accept that failed (none queued is not a failure), or an accept before the listener exists.
    Accept,
}

/// The I02 listener's operations, the seam [`serve_unanswered`] runs over (MON-HE005A-PLAN2): `linux_listen`'s
/// `LinuxI02` on Linux, a recording fake in the host tests. It offers no read and no write: a connection is only
/// accepted and closed.
pub trait I02Listener {
    /// Binds the I02 socket and makes it ready to wait on; called once, first.
    fn listen(&mut self) -> Result<(), ListenerError>;
    /// Waits until a connection may be queued (a wake may find none).
    fn wait(&mut self) -> Result<(), ListenerError>;
    /// Accepts one queued connection and keeps it: its number, or `None` when none is queued.
    fn accept(&mut self) -> Result<Option<u64>, ListenerError>;
    /// Closes the kept connection with that number, with nothing written to it and nothing read from it.
    fn close(&mut self, connection: u64);
}

/// What the broker serves after the seal until HE-005D (owner decision Q-HE5A-3 (a)): the listener is bound, then each
/// wait is followed by one accept, and an accepted connection is closed at once, unanswered. Single-threaded; it returns
/// only on a listener error, which it returns.
pub fn serve_unanswered<L: I02Listener>(listener: &mut L) -> ListenerError {
    if let Err(error) = listener.listen() {
        return error;
    }
    loop {
        if let Err(error) = listener.wait() {
            return error;
        }
        match listener.accept() {
            Ok(Some(connection)) => listener.close(connection),
            Ok(None) => {}
            Err(error) => return error,
        }
    }
}
