//! The effect gate's audited system-call surface (HE-002C DESIGN §3 and §9, obligation GATE-OPENAT): store
//! directories and store files are opened with `openat` only, behind a safe API, and every other file operation is
//! std on the `File` this crate returns. HE-002S (DESIGN §6) adds the process seal's raw calls in `seal` (Linux only),
//! behind safe functions that effect-gate's seal plan drives. HE-003A (DESIGN §3) adds the channel substrate's raw
//! calls in `channel` (Linux only: the AF_UNIX SOCK_SEQPACKET listeners, accept, peer credentials, the proc
//! filesystem's identity reads, pidfd probes, datagrams and the poller) and their portable byte parsers in
//! `peer_wire`. Std only, no build script.
//!
//! The crate root denies `unsafe_code`; `openat.rs`, `seal.rs` and `channel.rs` alone opt out, and `tools/gate.py`
//! checks that they are the only places in the workspace that may, and which foreign symbols each declares.
#![deny(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod channel;
pub mod openat;
pub mod peer_wire;
#[cfg(target_os = "linux")]
pub mod seal;

pub use openat::Dir;
pub use openat::FileMode;
