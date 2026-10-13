//! The effect gate's audited system-call surface (HE-002C DESIGN §3 and §9, obligation GATE-OPENAT): store
//! directories and store files are opened with `openat` only, behind a safe API, and every other file operation is
//! std on the `File` this crate returns. Std only, no build script.
//!
//! The crate root denies `unsafe_code`; `openat.rs` alone opts out, and `tools/gate.py` checks that it is the one
//! place in the workspace that may.
#![deny(unsafe_code)]

pub mod openat;

pub use openat::Dir;
pub use openat::FileMode;
