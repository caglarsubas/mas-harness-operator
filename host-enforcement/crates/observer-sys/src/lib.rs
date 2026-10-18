//! The policy observer's kernel reads (HE-004D1 DESIGN-D1 sections 3 and 4; owner decisions Q-HE4D1-4 and -5 (a)): a
//! std-only crate that planeon-observer alone links, so planeon-gate and gate-sys stay byte-identical. `dirent` is the
//! portable parser of a `getdents64` record buffer, host-tested; `kernel` (Linux only) holds the one foreign item,
//! `syscall`, the six calls it issues by number, their constants and layouts with compile-time asserts, one `// SAFETY:`
//! block per call and the safe API the observer's `linux_capture` module drives after the seal.
//!
//! The crate root denies `unsafe_code`; `kernel.rs` alone opts out, and `tools/gate.py` checks that it is the only file
//! of this crate that may, which foreign item it declares and how every call is formed (G-D1-2, G-D1-3, G-D1-4).
#![deny(unsafe_code)]

pub mod dirent;
#[cfg(target_os = "linux")]
pub mod kernel;
