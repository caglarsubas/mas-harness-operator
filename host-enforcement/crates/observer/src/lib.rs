//! The policy observer's library (HE-004A DESIGN section 3, owner decision Q-HE4A-7 (a)): what the binary's `main`
//! needs, beside it in the same package. HE-004A holds the OBSERVER process seal (`seal`: two stages over gate-sys's
//! raw calls, then the published OBSERVER seccomp program; SEC-4 and HI-7 for OBSERVER) and the exit-status table
//! (`status`). Std only and safe Rust (the root forbids `unsafe_code`); the generic seal engine is crate-private and the
//! Linux stages are the only makers of the `Stage1` and `Sealed` tokens. No configuration is read in HE-004A (owner
//! decision Q-HE4A-1: DESIGN-A §10 option (b), which the monitor's "(a), as recommended" decided, confirmed 2026-10-16;
//! HE-003A3, D1-1); HE-004B and HE-004C add the I06/ADM-4 logic and the apiserver client. The R10-defined behaviour is
//! listed in `crates/effect-gate/MODEL_DEFINED.md` (the HE-004A section).
#![forbid(unsafe_code)]

pub mod admission;
pub mod contracts;
pub mod inputs;
pub mod operational;
pub mod rbac;
pub mod seal;
pub mod snapshot;
pub mod status;

#[cfg(target_os = "linux")]
pub use seal::{seal_stage1, seal_stage2};
pub use seal::{SealError, SealFailure, SealStep, Sealed, Stage, Stage1};
