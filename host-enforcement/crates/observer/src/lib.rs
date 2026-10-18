//! The policy observer's library (HE-004A DESIGN section 3, owner decision Q-HE4A-7 (a)): what the binary's `main`
//! needs, beside it in the same package. HE-004A holds the OBSERVER process seal (`seal`: two stages over gate-sys's
//! raw calls, then the published OBSERVER seccomp program; SEC-4 and HI-7 for OBSERVER) and the exit-status table
//! (`status`). Std only and safe Rust (the root forbids `unsafe_code`); the generic seal engine is crate-private and the
//! Linux stages are the only makers of the `Stage1` and `Sealed` tokens. No configuration is read in HE-004A (owner
//! decision Q-HE4A-1: DESIGN-A §10 option (b), which the monitor's "(a), as recommended" decided, confirmed 2026-10-16;
//! HE-003A3, D1-1); HE-004B and HE-004C add the I06/ADM-4 logic and the apiserver client. The R10-defined behaviour is
//! listed in `crates/effect-gate/MODEL_DEFINED.md` (the HE-004A section).
//!
//! HE-004C (DESIGN-C revision 4; owner decisions Q-HE4-5, Q-HE4-6 and Q-HE4C-1..14, all (a)) adds the apiserver read
//! client and the live wiring, all of it run after the seal from `main.rs`'s `serve`: the signed configuration
//! (`signed_config`, `config`), the credentials (`credentials`) and the TLS 1.3 client profile (`tls`), the portable
//! transport (`client`) over the Linux socket module (`linux_net`, whose only constructor takes `&Sealed`), HTTP/1.1
//! (`http`), the exposition and watch-line readers (`exposition`, `watch`), the requests from B1's specs (`requests`),
//! quota headroom (`quota`), the UTC text of the wall clock (`utc`) and the observation epoch (`observe`). B1's five
//! logic modules and `contracts` are unchanged; the HE-004C rows of MODEL_DEFINED start at R106.
#![forbid(unsafe_code)]

pub mod admission;
pub mod client;
pub mod config;
pub mod contracts;
pub mod credentials;
pub mod exposition;
pub mod http;
pub mod inputs;
#[cfg(target_os = "linux")]
pub mod linux_net;
pub mod observe;
pub mod operational;
pub mod quota;
pub mod rbac;
pub mod requests;
pub mod seal;
pub mod signed_config;
pub mod snapshot;
pub mod status;
pub mod tls;
pub mod utc;
pub mod watch;

#[cfg(target_os = "linux")]
pub use seal::{seal_stage1, seal_stage2};
pub use seal::{SealError, SealFailure, SealStep, Sealed, Stage, Stage1};
