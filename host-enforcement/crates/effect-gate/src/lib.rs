//! The I05 v3 effect gate (HE-002): the gate state machine for one generation and its single broker channel, with
//! the in-memory journal and failure marker, the replay restart, the drain fence and the contract's test injections.
//! Std only, no unsafe code, no panics on any input. Durable stores (HE-002C), the I07 PolicyGate (HE-002B) and the
//! channel substrate (HE-003) are not here.
//!
//! Behaviour taken from the pinned model or validator rather than the READMEs, and the R10-defined behaviour, is
//! listed in `MODEL_DEFINED.md`.
#![forbid(unsafe_code)]

pub mod config;
pub mod gate;
pub mod journal;
pub mod types;

pub use config::{Config, ConfigError};
pub use gate::{ChannelRefusal, ConnectionRefusal, Event, EventError, FrameInput, Gate, GateError, Output, OutputKind,
               Stamp, UpstreamResponse};
pub use journal::{ChannelEnd, Entry, Record, TerminalDetails};
pub use types::{Classification, CloseReason, DrainAnswer, FatalReason, Invalidation, State};
