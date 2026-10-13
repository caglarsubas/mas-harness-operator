//! The I05 v3 effect gate (HE-002): the gate state machine for one generation and its single broker channel, with
//! the in-memory journal and failure marker, the replay restart, the drain fence and the contract's test injections.
//! HE-002B adds the I07 v3 PolicyGate (`policy`, `policy_gate`): the policy-writer channel on top of that gate.
//! Std only, no unsafe code, no panics on any input. Durable stores (HE-002C) and the channel substrate (HE-003) are
//! not here.
//!
//! Behaviour taken from the pinned models or validator rather than the READMEs, and the R10-defined behaviour, is
//! listed in `MODEL_DEFINED.md`.
#![forbid(unsafe_code)]

pub mod config;
pub mod gate;
pub mod journal;
pub mod policy;
pub mod policy_gate;
pub mod types;

pub use config::{Config, ConfigError};
pub use gate::{ChannelRefusal, ConnectionRefusal, Event, EventError, FrameInput, Gate, GateError, Output, OutputKind,
               Stamp, UpstreamResponse};
pub use journal::{ChannelEnd, Entry, Record, TerminalDetails, WriteDetails};
pub use policy::{check_write, classify, render_write, request_digest, write_outcome_is_final, KindsError, PolicyKinds,
                 Prior, RenderedWrite, ResourceRef, WritableKind, WriteOperation, WriteRefusal, WriteRequest};
pub use policy_gate::{PolicyEvent, PolicyGate, PolicyGateError, PolicyOutput, PolicyOutputKind, PolicyWriter,
                      UpstreamOutcome, WriteCounters, WriterFatal, WRITER_FRAME_VERSION};
pub use types::{AbortReason, Classification, CloseReason, DrainAnswer, FatalReason, Invalidation, Maintenance,
                MaintenanceEnd, MaintenanceReason, SessionEnd, State};
