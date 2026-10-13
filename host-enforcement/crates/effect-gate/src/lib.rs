//! The I05 v3 effect gate (HE-002): the gate state machine for one generation and its single broker channel, with
//! the in-memory journal and failure marker, the replay restart, the drain fence and the contract's test injections.
//! HE-002B adds the I07 v3 PolicyGate (`policy`, `policy_gate`): the policy-writer channel on top of that gate.
//! HE-002C adds the durable stores (`frame`, `store`, `file_store`): the one journal and the failure marker as files,
//! opened through `gate-sys`, and the process restart. Std only and safe Rust (the root forbids `unsafe_code`), no
//! panics on any input. The channel substrate (HE-003) is not here.
//!
//! Behaviour taken from the pinned models or validator rather than the READMEs, and the R10-defined behaviour, is
//! listed in `MODEL_DEFINED.md`.
#![forbid(unsafe_code)]

pub mod config;
pub mod file_store;
pub mod frame;
pub mod gate;
pub mod journal;
pub mod policy;
pub mod policy_gate;
pub mod store;
pub mod types;

pub use config::{Config, ConfigError, PriorBindings};
pub use file_store::{FileStores, OpenError, StoreDir};
pub use gate::{ChannelRefusal, ConnectionRefusal, Event, EventError, FrameInput, Gate, GateError, Output, OutputKind,
               Stamp, UpstreamResponse};
pub use journal::{ChannelEnd, Entry, Record, TerminalDetails, WriteDetails};
pub use policy::{check_write, classify, render_write, request_digest, write_outcome_is_final, KindsError, PolicyKinds,
                 Prior, RenderedWrite, ResourceRef, WritableKind, WriteOperation, WriteRefusal, WriteRequest};
pub use policy_gate::{PolicyEvent, PolicyGate, PolicyGateError, PolicyOutput, PolicyOutputKind, PolicyWriter,
                      UpstreamOutcome, WriteCounters, WriterFatal, WRITER_FRAME_VERSION};
pub use store::{Appended, FaultHandle, FaultPlan, FilePoint, MemoryStores, StoreFile, Stores};
pub use types::{AbortReason, Classification, CloseReason, DrainAnswer, FatalReason, Invalidation, Maintenance,
                MaintenanceEnd, MaintenanceReason, SessionEnd, State};
