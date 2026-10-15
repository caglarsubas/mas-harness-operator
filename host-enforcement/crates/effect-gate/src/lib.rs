//! The I05 v3 effect gate (HE-002): the gate state machine for one generation and its single broker channel, with
//! the in-memory journal and failure marker, the replay restart, the drain fence and the contract's test injections.
//! HE-002B adds the I07 v3 PolicyGate (`policy`, `policy_gate`): the policy-writer channel on top of that gate.
//! HE-002C adds the durable stores (`frame`, `store`, `file_store`): the one journal and the failure marker as files,
//! opened through `gate-sys`, and the process restart. HE-002S adds the EFFECT_GATE process seal (`seal`): two
//! stages, then the published seccomp program, over gate-sys's raw calls. HE-003A adds the channel substrate
//! (`substrate`, with the expected peers in `peers` and the Linux `Os` in `linux_os`): the I05 and I07 listeners, peer
//! qualification and per-frame custody, the expiry clock and the 2-second answer bound, with ports for the I04 and
//! upstream events of HE-003B and HE-003C. HE-003B adds the R10-defined `Event::Disconnect`, the ports' `failure()`
//! with `LoopExit::Port`, the I04 port's stream I/O trait (`net`) and the Linux stream table (`linux_net`, with
//! `LinuxOs::with_net`). Std only and safe Rust (the root forbids `unsafe_code`), no panics on any input. The TLS
//! ports live in the `gate-tls` crate; the binary's `main` (HE-003D) is not here.
//!
//! Behaviour taken from the pinned models or validator rather than the READMEs, and the R10-defined behaviour, is
//! listed in `MODEL_DEFINED.md`.
#![forbid(unsafe_code)]

pub mod config;
pub mod file_store;
pub mod frame;
pub mod gate;
pub mod journal;
#[cfg(target_os = "linux")]
pub mod linux_net;
#[cfg(target_os = "linux")]
pub mod linux_os;
pub mod net;
pub mod peers;
pub mod policy;
pub mod policy_gate;
pub mod seal;
pub mod store;
pub mod substrate;
pub mod types;

pub use config::{Config, ConfigError, PriorBindings};
pub use file_store::{FileStores, OpenError, StoreDir};
pub use gate::{BoundRun, ChannelRefusal, ChannelState, ConnectionRefusal, Event, EventError, FrameInput, Gate, GateError,
               Output, OutputKind, Stamp, UpstreamResponse};
pub use journal::{ChannelEnd, Entry, Record, TerminalDetails, WriteDetails};
pub use net::{Accepted, StreamNet, Transfer};
pub use peers::{ExpectedPeer, ExpectedPeers, ListenerPlan};
pub use policy::{check_write, classify, render_write, request_digest, write_outcome_is_final, KindsError, PolicyKinds,
                 Prior, RenderedWrite, ResourceRef, WritableKind, WriteOperation, WriteRefusal, WriteRequest};
pub use policy_gate::{PolicyEvent, PolicyGate, PolicyGateError, PolicyOutput, PolicyOutputKind, PolicyWriter,
                      UpstreamOutcome, WriteCounters, WriterFatal, WRITER_FRAME_VERSION};
#[cfg(target_os = "linux")]
pub use seal::{seal_stage1, seal_stage2};
pub use seal::{SealError, SealFailure, SealStep, Sealed, Stage, Stage1};
pub use store::{Appended, FaultHandle, FaultPlan, FilePoint, MemoryStores, StoreFile, Stores};
pub use substrate::{ConnId, GateView, I04Port, Interest, Lifetimes, Listen, LoopExit, Os, OsFailure, Owner,
                    PeerCredentials, Port, PortPoll, ProcIdentity, QualifiedIdentity, Readiness, Received, Registry,
                    SourceId, Substrate, UpstreamPort, Watch};
pub use types::{AbortReason, Classification, CloseReason, DrainAnswer, FatalReason, Invalidation, Maintenance,
                MaintenanceEnd, MaintenanceReason, SessionEnd, State};
