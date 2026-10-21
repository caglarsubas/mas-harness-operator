//! The observer binary's exit statuses (HE-004A DESIGN section 5, D1-10): one distinct, non-zero status below 200 (systemd
//! reserves 200-243) per failure point of the seal (stage 1 in 40-59, stage 2 in 60-79), the "not yet serving" exit after
//! a successful seal (owner decision Q-HE4A-2 (a): nothing serves in HE-004A, so the process ends there) and the
//! non-Linux build's stub. Portable and host-tested; MODEL_DEFINED.md lists the table (R86).
//!
//! HE-004C (DESIGN-C section 14, D1-2; MODEL_DEFINED R106) adds the serving statuses in their own table, `SERVING`:
//! `serve`'s setup (11-14, 20-24) and the epoch's exits (80-99, `observation`, one exhaustive match). `STAGES` keeps
//! `NOT_YET_SERVING`, which `main` no longer reaches. Every status stays distinct, non-zero, below 200 and outside
//! 40-79, 2 and 10. There is no normal end and no status 0.
//!
//! HE-004D1 (DESIGN-D1 section 17.2, owner decision Q-HE4D1-7 (a); MODEL_DEFINED R132) adds the capture setup's
//! statuses in a third table, `CAPTURE_SETUP` (25-30): the embedded schema (25), the record's read (26), form (27),
//! read-path preconditions (28) and window (29), and the capture roots (30), mapped by `capture_setup`, one exhaustive
//! match. 31-39 stay free. A capture's own failure is never a status: it is a slot of the view.
//!
//! HE-004-I01a (DESIGN-I01A sections 4 and 14) adds the I01 listener's statuses in a fourth table, `LISTENER` (31-35):
//! at setup its socket, address or options (31), `bind` (32), `listen` (33) and its registration with the poller (34),
//! mapped with the poller's 24 by `wire_setup`, one exhaustive match over `client::WireSetup`; at run time the listener
//! failing persistently (35: twelve faults in a row), an epoch exit. One list everywhere: 31, 32, 33, 34 and 35; 36-39
//! stay free. No other I01 condition exits: sessions close, and the listener backs off.

use crate::client::{ListenerSetup, WireSetup};
use crate::config::LifetimeError;
use crate::enrolled::SetupError;
use crate::observe::ObserverExit;
use crate::seal::{SealError, SealStep, Stage};
use crate::signed_config::LoadError;

/// The non-Linux build of the binary (command 8's darwin build) has no observer to run.
pub const NOT_LINUX: u8 = 2;
/// Both stages of the seal succeeded and the OBSERVER program is installed; HE-004A served nothing, so `main` ended
/// here. Kept in the table (HE-004A's test pins `STAGES`); since HE-004C `main` runs `serve` instead.
pub const NOT_YET_SERVING: u8 = 10;

/// The status of a seal error: its step's.
pub fn seal(error: &SealError) -> u8 {
    seal_step(error.step())
}

/// One total mapping over both stages, exhaustive per `SealStep` variant, so a new variant fails the build.
pub fn seal_step(step: SealStep) -> u8 {
    match step {
        SealStep::Threads(Stage::One) => 40,
        SealStep::UserIds => 41,
        SealStep::GroupIds => 42,
        SealStep::StartCapabilities => 43,
        SealStep::StartBounding => 44,
        SealStep::StartAmbient => 45,
        SealStep::StartState => 46,
        SealStep::Program => 47,
        SealStep::CoreLimit => 48,
        SealStep::CoreLimitReadBack => 49,
        SealStep::Ambient => 50,
        SealStep::Capabilities => 51,
        SealStep::CapabilitiesReadBack => 52,
        SealStep::NoNewPrivs => 53,
        SealStep::NoNewPrivsReadBack => 54,
        SealStep::Threads(Stage::Two) => 60,
        SealStep::FinalCapabilities => 61,
        SealStep::FinalBounding => 62,
        SealStep::FinalAmbient => 63,
        SealStep::FinalNoNewPrivs => 64,
        SealStep::FinalCoreLimit => 65,
        SealStep::Filter => 66,
    }
}

/// The statuses outside the seal, in table order.
pub const STAGES: [u8; 2] = [NOT_LINUX, NOT_YET_SERVING];

/// `signed_config::load`: a document not read as specified.
pub const CONFIG_READ: u8 = 11;
/// The key not set, refused, or the signature not verified.
pub const CONFIG_SIGNATURE: u8 = 12;
/// The canonical form, schema or a check of the configuration.
pub const CONFIG_CHECK: u8 = 13;
/// `now` outside `[notBefore, notAfter)` at start.
pub const CONFIG_LIFETIME: u8 = 14;
/// A credential or CA entry: open, size, read or pin.
pub const CREDENTIALS: u8 = 20;
/// `tls::client_config`.
pub const TLS_SETUP: u8 = 21;
/// `Closure::embedded()` refused at setup.
pub const CLOSURE: u8 = 22;
/// `LinuxWire::new`'s poller.
pub const SOCKETS: u8 = 24;
/// OR07 not reached in 300 s (the last answer not 401/403), or the hook absent (404).
pub const READYZ: u8 = 80;
/// The restart marker differs from `S0`.
pub const APISERVER_RESTART: u8 = 81;
/// 401 or 403 (after the cold start window, or still at its end).
pub const READ_REFUSED: u8 = 82;
/// The reopen bound exceeded; the snapshot deadline with transport as the last failure.
pub const UNREACHABLE: u8 = 83;
/// Another status, a framing or size refusal, the node-count cap, a malformed document, exposition, marker or progress
/// answer.
pub const ANSWER: u8 = 84;
/// `R` not decimal; an `Exact` answer's resourceVersion other than `R`; a progress resourceVersion missing or not
/// decimal; an `F` or `R` going backwards.
pub const CONSISTENCY: u8 = 85;
/// B1's `InputError`, `Missing` for a kind served only at another version included.
pub const INPUTS: u8 = 86;
/// B1's `ProduceError` or the snapshot check's refusal.
pub const RBAC: u8 = 87;
/// OR02, OR05, OR06.
pub const OPERATIONAL: u8 = 88;
/// The quota refusals; unsettled past the snapshot deadline.
pub const QUOTA: u8 = 89;
/// An ADM-4 MISMATCH verdict (snapshot or 60 s cycle).
pub const ADM4_MISMATCH: u8 = 90;
/// An ADM-4 UNAVAILABLE verdict (snapshot or 60 s cycle).
pub const ADM4_UNAVAILABLE: u8 = 91;
/// 410 on a reopen, an `ERROR` event, a malformed short event.
pub const WATCH_GAP: u8 = 92;
/// The snapshot deadline (the last failure not transport).
pub const DEADLINE: u8 = 93;
/// `notAfter` reached while running.
pub const CONFIG_EXPIRED: u8 = 94;
/// `Wire::wait` returned `PollError`.
pub const POLL: u8 = 95;
/// `check_loaded_manifest` returned `Adm4InputError`.
pub const ADM4_INPUT: u8 = 96;
/// A wall clock before the epoch or past the year 9999 (the lifetime check or `utc.rs`).
pub const CLOCK: u8 = 97;
/// Three staleness snapshots in a row.
pub const STALE: u8 = 98;
/// The weighted expansion guard before the producer.
pub const EXPANSION: u8 = 99;

/// The serving statuses, in table order.
pub const SERVING: [u8; 28] = [
    CONFIG_READ, CONFIG_SIGNATURE, CONFIG_CHECK, CONFIG_LIFETIME, CREDENTIALS, TLS_SETUP, CLOSURE, SOCKETS, READYZ,
    APISERVER_RESTART, READ_REFUSED, UNREACHABLE, ANSWER, CONSISTENCY, INPUTS, RBAC, OPERATIONAL, QUOTA, ADM4_MISMATCH,
    ADM4_UNAVAILABLE, WATCH_GAP, DEADLINE, CONFIG_EXPIRED, POLL, ADM4_INPUT, CLOCK, STALE, EXPANSION,
];

/// `CaptureSchema::embedded`: the canonical pin, a conditional outside the closed form, or a variant's load.
pub const CAPTURE_SCHEMA: u8 = 25;
/// `enrolled::load_record`: the record's open, size, read or pin.
pub const RECORD_READ: u8 = 26;
/// The record's form: the canonical subset, the node cap, not a v4 record, the data bound or the `record` variant.
pub const RECORD_FORM: u8 = 27;
/// R10's read-path preconditions of the record.
pub const RECORD_TARGETS: u8 = 28;
/// The record's window: not canonical, not ordered, or already over at start.
pub const RECORD_WINDOW: u8 = 29;
/// `LinuxCapture::new`: a capture root's open or its filesystem magic.
pub const CAPTURE_ROOTS: u8 = 30;

/// The capture setup's statuses, in table order (HE-004D1).
pub const CAPTURE_SETUP: [u8; 6] = [CAPTURE_SCHEMA, RECORD_READ, RECORD_FORM, RECORD_TARGETS, RECORD_WINDOW, CAPTURE_ROOTS];

/// The I01 listener's socket, address or options (HE-004-I01a).
pub const LISTENER_SOCKET: u8 = 31;
/// Its `bind` (an existing path among the causes: the observer never unlinks).
pub const LISTENER_BIND: u8 = 32;
/// Its `listen`.
pub const LISTENER_LISTEN: u8 = 33;
/// Its registration with the poller.
pub const LISTENER_REGISTER: u8 = 34;
/// The listener failing persistently at run time: twelve faults in a row, about 60 s without an accept.
pub const LISTENER_FAILED: u8 = 35;

/// The I01 listener's statuses, in table order (HE-004-I01a).
pub const LISTENER: [u8; 5] = [LISTENER_SOCKET, LISTENER_BIND, LISTENER_LISTEN, LISTENER_REGISTER, LISTENER_FAILED];

/// The status of `LinuxWire::new`'s refusal: 24 for the poller, 31-34 for the I01 listener's step (one exhaustive
/// match, so a new step fails the build).
pub fn wire_setup(error: &WireSetup) -> u8 {
    match error {
        WireSetup::Poller(_) => SOCKETS,
        WireSetup::Listener(ListenerSetup::Socket | ListenerSetup::Address | ListenerSetup::Options) => LISTENER_SOCKET,
        WireSetup::Listener(ListenerSetup::Bind) => LISTENER_BIND,
        WireSetup::Listener(ListenerSetup::Listen) => LISTENER_LISTEN,
        WireSetup::Listener(ListenerSetup::Register) => LISTENER_REGISTER,
    }
}

/// The status of a capture setup refusal: one exhaustive match (an unusable wall clock stays 97, as for the
/// configuration's lifetime).
pub fn capture_setup(error: &SetupError) -> u8 {
    match error {
        SetupError::Schema(_) => CAPTURE_SCHEMA,
        SetupError::RecordRead(_) => RECORD_READ,
        SetupError::RecordForm(_) => RECORD_FORM,
        SetupError::RecordTargets(_) => RECORD_TARGETS,
        SetupError::RecordWindow(_) => RECORD_WINDOW,
        SetupError::Roots(_) => CAPTURE_ROOTS,
        SetupError::Clock => lifetime(&LifetimeError::Clock),
    }
}

/// The status of `signed_config::load`'s refusal: 11 for the read, 12 for the key or the signature.
pub fn config_load(error: &LoadError) -> u8 {
    match error {
        LoadError::Read => CONFIG_READ,
        LoadError::Signature(_) => CONFIG_SIGNATURE,
    }
}

/// The status of the lifetime check's refusal: 14 outside the validity, 97 for an unusable wall clock.
pub fn lifetime(error: &LifetimeError) -> u8 {
    match error {
        LifetimeError::Outside => CONFIG_LIFETIME,
        LifetimeError::Clock => CLOCK,
    }
}

/// The status of the epoch's exit: one exhaustive match, so a new exit fails the build.
pub fn observation(exit: &ObserverExit) -> u8 {
    match exit {
        ObserverExit::Readyz => READYZ,
        ObserverExit::ApiserverRestart => APISERVER_RESTART,
        ObserverExit::ReadRefused => READ_REFUSED,
        ObserverExit::Unreachable => UNREACHABLE,
        ObserverExit::Answer => ANSWER,
        ObserverExit::Consistency => CONSISTENCY,
        ObserverExit::Inputs => INPUTS,
        ObserverExit::Rbac => RBAC,
        ObserverExit::Operational => OPERATIONAL,
        ObserverExit::Quota => QUOTA,
        ObserverExit::Adm4Mismatch => ADM4_MISMATCH,
        ObserverExit::Adm4Unavailable => ADM4_UNAVAILABLE,
        ObserverExit::WatchGap => WATCH_GAP,
        ObserverExit::Deadline => DEADLINE,
        ObserverExit::ConfigExpired => CONFIG_EXPIRED,
        ObserverExit::Poll => POLL,
        ObserverExit::Adm4Input => ADM4_INPUT,
        ObserverExit::Clock => CLOCK,
        ObserverExit::Stale => STALE,
        ObserverExit::Expansion => EXPANSION,
        ObserverExit::Listener => LISTENER_FAILED,
    }
}
