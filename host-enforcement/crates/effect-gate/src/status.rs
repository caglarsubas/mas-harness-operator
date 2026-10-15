//! The gate binary's exit statuses (HE-003D DESIGN sections 3.5 and 4, obligation O7): one distinct, non-zero status
//! per failure point: each seal step (stage 1 in 40-59, stage 2 in 60-79), each configuration stage (11-13), each
//! setup stage (20-25) and each loop exit (30-35); 2 is the non-Linux build's stub. Portable and host-tested; the
//! loop has no normal end, so no status is 0. MODEL_DEFINED.md lists the table (R71).

use crate::seal::{SealError, SealStep, Stage};
use crate::substrate::LoopExit;

/// The non-Linux build of the binary (command 8's darwin build) has no gate to run.
pub const NOT_LINUX: u8 = 2;
/// `signed_config::load`: a file could not be read as specified (missing, not a regular file, a size out of bounds,
/// a short or long read, an I/O error).
pub const CONFIG_READ: u8 = 11;
/// `signed_config::load`: the signature does not verify, or the compiled-in key is not set or refused.
pub const CONFIG_SIGNATURE: u8 = 12;
/// `GateConfig::parse`: the canonical form, the schema or a check of DESIGN section 3.3.
pub const CONFIG_CHECK: u8 = 13;
/// A credential or CA file: open, size, read or its pinned sha256 (DESIGN section 3.4).
pub const CREDENTIALS: u8 = 20;
/// The TLS configurations: `server_config` and the two `client_config`.
pub const TLS_SETUP: u8 = 21;
/// `FileStores::open_bound`, the generation binding included.
pub const STORES: u8 = 22;
/// `PolicyGate::create` or `PolicyGate::open`.
pub const GATE: u8 = 23;
/// The socket setup: the I04 listener and the Linux `Os` (poller and the two channel listeners).
pub const SOCKETS: u8 = 24;
/// `Substrate::new`.
pub const SUBSTRATE: u8 = 25;
/// The loop's exits, one per `LoopExit` variant.
pub const LOOP_MODEL_PRECONDITION: u8 = 30;
pub const LOOP_UNEXPECTED_OUTPUT: u8 = 31;
pub const LOOP_ACCEPT: u8 = 32;
pub const LOOP_POLL: u8 = 33;
pub const LOOP_PORT_TOKEN: u8 = 34;
pub const LOOP_PORT: u8 = 35;

/// The status of a seal error: its step's (DESIGN section 4 steps 1 and 3).
pub fn seal(error: &SealError) -> u8 {
    seal_step(error.step())
}

/// One total mapping over both stages, exhaustive per `SealStep` variant, so a new variant fails the build; the
/// capability number of `BoundingDrop` is ignored.
pub fn seal_step(step: SealStep) -> u8 {
    match step {
        SealStep::Threads(Stage::One) => 40,
        SealStep::UserIds => 41,
        SealStep::GroupIds => 42,
        SealStep::StartCapabilities => 43,
        SealStep::StartBounding => 44,
        SealStep::Program => 45,
        SealStep::CoreLimit => 46,
        SealStep::CoreLimitReadBack => 47,
        SealStep::AmbientClear => 48,
        SealStep::AmbientReadBack => 49,
        SealStep::BoundingDrop(Stage::One, _) => 50,
        SealStep::BoundingReadBack(Stage::One) => 51,
        SealStep::Capabilities(Stage::One) => 52,
        SealStep::CapabilitiesReadBack(Stage::One) => 53,
        SealStep::NoNewPrivs => 54,
        SealStep::NoNewPrivsReadBack => 55,
        SealStep::Threads(Stage::Two) => 60,
        SealStep::BoundingDrop(Stage::Two, _) => 61,
        SealStep::BoundingReadBack(Stage::Two) => 62,
        SealStep::Capabilities(Stage::Two) => 63,
        SealStep::CapabilitiesReadBack(Stage::Two) => 64,
        SealStep::FinalCapabilities => 65,
        SealStep::FinalBounding => 66,
        SealStep::FinalAmbient => 67,
        SealStep::FinalNoNewPrivs => 68,
        SealStep::FinalCoreLimit => 69,
        SealStep::Filter => 70,
    }
}

/// The status of a loop exit (DESIGN section 4 step 7).
pub fn loop_exit(exit: &LoopExit) -> u8 {
    match exit {
        LoopExit::ModelPrecondition(_) => LOOP_MODEL_PRECONDITION,
        LoopExit::UnexpectedOutput(_) => LOOP_UNEXPECTED_OUTPUT,
        LoopExit::Accept(_) => LOOP_ACCEPT,
        LoopExit::Poll => LOOP_POLL,
        LoopExit::PortToken(_) => LOOP_PORT_TOKEN,
        LoopExit::Port(_, _) => LOOP_PORT,
    }
}

/// The configuration and setup statuses, in table order (`main` reaches the socket setup, 24, before the stores, 22,
/// and the gate, 23).
pub const STAGES: [u8; 10] = [NOT_LINUX, CONFIG_READ, CONFIG_SIGNATURE, CONFIG_CHECK, CREDENTIALS, TLS_SETUP, STORES, GATE,
                              SOCKETS, SUBSTRATE];
