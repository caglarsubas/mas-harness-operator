//! The broker binary's exit statuses (HE-005A; owner decisions Q-HE5A-2 (a) and Q-HE5A-3 (a), MON-HE005A-PLAN2,
//! MON-HE005A-LAUNCH): one distinct, non-zero status below 200 (systemd reserves 200-243) per failure point. Portable and
//! host-tested; MODEL_DEFINED.md lists the table (the HE-005A section).
//!
//! - The seal's steps: the observer's own table, stage 1 in 40-59 and stage 2 in 60-79. `seal_step` is the observer's
//!   text, and `tools/gate.py` compares the two by text (Q-HE5A-2 (a)), so they cannot drift.
//! - NOT_LINUX (2) and NOT_YET_SERVING (10), as the observer's: the non-Linux build's stub, and a status `main` never
//!   reaches (it serves after the seal), kept so the two tables stay alike.
//! - The broker's pre-check of the start state, before role-seal's stage 1 (MON-HE005A-LAUNCH): 36 for the status read,
//!   37 for the filesystem uid, 38 for the filesystem gid and 39 for the supplementary groups, outside 40-79.
//! - The I02 listener's one status, 24 (Q-HE5A-3 (a)): `serve_unanswered` returns only on a listener error.
//!
//! There is no normal end and no status 0. No status here is held in a byte array (the R1-2 rule over the broker's
//! sources outside seal.rs).

use crate::seal::{SealError, SealStep, Stage, StartCheck};
use crate::ListenerError;

/// The non-Linux build of the binary has no broker to run.
pub const NOT_LINUX: u8 = 2;
/// Both stages of the seal succeeded and the BROKER program is installed, with nothing served; kept from the observer's
/// table, which `main` does not reach (it runs `serve` instead).
pub const NOT_YET_SERVING: u8 = 10;

/// The status of a seal error: the pre-check's own, or its step's.
pub fn seal(error: &SealError) -> u8 {
    match error {
        SealError::Start(check) => start(*check),
        SealError::Seal(error) => seal_step(error.step()),
    }
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

/// The pre-check's read of the process's own status failed.
pub const START_STATUS: u8 = 36;
/// The filesystem uid is not 0, or the `Uid:` line is not one line of four decimal fields.
pub const START_FS_UID: u8 = 37;
/// The filesystem gid is not 0, or the `Gid:` line is not one line of four decimal fields.
pub const START_FS_GID: u8 = 38;
/// A supplementary group is listed, or the `Groups:` line is missing or repeated.
pub const START_GROUPS: u8 = 39;

/// The status of a pre-check refusal: one exhaustive match, so a new refusal fails the build.
pub fn start(check: StartCheck) -> u8 {
    match check {
        StartCheck::Status => START_STATUS,
        StartCheck::FsUid => START_FS_UID,
        StartCheck::FsGid => START_FS_GID,
        StartCheck::Groups => START_GROUPS,
    }
}

/// The I02 listener failed: its setup, the poller, a wait or an accept (Q-HE5A-3 (a)).
pub const LISTENER: u8 = 24;

/// The status of the listener's error: one exhaustive match, every step the one status.
pub fn listener(error: &ListenerError) -> u8 {
    match error {
        ListenerError::Listen | ListenerError::Register | ListenerError::Wait | ListenerError::Accept => LISTENER,
    }
}
