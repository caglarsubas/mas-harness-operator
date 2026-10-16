//! The observer binary's exit statuses (HE-004A DESIGN section 5, D1-10): one distinct, non-zero status below 200 (systemd
//! reserves 200-243) per failure point of the seal (stage 1 in 40-59, stage 2 in 60-79), the "not yet serving" exit after
//! a successful seal (owner decision Q-HE4A-2 (a): nothing serves in HE-004A, so the process ends there) and the
//! non-Linux build's stub. Portable and host-tested; MODEL_DEFINED.md lists the table (R86).

use crate::seal::{SealError, SealStep, Stage};

/// The non-Linux build of the binary (command 8's darwin build) has no observer to run.
pub const NOT_LINUX: u8 = 2;
/// Both stages of the seal succeeded and the OBSERVER program is installed; HE-004A serves nothing yet, so `main` ends
/// here (HE-008 must not deploy the unit with `Restart=` before HE-004B and HE-004C).
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
