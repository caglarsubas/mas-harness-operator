//! HE-004D1 DESIGN-D1 section 17.2 (owner decision Q-HE4D1-7 (a); MODEL_DEFINED R132): the capture setup's statuses
//! (`status::CAPTURE_SETUP`, 25-30) are distinct, inside 25-39 and apart from `SERVING`, `STAGES` and every seal status;
//! `capture_setup` maps every setup refusal exhaustively (an unusable clock stays 97); 31-39 stay free.

use std::collections::BTreeSet;

use planeon_observer::enrolled::SetupError;
use planeon_observer::status::{self, capture_setup, seal_step, CAPTURE_SETUP, SERVING, STAGES};
use planeon_observer::{SealStep, Stage};

fn seal_statuses() -> Vec<u8> {
    use SealStep::*;
    [Threads(Stage::One), UserIds, GroupIds, StartCapabilities, StartBounding, StartAmbient, StartState, Program, CoreLimit,
     CoreLimitReadBack, Ambient, Capabilities, CapabilitiesReadBack, NoNewPrivs, NoNewPrivsReadBack, Threads(Stage::Two),
     FinalCapabilities, FinalBounding, FinalAmbient, FinalNoNewPrivs, FinalCoreLimit, Filter]
        .into_iter()
        .map(seal_step)
        .collect()
}

#[test]
fn the_capture_setup_statuses_are_distinct_and_apart() {
    let setup: BTreeSet<u8> = CAPTURE_SETUP.iter().copied().collect();
    assert_eq!(setup.len(), CAPTURE_SETUP.len(), "distinct");
    assert_eq!(CAPTURE_SETUP, [25, 26, 27, 28, 29, 30]);
    assert!(CAPTURE_SETUP.iter().all(|code| (25..=39).contains(code)));
    assert!(CAPTURE_SETUP.iter().all(|code| !SERVING.contains(code) && !STAGES.contains(code) && !seal_statuses().contains(code)));
    assert_eq!(SERVING.len(), 28, "HE-004C's table unchanged");
    assert!((31..=39).all(|code| !SERVING.contains(&code) && !CAPTURE_SETUP.contains(&code)), "31-39 stay free");
    assert!(!CAPTURE_SETUP.contains(&101));
}

#[test]
fn the_mapping_is_exhaustive() {
    let all = [SetupError::Schema("a"), SetupError::RecordRead("a"), SetupError::RecordForm("a"), SetupError::RecordTargets("a"),
               SetupError::RecordWindow("a"), SetupError::Roots("a")];
    let codes: Vec<u8> = all.iter().map(capture_setup).collect();
    assert_eq!(codes, CAPTURE_SETUP.to_vec());
    assert_eq!(capture_setup(&SetupError::Clock), status::CLOCK);
    assert_eq!((status::CAPTURE_SCHEMA, status::RECORD_READ, status::RECORD_FORM, status::RECORD_TARGETS, status::RECORD_WINDOW,
                status::CAPTURE_ROOTS), (25, 26, 27, 28, 29, 30));
    // A v2 parse refusal, the record's path outside the configuration's directory included, stays 13.
    assert_eq!(status::CONFIG_CHECK, 13);
}
