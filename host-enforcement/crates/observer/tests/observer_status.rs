//! HE-004A DESIGN sections 5 and 8 (D1-10): the observer binary's exit statuses are distinct, non-zero and below 200
//! (systemd reserves 200-243); every seal step has its own (stage 1 in 40-59, stage 2 in 60-79), and the not-yet-serving
//! status differs from every seal status and from the non-Linux stub's.

use std::collections::BTreeMap;

use planeon_observer::status::{self, seal_step, STAGES};
use planeon_observer::{SealStep, Stage};

/// Every seal step of stage 1 and stage 2 (DESIGN section 4: 15 and 7).
fn steps() -> (Vec<SealStep>, Vec<SealStep>) {
    use SealStep::*;
    let one = vec![Threads(Stage::One), UserIds, GroupIds, StartCapabilities, StartBounding, StartAmbient, StartState,
                   Program, CoreLimit, CoreLimitReadBack, Ambient, Capabilities, CapabilitiesReadBack, NoNewPrivs,
                   NoNewPrivsReadBack];
    let two = vec![Threads(Stage::Two), FinalCapabilities, FinalBounding, FinalAmbient, FinalNoNewPrivs, FinalCoreLimit,
                   Filter];
    (one, two)
}

#[test]
fn every_seal_step_has_its_own_status_in_its_stage_range() {
    let (one, two) = steps();
    assert_eq!((one.len(), two.len()), (15, 7));
    let mut seen = BTreeMap::new();
    for step in &one {
        let code = seal_step(*step);
        assert!((40..=59).contains(&code), "{step:?} -> {code}");
        assert!(seen.insert(code, *step).is_none(), "{step:?} shares {code}");
    }
    for step in &two {
        let code = seal_step(*step);
        assert!((60..=79).contains(&code), "{step:?} -> {code}");
        assert!(seen.insert(code, *step).is_none(), "{step:?} shares {code}");
    }
    assert_eq!(seen.keys().copied().collect::<Vec<u8>>(),
               [40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 60, 61, 62, 63, 64, 65, 66]);
}

#[test]
fn all_statuses_are_distinct_non_zero_and_below_200() {
    let (one, two) = steps();
    let mut all: Vec<u8> = STAGES.to_vec();
    all.extend(one.iter().chain(two.iter()).map(|step| seal_step(*step)));
    let mut sorted = all.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), all.len(), "a status is shared: {all:?}");
    assert!(all.iter().all(|code| (1..200).contains(code)), "{all:?}");
    assert_eq!(STAGES, [2, 10]);
    assert_eq!((status::NOT_LINUX, status::NOT_YET_SERVING), (2, 10));
    assert!(!one.iter().chain(two.iter()).any(|step| seal_step(*step) == status::NOT_YET_SERVING));
}
