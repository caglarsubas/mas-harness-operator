//! HE-005A (owner decisions Q-HE5A-2 (a) and Q-HE5A-3 (a); MON-HE005A-LAUNCH): the broker binary's exit statuses are
//! distinct, non-zero and below 200 (systemd reserves 200-243). Every seal step has the observer's status (stage 1 in
//! 40-59, stage 2 in 60-79), each pre-check refusal its own status outside them (36-39), the I02 listener its one status
//! (24), and NOT_LINUX and NOT_YET_SERVING are the observer's 2 and 10. HE-005C: the signed configuration's 11, 12 and 13.

use std::collections::BTreeMap;

use planeon_broker::seal::{SealStep, Stage};
use planeon_broker::status::{self, seal_step};
use planeon_broker::{ListenerError, SealError, StartCheck};

/// Every seal step of stage 1 and stage 2 (role-seal's 15 and 7).
fn steps() -> (Vec<SealStep>, Vec<SealStep>) {
    use SealStep::*;
    let one = vec![Threads(Stage::One), UserIds, GroupIds, StartCapabilities, StartBounding, StartAmbient, StartState,
                   Program, CoreLimit, CoreLimitReadBack, Ambient, Capabilities, CapabilitiesReadBack, NoNewPrivs,
                   NoNewPrivsReadBack];
    let two = vec![Threads(Stage::Two), FinalCapabilities, FinalBounding, FinalAmbient, FinalNoNewPrivs, FinalCoreLimit,
                   Filter];
    (one, two)
}

/// The pre-check's refusals, in its order.
const CHECKS: [StartCheck; 4] = [StartCheck::Status, StartCheck::FsUid, StartCheck::FsGid, StartCheck::Groups];

/// The listener's errors.
const LISTENER_ERRORS: [ListenerError; 4] =
    [ListenerError::Listen, ListenerError::Register, ListenerError::Wait, ListenerError::Accept];

#[test]
fn every_seal_step_has_the_observers_status_in_its_stage_range() {
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
fn each_pre_check_refusal_has_its_own_status_outside_the_seals() {
    let codes: Vec<u8> = CHECKS.iter().map(|check| status::start(*check)).collect();
    assert_eq!(codes, [36, 37, 38, 39]);
    assert_eq!((status::START_STATUS, status::START_FS_UID, status::START_FS_GID, status::START_GROUPS), (36, 37, 38, 39));
    for check in CHECKS {
        let code = status::seal(&SealError::Start(check));
        assert_eq!(code, status::start(check), "{check:?}");
        assert!(!(40..=79).contains(&code), "{check:?} -> {code} is inside the seal's ranges");
    }
}

#[test]
fn every_listener_error_is_the_one_listener_status() {
    for error in LISTENER_ERRORS {
        assert_eq!(status::listener(&error), 24, "{error:?}");
    }
    assert_eq!(status::LISTENER, 24);
}

#[test]
fn the_signed_configuration_has_the_gates_and_the_observers_three_statuses() {
    // HE-005C (DESIGN-HE005 section 3.1; delta C3, C3-6): the read 11, the key or the signature 12, the parse 13, outside
    // the seal's ranges and the pre-check's.
    let codes = [status::CONFIG_READ, status::CONFIG_SIGNATURE, status::CONFIG_CHECK];
    assert_eq!(codes, [11, 12, 13]);
    for code in codes {
        assert!(!(36..=79).contains(&code) && code != status::LISTENER, "{code}");
    }
}

#[test]
fn all_statuses_are_distinct_non_zero_and_below_200() {
    let (one, two) = steps();
    let mut all: Vec<u8> = vec![status::NOT_LINUX, status::NOT_YET_SERVING, status::LISTENER, status::CONFIG_READ,
                                status::CONFIG_SIGNATURE, status::CONFIG_CHECK];
    all.extend(CHECKS.iter().map(|check| status::start(*check)));
    all.extend(one.iter().chain(two.iter()).map(|step| seal_step(*step)));
    let mut sorted = all.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), all.len(), "a status is shared: {all:?}");
    assert!(all.iter().all(|code| (1..200).contains(code)), "{all:?}");
    assert_eq!((status::NOT_LINUX, status::NOT_YET_SERVING), (2, 10));
}
