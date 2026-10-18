//! HE-004C DESIGN-C section 14 (D1-2): the serving statuses (`status::SERVING`) are distinct, non-zero and below 200,
//! apart from `STAGES` and every seal status, and outside 40-79, 2 and 10; `status::observation` is exhaustive over the
//! epoch's exits (80-99), `config_load` maps 11 and 12 and `lifetime` 14 and 97.

use std::collections::BTreeSet;

use planeon_observer::config::LifetimeError;
use planeon_observer::observe::ObserverExit;
use planeon_observer::signed_config::{LoadError, VerifyError};
use planeon_observer::status::{self, seal_step, SERVING, STAGES};
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
fn the_serving_statuses_are_distinct_and_apart() {
    let serving: BTreeSet<u8> = SERVING.iter().copied().collect();
    assert_eq!(serving.len(), SERVING.len(), "distinct");
    assert_eq!(SERVING.len(), 28);
    assert!(SERVING.iter().all(|code| (1..200).contains(code)));
    assert!(SERVING.iter().all(|code| !(40..=79).contains(code) && *code != 2 && *code != 10));
    assert!(SERVING.iter().all(|code| !STAGES.contains(code) && !seal_statuses().contains(code)));
    assert_eq!(STAGES, [2, 10], "HE-004A's table unchanged");
    assert_eq!(serving, [11, 12, 13, 14, 20, 21, 22, 24].into_iter().chain(80..=99).collect());
}

#[test]
fn the_mappings_are_exhaustive() {
    let all = [ObserverExit::Readyz, ObserverExit::ApiserverRestart, ObserverExit::ReadRefused, ObserverExit::Unreachable,
               ObserverExit::Answer, ObserverExit::Consistency, ObserverExit::Inputs, ObserverExit::Rbac, ObserverExit::Operational,
               ObserverExit::Quota, ObserverExit::Adm4Mismatch, ObserverExit::Adm4Unavailable, ObserverExit::WatchGap,
               ObserverExit::Deadline, ObserverExit::ConfigExpired, ObserverExit::Poll, ObserverExit::Adm4Input, ObserverExit::Clock,
               ObserverExit::Stale, ObserverExit::Expansion];
    let codes: Vec<u8> = all.iter().map(status::observation).collect();
    assert_eq!(codes, (80..=99).collect::<Vec<u8>>());
    assert!(codes.iter().all(|code| SERVING.contains(code)));
    assert_eq!(status::config_load(&LoadError::Read), status::CONFIG_READ);
    for refusal in [VerifyError::KeyNotSet, VerifyError::KeyLength, VerifyError::SmallOrder, VerifyError::Signature] {
        assert_eq!(status::config_load(&LoadError::Signature(refusal)), status::CONFIG_SIGNATURE);
    }
    assert_eq!((status::lifetime(&LifetimeError::Outside), status::lifetime(&LifetimeError::Clock)), (14, 97));
    assert_eq!((status::CONFIG_READ, status::CONFIG_SIGNATURE, status::CONFIG_CHECK, status::CONFIG_LIFETIME), (11, 12, 13, 14));
    assert_eq!((status::CREDENTIALS, status::TLS_SETUP, status::CLOSURE, status::SOCKETS), (20, 21, 22, 24));
}
