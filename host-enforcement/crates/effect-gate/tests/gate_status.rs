//! HE-003D DESIGN sections 3.5, 4 and 8 (O7, D2-2): the gate binary's exit statuses are distinct and non-zero, every
//! seal step has its own (stage 1 in 40-59, stage 2 in 60-79, the capability number of `BoundingDrop` ignored), and
//! each loop exit its own in 30-35.

use std::collections::BTreeMap;

use effect_gate::status::{self, loop_exit, seal_step, STAGES};
use effect_gate::{Listen, LoopExit, Owner, SealStep, Stage};

/// Every seal step of stage 1 and stage 2 (DESIGN section 4, D2-2: 16 and 11 once the capability number is dropped).
fn steps() -> (Vec<SealStep>, Vec<SealStep>) {
    use SealStep::*;
    let one = vec![Threads(Stage::One), UserIds, GroupIds, StartCapabilities, StartBounding, Program, CoreLimit,
                   CoreLimitReadBack, AmbientClear, AmbientReadBack, BoundingDrop(Stage::One, 0),
                   BoundingReadBack(Stage::One), Capabilities(Stage::One), CapabilitiesReadBack(Stage::One), NoNewPrivs,
                   NoNewPrivsReadBack];
    let two = vec![Threads(Stage::Two), BoundingDrop(Stage::Two, 0), BoundingReadBack(Stage::Two), Capabilities(Stage::Two),
                   CapabilitiesReadBack(Stage::Two), FinalCapabilities, FinalBounding, FinalAmbient, FinalNoNewPrivs,
                   FinalCoreLimit, Filter];
    (one, two)
}

fn loop_exits() -> Vec<LoopExit> {
    vec![LoopExit::ModelPrecondition("x"), LoopExit::UnexpectedOutput("x"), LoopExit::Accept(Listen::I05), LoopExit::Poll,
         LoopExit::PortToken(Owner::I04), LoopExit::Port(Owner::Upstream, "x")]
}

#[test]
fn every_seal_step_has_its_own_status_in_its_stage_range() {
    let (one, two) = steps();
    assert_eq!((one.len(), two.len()), (16, 11));
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
    // The capability number of BoundingDrop does not change the status.
    for capability in 0..=40 {
        assert_eq!(seal_step(SealStep::BoundingDrop(Stage::One, capability)), seal_step(SealStep::BoundingDrop(Stage::One, 0)));
        assert_eq!(seal_step(SealStep::BoundingDrop(Stage::Two, capability)), seal_step(SealStep::BoundingDrop(Stage::Two, 0)));
    }
}

#[test]
fn every_loop_exit_has_its_own_status() {
    let codes: Vec<u8> = loop_exits().iter().map(loop_exit).collect();
    assert_eq!(codes, vec![30, 31, 32, 33, 34, 35]);
    assert_eq!(loop_exit(&LoopExit::Accept(Listen::I07)), status::LOOP_ACCEPT);
    assert_eq!(loop_exit(&LoopExit::Port(Owner::I04, "y")), status::LOOP_PORT);
}

#[test]
fn all_statuses_are_distinct_and_non_zero() {
    let (one, two) = steps();
    let mut all: Vec<u8> = STAGES.to_vec();
    all.extend(one.iter().chain(two.iter()).map(|step| seal_step(*step)));
    all.extend(loop_exits().iter().map(loop_exit));
    let mut sorted = all.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), all.len(), "a status is shared: {all:?}");
    assert!(!all.contains(&0), "the loop has no normal end, so no status is 0");
    assert_eq!(STAGES, [2, 11, 12, 13, 20, 21, 22, 23, 24, 25]);
    assert_eq!((status::NOT_LINUX, status::CONFIG_READ, status::CONFIG_SIGNATURE, status::CONFIG_CHECK), (2, 11, 12, 13));
    assert_eq!((status::CREDENTIALS, status::TLS_SETUP, status::STORES, status::GATE, status::SOCKETS, status::SUBSTRATE),
               (20, 21, 22, 23, 24, 25));
}
