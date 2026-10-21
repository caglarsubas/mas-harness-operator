//! HE-004-I01a DESIGN-I01A sections 4 and 14 (MODEL_DEFINED's HE-004-I01a section): the I01 listener's statuses
//! (`status::LISTENER`, 31-35) are distinct and apart from `SERVING`, `CAPTURE_SETUP`, `STAGES` and every seal status;
//! `wire_setup` maps the poller's refusal to 24 and the listener's setup steps to 31-34, one exhaustive match; the
//! epoch's `Listener` exit is 35; 36-39 stay free.

use std::collections::BTreeSet;

use planeon_observer::client::{ListenerSetup, WireSetup};
use planeon_observer::observe::ObserverExit;
use planeon_observer::status::{self, seal_step, wire_setup, CAPTURE_SETUP, LISTENER, SERVING, STAGES};
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
fn the_listener_statuses_are_distinct_and_apart() {
    let listener: BTreeSet<u8> = LISTENER.iter().copied().collect();
    assert_eq!(listener.len(), LISTENER.len(), "distinct");
    assert_eq!(LISTENER, [31, 32, 33, 34, 35]);
    let seal = seal_statuses();
    assert!(LISTENER.iter().all(|code| {
        !SERVING.contains(code) && !CAPTURE_SETUP.contains(code) && !STAGES.contains(code) && !seal.contains(code)
    }));
    assert_eq!((SERVING.len(), CAPTURE_SETUP.len(), STAGES), (28, 6, [2, 10]), "the earlier tables unchanged");
    assert!((36..=39).all(|code| !SERVING.contains(&code) && !CAPTURE_SETUP.contains(&code) && !LISTENER.contains(&code)),
            "36-39 stay free");
}

#[test]
fn the_wire_setup_mapping_is_exhaustive() {
    for errno in [24, 12, -1] {
        assert_eq!(wire_setup(&WireSetup::Poller(errno)), status::SOCKETS);
    }
    let steps = [(ListenerSetup::Socket, 31), (ListenerSetup::Address, 31), (ListenerSetup::Options, 31),
                 (ListenerSetup::Bind, 32), (ListenerSetup::Listen, 33), (ListenerSetup::Register, 34)];
    for (step, code) in steps {
        assert_eq!(wire_setup(&WireSetup::Listener(step)), code, "{step:?}");
    }
    assert_eq!(status::observation(&ObserverExit::Listener), 35);
    assert_eq!((status::LISTENER_SOCKET, status::LISTENER_BIND, status::LISTENER_LISTEN, status::LISTENER_REGISTER,
                status::LISTENER_FAILED), (31, 32, 33, 34, 35));
    assert_eq!(status::SOCKETS, 24, "the poller keeps its status");
}
